package server

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/acquisition"
	vaultcrypto "github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/Infisical/agent-vault/internal/store"
)

const acquisitionContinuationTTL = 5 * time.Minute

type providerRunner func(context.Context, acquisition.HandlerResolver, string, acquisition.ProviderInvocation) (*acquisition.ProviderResult, error)

type proposalAcquisitionStartRequest struct {
	Vault   string `json:"vault"`
	Handler string `json:"handler"`
	Profile string `json:"profile"`
}

type proposalAcquisitionCancelRequest struct {
	Vault string `json:"vault"`
}

type proposalAcquisitionResponse struct {
	ID                    string     `json:"id"`
	ProposalID            int        `json:"proposal_id"`
	CredentialKey         string     `json:"key"`
	Attempt               int        `json:"attempt"`
	HandlerID             string     `json:"handler_id"`
	Profile               string     `json:"profile"`
	Mode                  string     `json:"mode"`
	State                 string     `json:"state"`
	Source                string     `json:"source,omitempty"`
	ErrorCode             string     `json:"error_code,omitempty"`
	CredentialExpiresAt   *time.Time `json:"credential_expires_at,omitempty"`
	ContinuationExpiresAt *time.Time `json:"continuation_expires_at,omitempty"`
	StartedAt             *time.Time `json:"started_at,omitempty"`
	CompletedAt           *time.Time `json:"completed_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

func newProposalAcquisitionResponse(job *store.ProposalAcquisition) proposalAcquisitionResponse {
	return proposalAcquisitionResponse{
		ID: job.ID, ProposalID: job.ProposalID, CredentialKey: job.CredentialKey,
		Attempt: job.Attempt, HandlerID: job.HandlerID, Profile: job.Profile, Mode: job.Mode,
		State: job.State, Source: job.Source, ErrorCode: job.ErrorCode,
		CredentialExpiresAt: job.CredentialExpiresAt, ContinuationExpiresAt: job.ContinuationExpiresAt,
		StartedAt: job.StartedAt, CompletedAt: job.CompletedAt, CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
	}
}

func parseProposalAcquisitionID(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		jsonError(w, http.StatusBadRequest, "Invalid proposal ID")
		return 0, false
	}
	return id, true
}

func (s *Server) resolveProposalAcquisitionVault(w http.ResponseWriter, r *http.Request, name string) (*store.Vault, *Actor, bool) {
	if name == "" {
		name = store.DefaultVault
	}
	vault, err := s.store.GetVault(r.Context(), name)
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return nil, nil, false
	}
	actor, err := s.requireProposalReview(w, r, vault.ID)
	if err != nil {
		return nil, nil, false
	}
	return vault, actor, true
}

func proposalAcquisitionRef(credentialsJSON, key string) (*proposal.AcquisitionRef, error) {
	var slots []proposal.CredentialSlot
	if err := json.Unmarshal([]byte(credentialsJSON), &slots); err != nil {
		return nil, err
	}
	var found *proposal.AcquisitionRef
	for i := range slots {
		if slots[i].Action != proposal.ActionSet || slots[i].Key != key || slots[i].Acquisition == nil {
			continue
		}
		if found != nil {
			return nil, errors.New("duplicate acquisition declaration")
		}
		copy := *slots[i].Acquisition
		found = &copy
	}
	if found == nil {
		return nil, sql.ErrNoRows
	}
	return found, nil
}

func (s *Server) handleProposalAcquisitionStart(w http.ResponseWriter, r *http.Request) {
	proposalID, ok := parseProposalAcquisitionID(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	var req proposalAcquisitionStartRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	vault, actor, ok := s.resolveProposalAcquisitionVault(w, r, req.Vault)
	if !ok {
		return
	}
	enabled, err := s.credentialAcquisitionEnabled(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read acquisition settings")
		return
	}
	if !enabled {
		jsonCodedError(w, http.StatusConflict, "credential_acquisition_disabled", "Credential acquisition is disabled")
		return
	}
	if !s.assertBuiltinCredentialStore(w, r.Context(), vault.ID, vault.Name) {
		return
	}
	proposalRow, err := s.store.GetProposal(r.Context(), vault.ID, proposalID)
	if errors.Is(err, sql.ErrNoRows) || proposalRow == nil {
		jsonError(w, http.StatusNotFound, "Proposal not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read proposal")
		return
	}
	if proposalRow.Status != "pending" {
		jsonCodedError(w, http.StatusConflict, "proposal_not_pending", "Proposal is not pending")
		return
	}
	ref, err := proposalAcquisitionRef(proposalRow.CredentialsJSON, key)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusBadRequest, "Credential has no acquisition declaration")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse proposal credentials")
		return
	}
	if req.Handler != ref.Handler || req.Profile != ref.Profile {
		jsonCodedError(w, http.StatusBadRequest, "acquisition_mismatch", "Requested acquisition does not match the proposal")
		return
	}
	job, err := s.store.StartProposalAcquisition(r.Context(), store.ProposalAcquisitionStart{
		VaultID: vault.ID, ProposalID: proposalID, CredentialKey: key,
		HandlerID: ref.Handler, Profile: ref.Profile, Mode: string(ref.Mode),
	})
	if err != nil {
		writeProposalAcquisitionStartError(w, err)
		return
	}
	if !s.scheduleProposalAcquisition(job) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.store.CancelProposalAcquisitionByID(ctx, job.ID)
		jsonCodedError(w, http.StatusServiceUnavailable, "server_stopping", "Server is stopping")
		return
	}
	s.captureEvent(r, "av.proposal_acquisition_started", actor, map[string]string{
		"acquisition_id": job.ID, "proposal_id": strconv.Itoa(proposalID), "credential_key": key, "state": job.State,
		"context_binding_id": job.ContextBindingID,
	})
	jsonStatus(w, http.StatusAccepted, newProposalAcquisitionResponse(job))
}

func writeProposalAcquisitionStartError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrCredentialAcquisitionDisabled):
		jsonCodedError(w, http.StatusConflict, "credential_acquisition_disabled", "Credential acquisition is disabled")
	case errors.Is(err, store.ErrAcquisitionHandlerUnavailable), errors.Is(err, store.ErrAcquisitionPolicyHandlerUnavailable):
		jsonCodedError(w, http.StatusConflict, "handler_unavailable", "Acquisition handler is unavailable")
	case errors.Is(err, store.ErrBrowserDOMAcquisitionUnavailable):
		jsonCodedError(w, http.StatusConflict, "browser_dom_unavailable", "Browser DOM acquisition is not available in this build")
	case errors.Is(err, store.ErrProposalAcquisitionActive):
		jsonCodedError(w, http.StatusConflict, "proposal_acquisition_active", "Credential already has an active acquisition")
	case errors.Is(err, store.ErrProposalStateConflict), errors.Is(err, store.ErrContextBindingInactive),
		errors.Is(err, store.ErrProposalAcquisitionContextBindingRequired):
		jsonCodedError(w, http.StatusConflict, "proposal_context_conflict", "Proposal context is no longer active")
	case errors.Is(err, store.ErrProposalAcquisitionDeclarationMismatch):
		jsonCodedError(w, http.StatusBadRequest, "acquisition_mismatch", "Requested acquisition does not match the proposal")
	default:
		jsonError(w, http.StatusInternalServerError, "Failed to start credential acquisition")
	}
}

func (s *Server) handleProposalAcquisitionStatus(w http.ResponseWriter, r *http.Request) {
	proposalID, ok := parseProposalAcquisitionID(w, r)
	if !ok {
		return
	}
	vault, _, ok := s.resolveProposalAcquisitionVault(w, r, r.URL.Query().Get("vault"))
	if !ok {
		return
	}
	if _, err := s.store.GetProposal(r.Context(), vault.ID, proposalID); errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Proposal not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read proposal")
		return
	}
	if key := r.URL.Query().Get("key"); key != "" {
		job, err := s.store.GetProposalAcquisition(r.Context(), vault.ID, proposalID, key)
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, "Acquisition not found")
			return
		}
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to read acquisition")
			return
		}
		jsonOK(w, newProposalAcquisitionResponse(job))
		return
	}
	jobs, err := s.store.ListProposalAcquisitions(r.Context(), vault.ID, proposalID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list acquisitions")
		return
	}
	result := make([]proposalAcquisitionResponse, 0, len(jobs))
	for i := range jobs {
		result = append(result, newProposalAcquisitionResponse(&jobs[i]))
	}
	jsonOK(w, map[string]any{"acquisitions": result})
}

func (s *Server) handleProposalAcquisitionCancel(w http.ResponseWriter, r *http.Request) {
	proposalID, ok := parseProposalAcquisitionID(w, r)
	if !ok {
		return
	}
	var req proposalAcquisitionCancelRequest
	if err := decodeStrictJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	vault, actor, ok := s.resolveProposalAcquisitionVault(w, r, req.Vault)
	if !ok {
		return
	}
	if _, err := s.store.GetProposal(r.Context(), vault.ID, proposalID); errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Proposal not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read proposal")
		return
	}
	job, err := s.store.GetProposalAcquisition(r.Context(), vault.ID, proposalID, r.PathValue("key"))
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "Acquisition not found")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to read acquisition")
		return
	}
	cancelled, err := s.store.CancelProposalAcquisitionByID(r.Context(), job.ID)
	if errors.Is(err, store.ErrProposalAcquisitionStateConflict) {
		jsonCodedError(w, http.StatusConflict, "proposal_acquisition_state_conflict", "Acquisition is not active")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to cancel acquisition")
		return
	}
	s.cancelProposalAcquisitionJob(job.ID)
	s.captureEvent(r, "av.proposal_acquisition_cancelled", actor, map[string]string{
		"acquisition_id": job.ID, "proposal_id": strconv.Itoa(proposalID), "credential_key": job.CredentialKey, "state": cancelled.State,
		"context_binding_id": job.ContextBindingID,
	})
	jsonOK(w, newProposalAcquisitionResponse(cancelled))
}

func (s *Server) scheduleProposalAcquisition(job *store.ProposalAcquisition) bool {
	s.acquisitionJobsMu.Lock()
	if s.acquisitionStopping || s.acquisitionRootCtx == nil || s.acquisitionRootCtx.Err() != nil {
		s.acquisitionJobsMu.Unlock()
		return false
	}
	ctx, cancel := context.WithCancel(s.acquisitionRootCtx)
	s.acquisitionCancels[job.ID] = cancel
	s.acquisitionWG.Add(1)
	s.acquisitionJobsMu.Unlock()
	go s.executeProposalAcquisition(ctx, cancel, job)
	return true
}

func (s *Server) cancelProposalAcquisitionJob(id string) {
	s.acquisitionJobsMu.Lock()
	cancel := s.acquisitionCancels[id]
	s.acquisitionJobsMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) executeProposalAcquisition(ctx context.Context, cancel context.CancelFunc, queued *store.ProposalAcquisition) {
	defer s.acquisitionWG.Done()
	defer cancel()
	defer func() {
		s.acquisitionJobsMu.Lock()
		delete(s.acquisitionCancels, queued.ID)
		s.acquisitionJobsMu.Unlock()
	}()

	job, err := s.store.MarkProposalAcquisitionRunning(ctx, queued.ID)
	if err != nil {
		if ctx.Err() != nil {
			s.cancelProposalAcquisitionByID(queued.ID)
		} else {
			s.failProposalAcquisition(queued.ID, "admission_failed")
		}
		return
	}
	progress := make(chan acquisition.Progress, acquisition.MaxProgressMessages)
	invocation := acquisition.ProviderInvocation{
		VaultID: job.VaultID, ResourceID: job.CredentialKey, Profile: job.Profile,
		ContextBindingID: job.ContextBindingID, HandlerGeneration: job.HandlerGeneration,
		Params: map[string]string{"mode": job.Mode}, ProgressSink: progress,
	}
	type providerOutcome struct {
		result *acquisition.ProviderResult
		err    error
	}
	done := make(chan providerOutcome, 1)
	go func() {
		result, runErr := s.runAcquisitionProvider(ctx, s.store, job.HandlerID, invocation)
		done <- providerOutcome{result: result, err: runErr}
	}()

	var outcome providerOutcome
	var ticketHash []byte
	var progressCode string
	cancelled := false
	ctxDone := ctx.Done()
	providerDone := false
	for !providerDone {
		select {
		case item := <-progress:
			if progressCode == "" {
				ticketHash, progressCode = s.applyProposalAcquisitionProgress(ctx, job, ticketHash, item)
				if progressCode != "" {
					cancel()
					ctxDone = nil
				}
			}
		case outcome = <-done:
			providerDone = true
		case <-ctxDone:
			cancelled = true
			cancel()
			ctxDone = nil
		}
	}
	for {
		select {
		case item := <-progress:
			if progressCode == "" {
				ticketHash, progressCode = s.applyProposalAcquisitionProgress(context.Background(), job, ticketHash, item)
			}
		default:
			goto progressDrained
		}
	}

progressDrained:
	if outcome.result != nil && outcome.result.Secret != nil {
		defer outcome.result.Secret.Destroy()
	}
	if cancelled || ctx.Err() != nil && progressCode == "" && errors.Is(outcome.err, context.Canceled) {
		s.cancelProposalAcquisitionByID(job.ID)
		return
	}
	if progressCode != "" {
		s.failProposalAcquisition(job.ID, progressCode)
		return
	}
	if outcome.err != nil {
		code := acquisition.ProviderErrorCode(outcome.err)
		if code == "" {
			code = "provider_error"
		}
		s.failProposalAcquisition(job.ID, code)
		return
	}
	if outcome.result == nil || outcome.result.Secret == nil {
		s.failProposalAcquisition(job.ID, "protocol_violation")
		return
	}
	ciphertext, nonce, err := outcome.result.Secret.EncryptWithKey(s.encKey)
	if err != nil {
		s.failProposalAcquisition(job.ID, "encryption_failed")
		return
	}
	credential := store.EncryptedCredential{Ciphertext: ciphertext, Nonce: nonce}
	var expiresAt *time.Time
	if outcome.result.Meta.TTLSeconds > 0 {
		issuedAt := time.Now().UTC()
		if outcome.result.Meta.IssuedAtUnix > 0 {
			issuedAt = time.Unix(outcome.result.Meta.IssuedAtUnix, 0).UTC()
		}
		expires := issuedAt.Add(time.Duration(outcome.result.Meta.TTLSeconds) * time.Second)
		expiresAt = &expires
	}
	opCtx, opCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer opCancel()
	if len(ticketHash) == sha256.Size {
		_, err = s.store.CompleteProposalAcquisitionContinuation(opCtx, ticketHash, credential, outcome.result.Meta.Source, expiresAt)
	} else {
		_, err = s.store.CompleteProposalAcquisition(opCtx, job.ID, credential, outcome.result.Meta.Source, expiresAt)
	}
	if err != nil && !errors.Is(err, store.ErrProposalAcquisitionStateConflict) &&
		!errors.Is(err, store.ErrProposalAcquisitionContinuationUnavailable) {
		s.failProposalAcquisition(job.ID, "completion_failed")
	}
}

func (s *Server) applyProposalAcquisitionProgress(ctx context.Context, job *store.ProposalAcquisition, ticketHash []byte, item acquisition.Progress) ([]byte, string) {
	if item.ContextBindingID != job.ContextBindingID {
		return ticketHash, "progress_invalid"
	}
	switch item.Status {
	case acquisition.ProgressWorking:
		return ticketHash, ""
	case acquisition.ProgressAwaitingUser:
		if len(ticketHash) != 0 {
			return ticketHash, "progress_invalid"
		}
		rawTicket := make([]byte, acquisition.TicketBytes)
		if _, err := cryptorand.Read(rawTicket); err != nil {
			vaultcrypto.WipeBytes(rawTicket)
			return nil, "random_unavailable"
		}
		hash := sha256.Sum256(rawTicket)
		vaultcrypto.WipeBytes(rawTicket)
		expiresAt := time.Now().UTC().Add(acquisitionContinuationTTL)
		if _, err := s.store.MarkProposalAcquisitionAwaitingUser(ctx, job.ID, hash[:], expiresAt); err != nil {
			return nil, "progress_persist_failed"
		}
		return append([]byte(nil), hash[:]...), ""
	default:
		return ticketHash, "progress_invalid"
	}
}

func (s *Server) failProposalAcquisition(id, code string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.store.FailProposalAcquisition(ctx, id, code)
}

func (s *Server) cancelProposalAcquisitionByID(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.store.CancelProposalAcquisitionByID(ctx, id)
}

func (s *Server) stopAcquisitionJobs(timeout time.Duration) bool {
	s.acquisitionJobsMu.Lock()
	if !s.acquisitionStopping {
		s.acquisitionStopping = true
		if s.acquisitionRootCancel != nil {
			s.acquisitionRootCancel()
		}
	}
	for _, cancel := range s.acquisitionCancels {
		cancel()
	}
	s.acquisitionJobsMu.Unlock()

	done := make(chan struct{})
	go func() {
		s.acquisitionWG.Wait()
		close(done)
	}()
	if timeout <= 0 {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
