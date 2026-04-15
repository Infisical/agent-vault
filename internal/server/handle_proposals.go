package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/Infisical/agent-vault/internal/store"
)

// handleProposalApproveDetails returns proposal approval page data as JSON.
// The approval token grants read access; user session determines approval capability.
func (s *Server) handleProposalApproveDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.URL.Query().Get("token")
	idStr := r.URL.Query().Get("id")

	if token == "" {
		jsonError(w, http.StatusBadRequest, "Missing token")
		return
	}

	cs, err := s.store.GetProposalByApprovalToken(ctx, token)
	if err != nil || cs == nil {
		jsonError(w, http.StatusNotFound, "Invalid or expired approval link")
		return
	}

	if id, err := strconv.Atoi(idStr); err != nil || id != cs.ID {
		jsonError(w, http.StatusBadRequest, "Proposal ID mismatch")
		return
	}

	if cs.ApprovalTokenExpiresAt != nil && time.Now().After(*cs.ApprovalTokenExpiresAt) {
		jsonError(w, http.StatusGone, "Approval link has expired")
		return
	}

	if cs.Status != "pending" {
		jsonOK(w, map[string]interface{}{
			"error":         true,
			"error_title":   strings.ToUpper(cs.Status[:1]) + cs.Status[1:],
			"error_message": "This request has already been " + cs.Status + ".",
		})
		return
	}

	ns, err := s.store.GetVaultByID(ctx, cs.VaultID)
	if err != nil || ns == nil {
		jsonError(w, http.StatusInternalServerError, "Could not load vault details")
		return
	}

	// Resolve agent name via session -> agent chain.
	agentName := ""
	if sess, err := s.store.GetSession(ctx, cs.SessionID); err == nil && sess != nil && sess.AgentID != "" {
		if agent, err := s.store.GetAgentByID(ctx, sess.AgentID); err == nil && agent != nil {
			agentName = agent.Name
		}
	}

	authenticated := false
	canApprove := false
	userEmail := ""
	if c, err := r.Cookie("av_session"); err == nil && c.Value != "" {
		sess, err := s.store.GetSession(ctx, c.Value)
		if err == nil && sess != nil && !sessionExpired(sess) && sess.UserID != "" {
			actor, err := s.actorFromSession(ctx, sess)
			if err == nil && actor != nil && actor.User != nil {
				authenticated = true
				userEmail = actor.User.Email
				has, err := s.store.HasVaultAccess(ctx, actor.ID, cs.VaultID)
				if err == nil && has {
					canApprove = true
				}
			}
		}
	}

	jsonOK(w, map[string]interface{}{
		"proposal_id":   cs.ID,
		"vault":         ns.Name,
		"status":        cs.Status,
		"user_message":  cs.UserMessage,
		"message":       cs.Message,
		"services":      json.RawMessage(cs.ServicesJSON),
		"credentials":   json.RawMessage(cs.CredentialsJSON),
		"created_at":    cs.CreatedAt.Format(time.RFC3339),
		"agent_name":    agentName,
		"authenticated": authenticated,
		"can_approve":   canApprove,
		"user_email":    userEmail,
	})
}

const maxPendingProposals = 20

type proposalCreateRequest struct {
	Services    []proposal.Service        `json:"services"`
	Credentials []proposal.CredentialSlot `json:"credentials"`
	Message     string                    `json:"message"`
	UserMessage string                    `json:"user_message"`
}

func (s *Server) handleProposalCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Enforce scoped session or agent token with X-Vault.
	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Proposals require a vault-scoped session")
		return
	}

	resolvedVault, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return
	}
	vaultID := resolvedVault.ID

	var req proposalCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate the proposal.
	if err := proposal.Validate(req.Services, req.Credentials); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate that all credential references resolve to existing or proposed credentials.
	existingKeys := s.listCredentialKeys(ctx, vaultID)
	if err := proposal.ValidateCredentialRefs(req.Services, req.Credentials, existingKeys); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check pending limit.
	count, err := s.store.CountPendingProposals(ctx, vaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to count pending proposals")
		return
	}
	if count >= maxPendingProposals {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many pending proposals (max %d)", maxPendingProposals))
		return
	}

	// Encrypt agent-provided credential values (skip delete-action slots).
	encCredentials := make(map[string]store.EncryptedCredential)
	for i := range req.Credentials {
		if req.Credentials[i].Action == proposal.ActionDelete {
			continue
		}
		if req.Credentials[i].Value != nil && *req.Credentials[i].Value != "" {
			ct, nonce, err := crypto.Encrypt([]byte(*req.Credentials[i].Value), s.encKey)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "Encryption failed")
				return
			}
			encCredentials[req.Credentials[i].Key] = store.EncryptedCredential{Ciphertext: ct, Nonce: nonce}
			// Replace value with nil in the metadata and mark has_value.
			req.Credentials[i].Value = nil
			req.Credentials[i].HasValue = true
		}
	}

	servicesJSON, _ := json.Marshal(req.Services)
	credentialsJSON, _ := json.Marshal(req.Credentials)

	cs, err := s.store.CreateProposal(ctx, vaultID, sess.ID, string(servicesJSON), string(credentialsJSON), req.Message, req.UserMessage, encCredentials)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create proposal")
		return
	}

	nsName := resolvedVault.Name

	approvalURL := fmt.Sprintf("%s/approve/%d?token=%s", s.baseURL, cs.ID, cs.ApprovalToken)

	// Resolve agent name for the notification email.
	proposalAgentName := ""
	if sess.AgentID != "" {
		if agent, err := s.store.GetAgentByID(ctx, sess.AgentID); err == nil && agent != nil {
			proposalAgentName = agent.Name
		}
	}

	// Notify vault members about the new proposal (fire-and-forget).
	// The goroutine intentionally outlives the request, so we use a detached context.
	if s.notifier.Enabled() {
		go s.notifyProposalCreated(vaultID, nsName, cs.ID, req.Message, approvalURL, proposalAgentName) //nolint:gosec // G118: intentional fire-and-forget goroutine
	}

	jsonCreated(w, map[string]interface{}{
		"id":           cs.ID,
		"status":       cs.Status,
		"vault":        nsName,
		"approval_url": approvalURL,
		"message":      fmt.Sprintf("Proposal created. Approve here: %s", approvalURL),
	})
}

// notifyProposalCreated sends an email notification to all vault members
// when a new proposal is created. Intended to be called in a goroutine.
func (s *Server) notifyProposalCreated(vaultID, vaultName string, proposalID int, message, approvalURL, agentName string) {
	ctx := context.Background()

	grants, err := s.store.ListVaultMembersByType(ctx, vaultID, "user")
	if err != nil || len(grants) == 0 {
		return
	}

	var emails []string
	for _, g := range grants {
		if u, err := s.store.GetUserByID(ctx, g.ActorID); err == nil && u != nil {
			emails = append(emails, u.Email)
		}
	}
	if len(emails) == 0 {
		return
	}

	// Truncate message for the email body.
	msg := message
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}

	subject := fmt.Sprintf("New proposal (#%d) in vault %q", proposalID, vaultName)
	body := proposalNotificationEmailHTML
	body = strings.ReplaceAll(body, "{{VAULT_NAME}}", html.EscapeString(vaultName))
	body = strings.ReplaceAll(body, "{{PROPOSAL_ID}}", strconv.Itoa(proposalID))
	body = strings.ReplaceAll(body, "{{MESSAGE}}", html.EscapeString(msg))
	body = strings.ReplaceAll(body, "{{AGENT_NAME}}", html.EscapeString(agentName))
	body = strings.ReplaceAll(body, "{{APPROVAL_URL}}", html.EscapeString(approvalURL))

	if err := s.notifier.SendHTMLMail(emails, subject, body); err != nil {
		fmt.Fprintf(os.Stderr, "[agent-vault] Failed to send proposal notification: %v\n", err)
	}
}

func (s *Server) handleProposalGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Proposals require a vault-scoped session")
		return
	}

	resolvedVault, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	cs, err := s.store.GetProposal(ctx, resolvedVault.ID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal %d not found", id))
		return
	}

	jsonOK(w, map[string]interface{}{
		"id":          cs.ID,
		"status":      cs.Status,
		"services":    json.RawMessage(cs.ServicesJSON),
		"credentials": json.RawMessage(cs.CredentialsJSON),
		"message":     cs.Message,
		"review_note": cs.ReviewNote,
		"reviewed_at": cs.ReviewedAt,
		"created_at":  cs.CreatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleProposalList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sess := sessionFromContext(ctx)
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Proposals require a vault-scoped session")
		return
	}

	resolvedVault, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return
	}

	status := r.URL.Query().Get("status")
	list, err := s.store.ListProposals(ctx, resolvedVault.ID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list proposals")
		return
	}

	type item struct {
		ID        int    `json:"id"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		CreatedAt string `json:"created_at"`
	}
	items := make([]item, len(list))
	for i, cs := range list {
		items[i] = item{
			ID:        cs.ID,
			Status:    cs.Status,
			Message:   cs.Message,
			CreatedAt: cs.CreatedAt.Format(time.RFC3339),
		}
	}

	jsonOK(w, map[string]interface{}{
		"proposals": items,
	})
}

type adminApproveRequest struct {
	Vault       string            `json:"vault"`
	Credentials map[string]string `json:"credentials"` // human-provided credential values (plaintext)
}

func (s *Server) handleAdminProposalApprove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	var req adminApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Approving proposals: agents need admin role; users need vault access.
	if _, err := s.requireProposalReview(w, r, ns.ID); err != nil {
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal %d not found", id))
		return
	}
	if cs.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("Proposal %d is already %s", id, cs.Status))
		return
	}

	// Parse proposed services and credential slots.
	var proposedServices []proposal.Service
	if err := json.Unmarshal([]byte(cs.ServicesJSON), &proposedServices); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse proposal services")
		return
	}
	var credentialSlots []proposal.CredentialSlot
	if err := json.Unmarshal([]byte(cs.CredentialsJSON), &credentialSlots); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse proposal credentials")
		return
	}

	// Load agent-provided encrypted credentials.
	agentCredentials, err := s.store.GetProposalCredentials(ctx, ns.ID, cs.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load proposal credentials")
		return
	}

	// Resolve final credential values for set slots; collect keys for delete slots.
	finalCredentials := make(map[string]store.EncryptedCredential)
	var deleteCredentialKeys []string
	for _, slot := range credentialSlots {
		if slot.Action == proposal.ActionDelete {
			deleteCredentialKeys = append(deleteCredentialKeys, slot.Key)
			continue
		}

		var plaintext string

		if override, ok := req.Credentials[slot.Key]; ok {
			// Human-provided override.
			plaintext = override
		} else if slot.HasValue {
			// Agent-provided value: decrypt to re-encrypt with current key.
			enc, ok := agentCredentials[slot.Key]
			if !ok {
				jsonError(w, http.StatusBadRequest, fmt.Sprintf("Agent-provided credential %q not found in proposal", slot.Key))
				return
			}
			decrypted, err := crypto.Decrypt(enc.Ciphertext, enc.Nonce, s.encKey)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to decrypt agent-provided credential %q", slot.Key))
				return
			}
			plaintext = string(decrypted)
			crypto.WipeBytes(decrypted)
		} else {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Missing value for credential %q", slot.Key))
			return
		}

		if plaintext == "" {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Credential %q cannot be empty", slot.Key))
			return
		}

		ct, nonce, err := crypto.Encrypt([]byte(plaintext), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encrypt credential %q", slot.Key))
			return
		}
		finalCredentials[slot.Key] = store.EncryptedCredential{Ciphertext: ct, Nonce: nonce}
	}

	// Merge services.
	bc, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil {
		// No existing config — start fresh.
		bc = &store.BrokerConfig{ServicesJSON: "[]"}
	}

	var existingServices []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &existingServices); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to parse existing services")
		return
	}

	merged, _ := proposal.MergeServices(existingServices, proposedServices)
	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to marshal merged services")
		return
	}

	// Apply atomically.
	if err := s.store.ApplyProposal(ctx, ns.ID, cs.ID, string(mergedJSON), finalCredentials, deleteCredentialKeys); err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to apply proposal: %v", err))
		return
	}

	jsonOK(w, map[string]interface{}{
		"id":     id,
		"status": "applied",
	})
}

type adminRejectRequest struct {
	Vault  string `json:"vault"`
	Reason string `json:"reason"`
}

func (s *Server) handleAdminProposalReject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	var req adminRejectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Rejecting proposals: agents need admin role; users need vault access.
	if _, err := s.requireProposalReview(w, r, ns.ID); err != nil {
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal %d not found", id))
		return
	}
	if cs.Status != "pending" {
		jsonError(w, http.StatusConflict, fmt.Sprintf("Proposal %d is already %s", id, cs.Status))
		return
	}

	if err := s.store.UpdateProposalStatus(ctx, ns.ID, id, "rejected", req.Reason); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to reject proposal")
		return
	}

	jsonOK(w, map[string]interface{}{
		"id":     id,
		"status": "rejected",
	})
}

func (s *Server) handleAdminProposalList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nsName := r.URL.Query().Get("vault")
	if nsName == "" {
		nsName = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	// Proxy-role sessions can only view pending proposals (to avoid duplicates).
	sess := sessionFromContext(r.Context())
	isProxy := false
	if sess != nil {
		if sess.VaultID != "" {
			isProxy = sess.VaultRole == "proxy"
		} else if sess.AgentID != "" {
			if role, err := s.store.GetVaultRole(ctx, sess.AgentID, ns.ID); err == nil {
				isProxy = role == "proxy"
			}
		}
	}

	// Lazy expiration.
	_, _ = s.store.ExpirePendingProposals(ctx, time.Now().Add(-7*24*time.Hour))

	status := r.URL.Query().Get("status")
	if isProxy {
		status = "pending"
	}
	list, err := s.store.ListProposals(ctx, ns.ID, status)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list proposals")
		return
	}

	type csItem struct {
		ID              int     `json:"id"`
		Status          string  `json:"status"`
		Message         string  `json:"message"`
		ServicesJSON    string  `json:"services_json"`
		CredentialsJSON string  `json:"credentials_json"`
		ReviewNote      string  `json:"review_note,omitempty"`
		ReviewedAt      *string `json:"reviewed_at,omitempty"`
		CreatedAt       string  `json:"created_at"`
	}

	items := make([]csItem, len(list))
	for i, cs := range list {
		item := csItem{
			ID:              cs.ID,
			Status:          cs.Status,
			Message:         cs.Message,
			ServicesJSON:    cs.ServicesJSON,
			CredentialsJSON: cs.CredentialsJSON,
			ReviewNote:      cs.ReviewNote,
			CreatedAt:       cs.CreatedAt.Format(time.RFC3339),
		}
		if cs.ReviewedAt != nil {
			t := *cs.ReviewedAt
			item.ReviewedAt = &t
		}
		items[i] = item
	}

	jsonOK(w, map[string]interface{}{"proposals": items})
}

func (s *Server) handleAdminProposalGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	nsName := r.URL.Query().Get("vault")
	if nsName == "" {
		nsName = store.DefaultVault
	}

	ns, err := s.store.GetVault(ctx, nsName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", nsName))
		return
	}

	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid proposal id")
		return
	}

	cs, err := s.store.GetProposal(ctx, ns.ID, id)
	if err != nil || cs == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Proposal #%d not found in vault %q", id, nsName))
		return
	}

	// Proxy-role agents can only view pending proposals.
	sess := sessionFromContext(r.Context())
	if sess != nil && sess.VaultID != "" && sess.VaultRole == "proxy" && cs.Status != "pending" {
		jsonError(w, http.StatusForbidden, "Proxy-role agents can only view pending proposals")
		return
	}

	resp := map[string]interface{}{
		"id":               cs.ID,
		"status":           cs.Status,
		"message":          cs.Message,
		"user_message":     cs.UserMessage,
		"services_json":    cs.ServicesJSON,
		"credentials_json": cs.CredentialsJSON,
		"review_note":      cs.ReviewNote,
		"created_at":       cs.CreatedAt.Format(time.RFC3339),
	}
	if cs.ReviewedAt != nil {
		resp["reviewed_at"] = *cs.ReviewedAt
	}

	jsonOK(w, resp)
}
