package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/acquisition"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

const proposalAcquisitionSentinel = "PROPOSAL_ACQUISITION_SENTINEL_91d2"

func setupProposalAcquisitionEndpointTest(t *testing.T) (*Server, *mockStore, string) {
	t.Helper()
	srv, ms, token := setupAdminProposalTest(t)
	ms.settings[settingCredentialAcquisitionEnabled] = "true"
	seedProposalContextBinding(ms, false)
	bindingID := testServerContextBindingID
	proposalRows := ms.proposals["root-ns-id"]
	proposalRows[0].ContextBindingID = &bindingID
	proposalRows[0].ServicesJSON = `[]`
	proposalRows[0].CredentialsJSON = `[{"action":"set","key":"GITHUB_TOKEN","type":"static","acquisition":{"handler":"github-cli","profile":"github.com","mode":"native"}}]`
	ms.proposals["root-ns-id"] = proposalRows
	ms.acquisitionHandlers["github-cli"] = &store.AcquisitionHandler{
		ID: "github-cli", Generation: "generation-1", Kind: "executable", Enabled: true,
		ExecutablePath: "/usr/local/bin/provider", SHA256: strings.Repeat("a", 64),
		AllowedKeys: []string{"GITHUB_TOKEN"}, AllowedVaults: []string{"root-ns-id"},
		AllowedProfiles: []string{"github.com"}, TimeoutSeconds: 10, OutputLimitBytes: 65536,
	}
	if err := ms.SetVaultAcquisitionPolicy(context.Background(), "root-ns-id", store.VaultAcquisitionPolicy{
		EnabledHandlers: []string{"github-cli"},
	}); err != nil {
		t.Fatal(err)
	}
	return srv, ms, token
}

func startProposalAcquisitionRequest(t *testing.T, srv *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/acquisitions/GITHUB_TOKEN/start", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func waitProposalAcquisitionState(t *testing.T, ms *mockStore, state string) *store.ProposalAcquisition {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, err := ms.GetProposalAcquisition(context.Background(), "root-ns-id", 1, "GITHUB_TOKEN")
		if err == nil && job.State == state {
			return job
		}
		time.Sleep(5 * time.Millisecond)
	}
	job, err := ms.GetProposalAcquisition(context.Background(), "root-ns-id", 1, "GITHUB_TOKEN")
	t.Fatalf("state=%v err=%v want=%s", job, err, state)
	return nil
}

func TestProposalAcquisitionStartRunsProviderAndStoresOnlyEncryptedCredential(t *testing.T) {
	srv, ms, token := setupProposalAcquisitionEndpointTest(t)
	invocations := make(chan acquisition.ProviderInvocation, 1)
	srv.runAcquisitionProvider = func(_ context.Context, _ acquisition.HandlerResolver, handlerID string, invocation acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
		if handlerID != "github-cli" {
			t.Fatalf("handler=%q", handlerID)
		}
		invocations <- invocation
		secret, err := acquisition.NewSecretBuffer([]byte(proposalAcquisitionSentinel))
		if err != nil {
			return nil, err
		}
		return &acquisition.ProviderResult{Secret: secret, Meta: acquisition.ReplyMeta{
			IssuedAtUnix: time.Now().Unix(), TTLSeconds: 3600, Source: "github_cli",
		}}, nil
	}

	rec := startProposalAcquisitionRequest(t, srv, token, `{"vault":"default","handler":"github-cli","profile":"github.com"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start status=%d body=%s", rec.Code, rec.Body.String())
	}
	job := waitProposalAcquisitionState(t, ms, store.AcquisitionSucceeded)
	invocation := <-invocations
	if invocation.HandlerGeneration != "generation-1" || invocation.ContextBindingID != testServerContextBindingID ||
		invocation.Profile != "github.com" || invocation.Params["mode"] != "native" {
		t.Fatalf("invocation lost pinned identity: %+v", invocation)
	}
	credentials, err := ms.GetProposalCredentials(context.Background(), "root-ns-id", 1)
	if err != nil {
		t.Fatal(err)
	}
	credential := credentials["GITHUB_TOKEN"]
	plaintext, err := crypto.Decrypt(credential.Ciphertext, credential.Nonce, srv.encKey)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.WipeBytes(plaintext)
	if string(plaintext) != proposalAcquisitionSentinel {
		t.Fatal("acquired credential did not round trip")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/v1/admin/proposals/1/acquisitions?vault=default&key=GITHUB_TOKEN", nil)
	statusReq.Header.Set("Authorization", "Bearer "+token)
	statusRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK || strings.Contains(statusRec.Body.String(), proposalAcquisitionSentinel) || strings.Contains(statusRec.Body.String(), "continuation_ticket_hash") {
		t.Fatalf("unsafe status response=%d %s", statusRec.Code, statusRec.Body.String())
	}
	var status struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(statusRec.Body).Decode(&status); err != nil || status.ID != job.ID || status.State != store.AcquisitionSucceeded {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestProposalAcquisitionAwaitingUserAndCancellation(t *testing.T) {
	t.Run("awaiting user completes with one-time continuation state", func(t *testing.T) {
		srv, ms, token := setupProposalAcquisitionEndpointTest(t)
		release := make(chan struct{})
		srv.runAcquisitionProvider = func(ctx context.Context, _ acquisition.HandlerResolver, _ string, invocation acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
			invocation.ProgressSink <- acquisition.Progress{Status: acquisition.ProgressAwaitingUser, ContextBindingID: invocation.ContextBindingID}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			secret, err := acquisition.NewSecretBuffer([]byte(proposalAcquisitionSentinel))
			if err != nil {
				return nil, err
			}
			return &acquisition.ProviderResult{Secret: secret, Meta: acquisition.ReplyMeta{IssuedAtUnix: time.Now().Unix(), Source: "guided"}}, nil
		}
		rec := startProposalAcquisitionRequest(t, srv, token, `{"vault":"default","handler":"github-cli","profile":"github.com"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		awaiting := waitProposalAcquisitionState(t, ms, store.AcquisitionAwaitingUser)
		if len(awaiting.ContinuationTicketHash) != 32 || awaiting.ContinuationExpiresAt == nil {
			t.Fatalf("awaiting metadata=%+v", awaiting)
		}
		statusReq := httptest.NewRequest(http.MethodGet, "/v1/admin/proposals/1/acquisitions?vault=default&key=GITHUB_TOKEN", nil)
		statusReq.Header.Set("Authorization", "Bearer "+token)
		statusRec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(statusRec, statusReq)
		body := statusRec.Body.String()
		for _, forbidden := range []string{
			proposalAcquisitionSentinel,
			"generation-1",
			testServerContextBindingID,
			hex.EncodeToString(awaiting.ContinuationTicketHash),
			base64.StdEncoding.EncodeToString(awaiting.ContinuationTicketHash),
			"continuation_ticket_hash",
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("status leaked %q: %s", forbidden, body)
			}
		}
		if statusRec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", statusRec.Code, body)
		}
		close(release)
		completed := waitProposalAcquisitionState(t, ms, store.AcquisitionSucceeded)
		if completed.ContinuationUsedAt == nil {
			t.Fatal("continuation was not atomically consumed")
		}
	})

	t.Run("cancel terminates active provider", func(t *testing.T) {
		srv, ms, token := setupProposalAcquisitionEndpointTest(t)
		started := make(chan struct{})
		finished := make(chan struct{})
		srv.runAcquisitionProvider = func(ctx context.Context, _ acquisition.HandlerResolver, _ string, _ acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
			close(started)
			<-ctx.Done()
			close(finished)
			return nil, ctx.Err()
		}
		rec := startProposalAcquisitionRequest(t, srv, token, `{"vault":"default","handler":"github-cli","profile":"github.com"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		<-started
		cancelReq := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/acquisitions/GITHUB_TOKEN/cancel", strings.NewReader(`{"vault":"default"}`))
		cancelReq.Header.Set("Authorization", "Bearer "+token)
		cancelRec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(cancelRec, cancelReq)
		if cancelRec.Code != http.StatusOK {
			t.Fatalf("cancel status=%d body=%s", cancelRec.Code, cancelRec.Body.String())
		}
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("provider was not cancelled")
		}
		waitProposalAcquisitionState(t, ms, store.AcquisitionCancelled)
	})

	t.Run("cancel from another server terminates active provider", func(t *testing.T) {
		srv, ms, token := setupProposalAcquisitionEndpointTest(t)
		peer := newTestServer(withStore(ms), withEncKey(srv.encKey))
		started := make(chan struct{})
		finished := make(chan struct{})
		srv.runAcquisitionProvider = func(ctx context.Context, _ acquisition.HandlerResolver, _ string, _ acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
			close(started)
			<-ctx.Done()
			close(finished)
			return nil, ctx.Err()
		}
		t.Cleanup(func() { srv.stopAcquisitionJobs(time.Second) })

		rec := startProposalAcquisitionRequest(t, srv, token, `{"vault":"default","handler":"github-cli","profile":"github.com"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		<-started

		cancelReq := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/acquisitions/GITHUB_TOKEN/cancel", strings.NewReader(`{"vault":"default"}`))
		cancelReq.Header.Set("Authorization", "Bearer "+token)
		cancelRec := httptest.NewRecorder()
		peer.httpServer.Handler.ServeHTTP(cancelRec, cancelReq)
		if cancelRec.Code != http.StatusOK {
			t.Fatalf("cancel status=%d body=%s", cancelRec.Code, cancelRec.Body.String())
		}
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("provider was not cancelled after peer updated shared state")
		}
		waitProposalAcquisitionState(t, ms, store.AcquisitionCancelled)
	})

	t.Run("transient shared-state read failure does not cancel provider", func(t *testing.T) {
		srv, ms, token := setupProposalAcquisitionEndpointTest(t)
		observedFailure := make(chan struct{}, 1)
		ms.proposalAcquisitionByIDFailures = 1
		ms.proposalAcquisitionByIDFailure = observedFailure
		release := make(chan struct{})
		providerExit := make(chan error, 1)
		srv.runAcquisitionProvider = func(ctx context.Context, _ acquisition.HandlerResolver, _ string, _ acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
			select {
			case <-ctx.Done():
				providerExit <- ctx.Err()
				return nil, ctx.Err()
			case <-release:
			}
			secret, err := acquisition.NewSecretBuffer([]byte(proposalAcquisitionSentinel))
			if err != nil {
				providerExit <- err
				return nil, err
			}
			providerExit <- nil
			return &acquisition.ProviderResult{Secret: secret, Meta: acquisition.ReplyMeta{Source: "transient-retry"}}, nil
		}
		t.Cleanup(func() { srv.stopAcquisitionJobs(time.Second) })

		rec := startProposalAcquisitionRequest(t, srv, token, `{"vault":"default","handler":"github-cli","profile":"github.com"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		select {
		case <-observedFailure:
		case <-time.After(time.Second):
			t.Fatal("shared-state read failure was not exercised")
		}
		select {
		case err := <-providerExit:
			t.Fatalf("provider exited after transient state read failure: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		close(release)
		if err := <-providerExit; err != nil {
			t.Fatalf("provider completion error: %v", err)
		}
		waitProposalAcquisitionState(t, ms, store.AcquisitionSucceeded)
	})
}

func TestProposalAcquisitionEndpointsRequireProposalReviewer(t *testing.T) {
	srv, ms, token := setupProposalAcquisitionEndpointTest(t)
	if err := ms.GrantVaultRole(context.Background(), "owner-user-id", "user", "root-ns-id", "proxy"); err != nil {
		t.Fatal(err)
	}
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/acquisitions/GITHUB_TOKEN/start", strings.NewReader(`{"vault":"default","handler":"github-cli","profile":"github.com"}`)),
		httptest.NewRequest(http.MethodGet, "/v1/admin/proposals/1/acquisitions?vault=default&key=GITHUB_TOKEN", nil),
		httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/acquisitions/GITHUB_TOKEN/cancel", strings.NewReader(`{"vault":"default"}`)),
	} {
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d body=%s", req.Method, req.URL.Path, rec.Code, rec.Body.String())
		}
	}
}

func TestProposalAcquisitionStatusAndCancelRemainAvailableAfterStartGateCloses(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*mockStore)
	}{
		{"instance disabled", func(ms *mockStore) { ms.settings[settingCredentialAcquisitionEnabled] = "false" }},
		{"external store", func(ms *mockStore) {
			ms.credStores["root-ns-id"] = &store.VaultCredentialStore{VaultID: "root-ns-id", Kind: store.CredentialStoreInfisical}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, ms, token := setupProposalAcquisitionEndpointTest(t)
			if _, err := ms.StartProposalAcquisition(context.Background(), store.ProposalAcquisitionStart{
				VaultID: "root-ns-id", ProposalID: 1, CredentialKey: "GITHUB_TOKEN",
				HandlerID: "github-cli", Profile: "github.com", Mode: "native",
			}); err != nil {
				t.Fatal(err)
			}
			tt.mutate(ms)

			statusReq := httptest.NewRequest(http.MethodGet, "/v1/admin/proposals/1/acquisitions?vault=default&key=GITHUB_TOKEN", nil)
			statusReq.Header.Set("Authorization", "Bearer "+token)
			statusRec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(statusRec, statusReq)
			if statusRec.Code != http.StatusOK {
				t.Fatalf("status endpoint=%d body=%s", statusRec.Code, statusRec.Body.String())
			}

			cancelReq := httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/acquisitions/GITHUB_TOKEN/cancel", strings.NewReader(`{"vault":"default"}`))
			cancelReq.Header.Set("Authorization", "Bearer "+token)
			cancelRec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(cancelRec, cancelReq)
			if cancelRec.Code != http.StatusOK {
				t.Fatalf("cancel endpoint=%d body=%s", cancelRec.Code, cancelRec.Body.String())
			}
		})
	}
}

func TestProposalAcquisitionInvalidProgressFailsInsteadOfCancelling(t *testing.T) {
	srv, ms, token := setupProposalAcquisitionEndpointTest(t)
	srv.runAcquisitionProvider = func(ctx context.Context, _ acquisition.HandlerResolver, _ string, invocation acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
		invocation.ProgressSink <- acquisition.Progress{
			Status: acquisition.ProgressAwaitingUser, ContextBindingID: "av_ctx_wrong",
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	rec := startProposalAcquisitionRequest(t, srv, token, `{"vault":"default","handler":"github-cli","profile":"github.com"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	failed := waitProposalAcquisitionState(t, ms, store.AcquisitionFailed)
	if failed.ErrorCode != "progress_invalid" {
		t.Fatalf("state=%s error_code=%q", failed.State, failed.ErrorCode)
	}
}

func TestStopAcquisitionJobsCancelsAndDrainsProvider(t *testing.T) {
	srv, ms, token := setupProposalAcquisitionEndpointTest(t)
	started := make(chan struct{})
	finished := make(chan struct{})
	srv.runAcquisitionProvider = func(ctx context.Context, _ acquisition.HandlerResolver, _ string, _ acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
		close(started)
		<-ctx.Done()
		close(finished)
		return nil, ctx.Err()
	}
	rec := startProposalAcquisitionRequest(t, srv, token, `{"vault":"default","handler":"github-cli","profile":"github.com"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	<-started
	if !srv.stopAcquisitionJobs(time.Second) {
		t.Fatal("acquisition jobs did not drain")
	}
	select {
	case <-finished:
	default:
		t.Fatal("provider was not stopped before drain returned")
	}
	waitProposalAcquisitionState(t, ms, store.AcquisitionCancelled)
}

func TestProposalAcquisitionLookupFailureReturnsInternalError(t *testing.T) {
	srv, ms, token := setupProposalAcquisitionEndpointTest(t)
	ms.getProposalErr = errors.New("database unavailable")
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/admin/proposals/1/acquisitions?vault=default&key=GITHUB_TOKEN", nil),
		httptest.NewRequest(http.MethodPost, "/v1/admin/proposals/1/acquisitions/GITHUB_TOKEN/cancel", strings.NewReader(`{"vault":"default"}`)),
	} {
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s %s status=%d body=%s", req.Method, req.URL.Path, rec.Code, rec.Body.String())
		}
	}
}

func TestProposalAcquisitionStartGuards(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*mockStore)
		body   string
		code   int
	}{
		{"feature disabled", func(ms *mockStore) { ms.settings[settingCredentialAcquisitionEnabled] = "false" }, `{"vault":"default","handler":"github-cli","profile":"github.com"}`, http.StatusConflict},
		{"external store", func(ms *mockStore) {
			ms.credStores["root-ns-id"] = &store.VaultCredentialStore{VaultID: "root-ns-id", Kind: store.CredentialStoreInfisical}
		}, `{"vault":"default","handler":"github-cli","profile":"github.com"}`, http.StatusConflict},
		{"policy disabled", func(ms *mockStore) {
			_ = ms.SetVaultAcquisitionPolicy(context.Background(), "root-ns-id", store.VaultAcquisitionPolicy{})
		}, `{"vault":"default","handler":"github-cli","profile":"github.com"}`, http.StatusConflict},
		{"request mismatch", func(*mockStore) {}, `{"vault":"default","handler":"other","profile":"github.com"}`, http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, ms, token := setupProposalAcquisitionEndpointTest(t)
			tt.mutate(ms)
			srv.runAcquisitionProvider = func(context.Context, acquisition.HandlerResolver, string, acquisition.ProviderInvocation) (*acquisition.ProviderResult, error) {
				return nil, errors.New("must not run")
			}
			rec := startProposalAcquisitionRequest(t, srv, token, tt.body)
			if rec.Code != tt.code {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tt.code, rec.Body.String())
			}
		})
	}
}
