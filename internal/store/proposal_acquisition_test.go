package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProposalAcquisitionMigrationAndLifecycle(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()

	var table string
	if err := s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='proposal_acquisitions'").Scan(&table); err != nil {
		t.Fatalf("proposal_acquisitions table missing: %v", err)
	}

	started, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if err != nil {
		t.Fatalf("StartProposalAcquisition: %v", err)
	}
	if started.ID == "" || started.State != AcquisitionQueued || started.ContextBindingID != *proposal.ContextBindingID {
		t.Fatalf("unexpected started acquisition: %+v", started)
	}
	if started.HandlerGeneration != handler.Generation {
		t.Fatalf("handler generation=%q want %q", started.HandlerGeneration, handler.Generation)
	}

	if _, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	}); !errors.Is(err, ErrProposalAcquisitionActive) {
		t.Fatalf("second active start error=%v", err)
	}

	running, err := s.MarkProposalAcquisitionRunning(ctx, started.ID)
	if err != nil || running.State != AcquisitionRunning || running.StartedAt == nil {
		t.Fatalf("MarkProposalAcquisitionRunning=%+v err=%v", running, err)
	}
	rawTicket := []byte("continuation-ticket-never-persisted")
	ticketHash := sha256.Sum256(rawTicket)
	continuationExpiry := time.Now().UTC().Add(5 * time.Minute)
	awaiting, err := s.MarkProposalAcquisitionAwaitingUser(ctx, started.ID, ticketHash[:], continuationExpiry)
	if err != nil || awaiting.State != AcquisitionAwaitingUser || awaiting.ContinuationExpiresAt == nil {
		t.Fatalf("MarkProposalAcquisitionAwaitingUser=%+v err=%v", awaiting, err)
	}
	consumed, err := s.ConsumeProposalAcquisitionContinuation(ctx, ticketHash[:], time.Now().UTC())
	if err != nil || consumed.ID != started.ID || consumed.ContinuationUsedAt == nil {
		t.Fatalf("ConsumeProposalAcquisitionContinuation=%+v err=%v", consumed, err)
	}
	if _, err := s.ConsumeProposalAcquisitionContinuation(ctx, ticketHash[:], time.Now().UTC()); !errors.Is(err, ErrProposalAcquisitionContinuationUnavailable) {
		t.Fatalf("continuation replay error=%v", err)
	}

	credentialExpiry := time.Now().UTC().Add(time.Hour)
	completed, err := s.CompleteProposalAcquisition(ctx, started.ID, EncryptedCredential{
		Ciphertext: []byte("encrypted-sentinel"), Nonce: []byte("nonce-sentinel"),
	}, "github_cli", &credentialExpiry)
	if err != nil {
		t.Fatalf("CompleteProposalAcquisition: %v", err)
	}
	if completed.State != AcquisitionSucceeded || completed.Source != "github_cli" || completed.CompletedAt == nil || completed.CredentialExpiresAt == nil {
		t.Fatalf("unexpected completed acquisition: %+v", completed)
	}
	credentials, err := s.GetProposalCredentials(ctx, proposal.VaultID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := credentials["GITHUB_TOKEN"]; string(got.Ciphertext) != "encrypted-sentinel" || string(got.Nonce) != "nonce-sentinel" {
		t.Fatalf("proposal credential mismatch: %+v", got)
	}

	restarted, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if err != nil || restarted.ID == started.ID {
		t.Fatalf("restart=%+v err=%v", restarted, err)
	}
	history, err := s.ListProposalAcquisitions(ctx, proposal.VaultID, proposal.ID)
	if err != nil || len(history) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}

func TestProposalAcquisitionConcurrentStartAllowsOneActiveJob(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	start := ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.StartProposalAcquisition(ctx, start)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	var succeeded, conflicted int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrProposalAcquisitionActive):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent start error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func TestProposalAcquisitionStartRequiresVaultPolicyHandler(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	if err := s.DeleteVaultSetting(ctx, proposal.VaultID, VaultSettingCredentialAcquisitionPolicy); err != nil {
		t.Fatal(err)
	}

	_, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if !errors.Is(err, ErrAcquisitionPolicyHandlerUnavailable) {
		t.Fatalf("start without vault policy error=%v", err)
	}
}

func TestProposalAcquisitionStartRejectsMalformedOrMismatchedVaultPolicy(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
	}{
		{"null", `null`},
		{"null handlers", `{"enabled_handlers":null,"browser_dom_enabled":false}`},
		{"duplicate handler", `{"enabled_handlers":["github-cli","github-cli"],"browser_dom_enabled":false}`},
		{"different handler", `{"enabled_handlers":["other-handler"],"browser_dom_enabled":false}`},
		{"null browser flag", `{"enabled_handlers":["github-cli"],"browser_dom_enabled":null}`},
		{"unknown field", `{"enabled_handlers":["github-cli"],"browser_dom_enabled":false,"executable":"/tmp/provider"}`},
		{"duplicate field", `{"enabled_handlers":[],"enabled_handlers":["github-cli"],"browser_dom_enabled":false}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, proposal, handler := setupProposalAcquisition(t)
			ctx := context.Background()
			if err := s.SetVaultSetting(ctx, proposal.VaultID, VaultSettingCredentialAcquisitionPolicy, tt.raw); err != nil {
				t.Fatal(err)
			}
			_, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
				VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
				HandlerID: handler.ID, Profile: "github.com", Mode: "native",
			})
			if !errors.Is(err, ErrAcquisitionPolicyHandlerUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProposalAcquisitionGuardsAndAtomicCompletion(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	start := ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	}

	start.Profile = "wrong-host"
	if _, err := s.StartProposalAcquisition(ctx, start); !errors.Is(err, ErrAcquisitionHandlerUnavailable) {
		t.Fatalf("wrong profile error=%v", err)
	}
	start.Profile = "github.com"
	job, err := s.StartProposalAcquisition(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteProposalAcquisition(ctx, job.ID, EncryptedCredential{Ciphertext: []byte("ct"), Nonce: []byte("nonce")}, "test", nil); !errors.Is(err, ErrProposalAcquisitionStateConflict) {
		t.Fatalf("complete-before-running error=%v", err)
	}
	if _, err := s.MarkProposalAcquisitionRunning(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireContextBinding(ctx, *proposal.ContextBindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteProposalAcquisition(ctx, job.ID, EncryptedCredential{Ciphertext: []byte("ct"), Nonce: []byte("nonce")}, "test", nil); !errors.Is(err, ErrContextBindingInactive) {
		t.Fatalf("completion with retired binding error=%v", err)
	}
	credentials, err := s.GetProposalCredentials(ctx, proposal.VaultID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 0 {
		t.Fatalf("credential persisted despite failed atomic completion: %+v", credentials)
	}
}

func TestProposalAcquisitionQueuedJobRejectsHandlerGenerationDrift(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	job, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAcquisitionHandler(ctx, handler.ID); err != nil {
		t.Fatal(err)
	}
	replacement := handler
	replacement.Generation = ""
	replacement.SHA256 = strings.Repeat("b", 64)
	created, err := s.CreateAcquisitionHandler(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAcquisitionHandlerEnabled(ctx, created.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkProposalAcquisitionRunning(ctx, job.ID); !errors.Is(err, ErrAcquisitionHandlerUnavailable) {
		t.Fatalf("handler generation drift error=%v", err)
	}
}

func TestProposalAcquisitionCancellationReleasesActiveSlot(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	start := ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	}
	job, err := s.StartProposalAcquisition(ctx, start)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := s.CancelProposalAcquisition(ctx, proposal.VaultID, proposal.ID, "GITHUB_TOKEN")
	if err != nil || cancelled.ID != job.ID || cancelled.State != AcquisitionCancelled {
		t.Fatalf("cancelled=%+v err=%v", cancelled, err)
	}
	if _, err := s.StartProposalAcquisition(ctx, start); err != nil {
		t.Fatalf("restart after cancellation: %v", err)
	}
}

func TestProposalAcquisitionAwaitingUserRequiresLiveConsumedContinuation(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	job, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkProposalAcquisitionRunning(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	ticketHash := sha256.Sum256([]byte("one-time-continuation"))
	if _, err := s.MarkProposalAcquisitionAwaitingUser(ctx, job.ID, ticketHash[:], time.Now().UTC().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteProposalAcquisition(ctx, job.ID, EncryptedCredential{
		Ciphertext: []byte("ct"), Nonce: []byte("nonce"),
	}, "test", nil); !errors.Is(err, ErrProposalAcquisitionContinuationUnavailable) {
		t.Fatalf("completion without continuation consumption error=%v", err)
	}
}

func TestProposalAcquisitionContinuationTTLIsStrictlyFiveMinutes(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	job, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkProposalAcquisitionRunning(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	ticketHash := sha256.Sum256([]byte("overlong-continuation"))
	if _, err := s.MarkProposalAcquisitionAwaitingUser(ctx, job.ID, ticketHash[:], time.Now().UTC().Add(5*time.Minute+500*time.Millisecond)); err == nil {
		t.Fatal("expected continuation TTL over five minutes to be rejected")
	}
}

func TestProposalAcquisitionContinuationCompletionIsAtomicAndReplaySafe(t *testing.T) {
	s, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	job, err := s.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkProposalAcquisitionRunning(ctx, job.ID); err != nil {
		t.Fatal(err)
	}
	ticketHash := sha256.Sum256([]byte("atomic-continuation"))
	if _, err := s.MarkProposalAcquisitionAwaitingUser(ctx, job.ID, ticketHash[:], time.Now().UTC().Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	completed, err := s.CompleteProposalAcquisitionContinuation(ctx, ticketHash[:], EncryptedCredential{
		Ciphertext: []byte("atomic-ct"), Nonce: []byte("atomic-nonce"),
	}, "native_host", nil)
	if err != nil || completed.State != AcquisitionSucceeded || completed.ContinuationUsedAt == nil {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	if _, err := s.CompleteProposalAcquisitionContinuation(ctx, ticketHash[:], EncryptedCredential{
		Ciphertext: []byte("replay-ct"), Nonce: []byte("replay-nonce"),
	}, "native_host", nil); !errors.Is(err, ErrProposalAcquisitionContinuationUnavailable) {
		t.Fatalf("continuation replay error=%v", err)
	}
	credentials, err := s.GetProposalCredentials(ctx, proposal.VaultID, proposal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := credentials["GITHUB_TOKEN"]; string(got.Ciphertext) != "atomic-ct" || string(got.Nonce) != "atomic-nonce" {
		t.Fatalf("replay changed credential: %+v", got)
	}
}

func setupProposalAcquisition(t *testing.T) (*SQLStore, *Proposal, AcquisitionHandler) {
	t.Helper()
	s := openTestDB(t)
	ctx := context.Background()
	vault, err := s.GetVault(ctx, DefaultVault)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := s.CreateContextBinding(ctx, testContextBindingTuple())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := s.CreateProposalWithContext(ctx, vault.ID, "acquisition-test-session", binding.ID, "[]", "[]", "test", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := testAcquisitionHandler()
	handler.AllowedVaults = []string{vault.ID}
	created, err := s.CreateAcquisitionHandler(ctx, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAcquisitionHandlerEnabled(ctx, created.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVaultAcquisitionPolicy(ctx, vault.ID, VaultAcquisitionPolicy{
		EnabledHandlers: []string{created.ID},
	}); err != nil {
		t.Fatal(err)
	}
	handler, err = func() (AcquisitionHandler, error) {
		got, getErr := s.GetAcquisitionHandler(ctx, created.ID)
		if getErr != nil {
			return AcquisitionHandler{}, getErr
		}
		return *got, nil
	}()
	if err != nil {
		t.Fatal(err)
	}
	return s, proposal, handler
}

func TestProposalAcquisitionMissingRowsUseSQLNoRows(t *testing.T) {
	s := openTestDB(t)
	if _, err := s.GetProposalAcquisition(context.Background(), "missing", 1, "TOKEN"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing acquisition error=%v", err)
	}
}

func TestProposalAcquisitionsAreIncludedInDataCopy(t *testing.T) {
	src, proposal, handler := setupProposalAcquisition(t)
	ctx := context.Background()
	want, err := src.StartProposalAcquisition(ctx, ProposalAcquisitionStart{
		VaultID: proposal.VaultID, ProposalID: proposal.ID, CredentialKey: "GITHUB_TOKEN",
		HandlerID: handler.ID, Profile: "github.com", Mode: "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	counts, err := CountSourceTables(src)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, count := range counts {
		if count.Table == "proposal_acquisitions" && count.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("proposal_acquisitions missing from source counts: %+v", counts)
	}

	dst := openTestDB(t)
	if err := MigrateData(ctx, src, dst, nil); err != nil {
		t.Fatalf("MigrateData: %v", err)
	}
	got, err := dst.GetProposalAcquisitionByID(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContextBindingID != want.ContextBindingID || got.HandlerGeneration != want.HandlerGeneration || got.State != AcquisitionQueued {
		t.Fatalf("copied acquisition mismatch: got=%+v want=%+v", got, want)
	}
}
