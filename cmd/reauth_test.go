package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
)

func TestDoAdminRequestWithBody_401WrapsErrSessionExpired(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"session expired", `{"error":"Session expired"}`},
		{"invalid or expired session", `{"error":"Invalid or expired session"}`},
		{"authorization required", `{"error":"Authorization required"}`},
		{"empty body still wraps", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := doAdminRequestWithBody(http.MethodGet, srv.URL+"/whatever", "stale-token", nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, errSessionExpired) {
				t.Fatalf("err %q does not wrap errSessionExpired", err)
			}
		})
	}
}

func TestDoAdminRequestWithBody_401MessageDoesNotStutter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Session expired"}`))
	}))
	defer srv.Close()

	_, err := doAdminRequestWithBody(http.MethodGet, srv.URL+"/x", "tok", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "Session expired" {
		t.Fatalf("expected exact server message %q, got %q", "Session expired", got)
	}
}

func TestRequestScopedSession_401MessagePreservesPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Session expired"}`))
	}))
	defer srv.Close()

	_, err := requestScopedSession(srv.URL, "tok", "default", "", 0)
	if err == nil {
		t.Fatal("expected error")
	}
	want := "failed to create scoped session: Session expired"
	if got := err.Error(); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestDoAdminRequestWithBody_Non401DoesNotWrap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	_, err := doAdminRequestWithBody(http.MethodGet, srv.URL+"/whatever", "tok", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, errSessionExpired) {
		t.Fatalf("403 should not wrap errSessionExpired, got %q", err)
	}
}

func TestRequestScopedSession_401WrapsErrSessionExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Session expired"}`))
	}))
	defer srv.Close()

	_, err := requestScopedSession(srv.URL, "stale-token", "default", "", 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errSessionExpired) {
		t.Fatalf("err %q does not wrap errSessionExpired", err)
	}
}

func TestFetchUserVaults_401WrapsErrSessionExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Session expired"}`))
	}))
	defer srv.Close()

	_, err := fetchUserVaults(srv.URL, "stale-token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errSessionExpired) {
		t.Fatalf("err %q does not wrap errSessionExpired", err)
	}
}

func TestFetchUserVaults_401PreservesServerMessage(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{`{"error":"Authorization required"}`, "listing vaults: Authorization required"},
		{`{"error":"Invalid or expired session"}`, "listing vaults: Invalid or expired session"},
		{``, "listing vaults: status 401"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := fetchUserVaults(srv.URL, "tok")
			if err == nil {
				t.Fatal("expected error")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

// TestMintScopedSession_VaultResolutionMemoized asserts that when the admin
// session expires between the vault lookup and the scoped-session mint, the
// retry does not re-run vault resolution — otherwise a multi-vault user
// would be re-prompted by the picker, and a single-vault user would pay an
// extra `/v1/vaults` round-trip.
func TestMintScopedSession_VaultResolutionMemoized(t *testing.T) {
	// Isolate $HOME so a developer-set ~/.agent-vault/context doesn't
	// short-circuit resolveVaultForRun before fetchUserVaults runs.
	t.Setenv("HOME", t.TempDir())

	var vaultsHits, sessionsHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults":
			vaultsHits++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vaults":[{"name":"myvault"}]}`))
		case "/v1/sessions":
			sessionsHits++
			if sessionsHits == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"Session expired"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"scoped-token"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	withTestStubs(t, true, func(s *session.ClientSession) (*session.ClientSession, error) {
		return &session.ClientSession{Token: "fresh", Address: s.Address}, nil
	})

	cmd := &cobra.Command{}
	cmd.Flags().String("vault", "", "")

	sess := &session.ClientSession{Token: "stale", Address: srv.URL}
	vault, token, err := mintScopedSession(cmd, sess, srv.URL, "", 0)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if vault != "myvault" {
		t.Fatalf("expected vault=myvault, got %q", vault)
	}
	if token != "scoped-token" {
		t.Fatalf("expected token=scoped-token, got %q", token)
	}
	if vaultsHits != 1 {
		t.Fatalf("expected /v1/vaults hit exactly once across retry, got %d", vaultsHits)
	}
	if sessionsHits != 2 {
		t.Fatalf("expected /v1/sessions hit twice (initial + retry), got %d", sessionsHits)
	}
}

// withTestStubs swaps the package-level isInteractiveFn / reauthFn for the
// duration of the test and restores them on cleanup.
func withTestStubs(t *testing.T, interactive bool, reauth func(*session.ClientSession) (*session.ClientSession, error)) {
	t.Helper()
	origInteractive := isInteractiveFn
	origReauth := reauthFn
	isInteractiveFn = func() bool { return interactive }
	reauthFn = reauth
	t.Cleanup(func() {
		isInteractiveFn = origInteractive
		reauthFn = origReauth
	})
}

func TestWithReauthRetry_NonInteractiveReturnsOriginalError(t *testing.T) {
	withTestStubs(t, false, func(s *session.ClientSession) (*session.ClientSession, error) {
		t.Fatal("reauth should not run when stdin is not a TTY")
		return nil, nil
	})

	calls := 0
	original := errSessionExpired
	sess := &session.ClientSession{Token: "stale", Address: "http://x"}
	err := withReauthRetry(sess, sess.Address, func(s *session.ClientSession) error {
		calls++
		return original
	})
	if calls != 1 {
		t.Fatalf("op should run exactly once, ran %d times", calls)
	}
	if !errors.Is(err, errSessionExpired) {
		t.Fatalf("expected wrapped errSessionExpired, got %v", err)
	}
	if sess.Token != "stale" {
		t.Fatalf("session token should be untouched, got %q", sess.Token)
	}
}

func TestWithReauthRetry_NoErrorRunsOpOnce(t *testing.T) {
	withTestStubs(t, true, func(s *session.ClientSession) (*session.ClientSession, error) {
		t.Fatal("reauth should not run when op succeeds")
		return nil, nil
	})

	calls := 0
	sess := &session.ClientSession{Token: "good", Address: "http://x"}
	err := withReauthRetry(sess, sess.Address, func(s *session.ClientSession) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("op should run exactly once, ran %d times", calls)
	}
}

func TestWithReauthRetry_RetriesAfterReauth(t *testing.T) {
	reauthCalls := 0
	withTestStubs(t, true, func(s *session.ClientSession) (*session.ClientSession, error) {
		reauthCalls++
		return &session.ClientSession{Token: "fresh", Address: s.Address, Email: "user@example.com"}, nil
	})

	sess := &session.ClientSession{Token: "stale", Address: "http://x"}
	calls := 0
	var seenTokens []string
	err := withReauthRetry(sess, sess.Address, func(s *session.ClientSession) error {
		calls++
		seenTokens = append(seenTokens, s.Token)
		if calls == 1 {
			return errSessionExpired
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil after retry, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("op should run twice, ran %d times", calls)
	}
	if reauthCalls != 1 {
		t.Fatalf("reauth should run exactly once, ran %d times", reauthCalls)
	}
	if seenTokens[0] != "stale" || seenTokens[1] != "fresh" {
		t.Fatalf("op should see fresh token on retry, saw %v", seenTokens)
	}
	if sess.Token != "fresh" || sess.Email != "user@example.com" {
		t.Fatalf("caller's session should be updated in place, got %+v", sess)
	}
}

func TestWithReauthRetry_DoesNotLoop(t *testing.T) {
	reauthCalls := 0
	withTestStubs(t, true, func(s *session.ClientSession) (*session.ClientSession, error) {
		reauthCalls++
		return &session.ClientSession{Token: "fresh", Address: s.Address}, nil
	})

	sess := &session.ClientSession{Token: "stale", Address: "http://x"}
	calls := 0
	err := withReauthRetry(sess, sess.Address, func(s *session.ClientSession) error {
		calls++
		return errSessionExpired
	})
	if calls != 2 {
		t.Fatalf("op should run exactly twice (one retry), ran %d times", calls)
	}
	if reauthCalls != 1 {
		t.Fatalf("reauth should run exactly once, ran %d times", reauthCalls)
	}
	if !errors.Is(err, errSessionExpired) {
		t.Fatalf("second 401 should bubble up unchanged, got %v", err)
	}
}

func TestWithReauthRetry_CrossServerSkipsReauth(t *testing.T) {
	withTestStubs(t, true, func(s *session.ClientSession) (*session.ClientSession, error) {
		t.Fatal("reauth should not run when addr differs from sess.Address")
		return nil, nil
	})

	calls := 0
	sess := &session.ClientSession{Token: "tokA", Address: "http://server-a"}
	err := withReauthRetry(sess, "http://server-b", func(s *session.ClientSession) error {
		calls++
		return errSessionExpired
	})
	if calls != 1 {
		t.Fatalf("op should not retry on cross-server 401, ran %d times", calls)
	}
	if !errors.Is(err, errSessionExpired) {
		t.Fatalf("expected errSessionExpired bubbled, got %v", err)
	}
	if sess.Token != "tokA" {
		t.Fatalf("session token should be untouched, got %q", sess.Token)
	}
}

func TestWithReauthRetry_ReauthFailureWraps(t *testing.T) {
	stubErr := errors.New("invalid email or password")
	withTestStubs(t, true, func(s *session.ClientSession) (*session.ClientSession, error) {
		return nil, stubErr
	})

	sess := &session.ClientSession{Token: "stale", Address: "http://x"}
	calls := 0
	err := withReauthRetry(sess, sess.Address, func(s *session.ClientSession) error {
		calls++
		return errSessionExpired
	})
	if calls != 1 {
		t.Fatalf("op should not retry when reauth fails, ran %d times", calls)
	}
	if !errors.Is(err, stubErr) {
		t.Fatalf("expected wrapped reauth error, got %v", err)
	}
}
