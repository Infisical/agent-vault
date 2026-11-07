package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// These exercise the real SQL paths rather than a mock, so the migration, the
// writer-oriented update semantics, and the reference scan across broker
// configs are all checked against the database they run on.

func insertProxy(t *testing.T, s *SQLStore, p *UpstreamProxy) *UpstreamProxy {
	t.Helper()
	if err := s.CreateUpstreamProxy(context.Background(), p); err != nil {
		t.Fatalf("CreateUpstreamProxy: %v", err)
	}
	return p
}

func TestUpstreamProxyMigrationCreatesTable(t *testing.T) {
	s := openTestDB(t)

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM upstream_proxies").Scan(&count); err != nil {
		t.Fatalf("upstream_proxies table missing after migration: %v", err)
	}

	// SQLite stores booleans as integers; the migration must pick the right
	// type for each dialect or every IsDefault read silently returns false.
	_, err := s.db.Exec(`INSERT INTO upstream_proxies
		(id, name, scheme, host, on_failure, is_default, enabled, created_at, updated_at)
		VALUES ('p1', 'p', 'http', 'proxy:3128', 'fail_closed', 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatalf("inserting an upstream_proxy row: %v", err)
	}
	_, err = s.db.Exec(`INSERT INTO upstream_proxies
		(id, name, scheme, host, on_failure, is_default, enabled, created_at, updated_at)
		VALUES ('p2', 'p2', 'http', 'proxy:3128', 'fail_closed', 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if err == nil {
		t.Fatal("partial unique index must reject a second default")
	}
}

func TestUpstreamProxyCRUDAgainstSQLite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{
		Name: "corp", Scheme: "http", Host: "proxy.internal:3128",
		NoProxy: "example.com", ProxyCAPEM: "-----BEGIN CERTIFICATE-----",
		OnFailure: "fail_closed", IsDefault: true, Enabled: true,
		UsernameCT: []byte("u"), UsernameNonce: []byte("un"),
		PasswordCT: []byte("p"), PasswordNonce: []byte("pn"),
	})

	listed, err := s.ListUpstreamProxies(ctx)
	if err != nil {
		t.Fatalf("ListUpstreamProxies: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d proxies, want 1", len(listed))
	}
	if listed[0].PasswordCT == nil {
		t.Fatal("ciphertext columns must round-trip as blobs")
	}

	byName, err := s.GetUpstreamProxyByName(ctx, "corp")
	if err != nil {
		t.Fatalf("GetUpstreamProxyByName: %v", err)
	}
	if byName.Host != "proxy.internal:3128" || byName.OnFailure != "fail_closed" || !byName.IsDefault {
		t.Fatalf("stored proxy = %+v, want the inserted values", byName)
	}

	def, err := s.GetDefaultUpstreamProxy(ctx)
	if err != nil {
		t.Fatalf("GetDefaultUpstreamProxy: %v", err)
	}
	if def.Name != "corp" {
		t.Fatalf("default = %q, want corp", def.Name)
	}

	if _, err := s.GetUpstreamProxyByName(ctx, "absent"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUpstreamProxyByName(absent) = %v, want sql.ErrNoRows", err)
	}
}

func TestUpstreamProxyDuplicateCreateIsRejected(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{Name: "corp", Scheme: "http", Host: "a:3128", OnFailure: "fail_closed", Enabled: true})
	err := s.CreateUpstreamProxy(ctx, &UpstreamProxy{Name: "corp", Scheme: "http", Host: "b:3128", OnFailure: "fail_closed", Enabled: true})
	if err == nil {
		t.Fatal("duplicate names must be rejected by the unique index")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Fatalf("error = %v, want a UNIQUE violation", err)
	}
}

func TestUpstreamProxyDefaultIsExclusiveInSQLite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{Name: "first", Scheme: "http", Host: "a:3128", OnFailure: "fail_closed", IsDefault: true, Enabled: true})
	insertProxy(t, s, &UpstreamProxy{Name: "second", Scheme: "http", Host: "b:3128", OnFailure: "fail_closed", IsDefault: true, Enabled: true})

	first, err := s.GetUpstreamProxyByName(ctx, "first")
	if err != nil {
		t.Fatalf("GetUpstreamProxyByName: %v", err)
	}
	if first.IsDefault {
		t.Fatal("promoting 'second' must demote 'first'; is_default is a single-valued pointer")
	}

	promote := true
	updated, err := s.UpdateUpstreamProxy(ctx, UpdateUpstreamProxyParams{Name: "first", IsDefault: &promote})
	if err != nil {
		t.Fatalf("UpdateUpstreamProxy: %v", err)
	}
	if !updated.IsDefault {
		t.Fatal("explicit promotion must take effect")
	}
	demoted, err := s.GetUpstreamProxyByName(ctx, "second")
	if err != nil {
		t.Fatalf("GetUpstreamProxyByName: %v", err)
	}
	if demoted.IsDefault {
		t.Fatal("previous default must be cleared on promotion")
	}
}

func TestUpstreamProxyPatchSemantics(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{
		Name: "corp", Scheme: "http", Host: "a:3128",
		NoProxy: "example.com", OnFailure: "fail_closed", Enabled: true,
		UsernameCT: []byte("u"), UsernameNonce: []byte("un"),
	})

	host := "renamed.internal:3129"
	noProxy := ""
	updated, err := s.UpdateUpstreamProxy(ctx, UpdateUpstreamProxyParams{Name: "corp", Host: &host, NoProxy: &noProxy})
	if err != nil {
		t.Fatalf("UpdateUpstreamProxy: %v", err)
	}
	if updated.Host != host {
		t.Fatalf("host = %q, want %q", updated.Host, host)
	}
	if updated.NoProxy != "" {
		t.Fatalf("no_proxy = %q, want an explicit non-nil pointer to clear it", updated.NoProxy)
	}
	// Untouched columns must survive a partial patch.
	if len(updated.UsernameCT) == 0 {
		t.Fatal("partial patch must not clear credentials it did not mention")
	}
	if updated.OnFailure != "fail_closed" {
		t.Fatalf("on_failure = %q, want unchanged", updated.OnFailure)
	}

	if _, err := s.UpdateUpstreamProxy(ctx, UpdateUpstreamProxyParams{Name: "absent", Host: &host}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("UpdateUpstreamProxy(absent) = %v, want sql.ErrNoRows", err)
	}
}

func TestUpstreamProxyDeleteRefusesWhenReferenced(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{Name: "corp", Scheme: "http", Host: "a:3128", OnFailure: "fail_closed", Enabled: true})

	refs, err := s.CountUpstreamProxyReferences(ctx, "corp")
	if err != nil {
		t.Fatalf("CountUpstreamProxyReferences: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("references = %v, want none for an unused profile", refs)
	}

	vault, err := s.CreateVault(ctx, "demo")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	services := `[{"name":"anthropic","host":"api.anthropic.com","auth":{"type":"bearer","token":"t"},"upstream_proxy":"corp"},` +
		`{"name":"openai","host":"api.openai.com","auth":{"type":"bearer","token":"t"}}]`
	if _, err := s.SetBrokerConfig(ctx, vault.ID, services); err != nil {
		t.Fatalf("seeding broker config: %v", err)
	}

	refs, err = s.CountUpstreamProxyReferences(ctx, "corp")
	if err != nil {
		t.Fatalf("CountUpstreamProxyReferences: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("references = %v, want exactly the anthropic service", refs)
	}
	// References are reported as vault name / service name — the form an
	// operator recognises from the UI, not raw IDs.
	if refs[0] != "demo/anthropic" {
		t.Fatalf("reference = %q, want demo/anthropic", refs[0])
	}

	if err := s.DeleteUpstreamProxy(ctx, "absent"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DeleteUpstreamProxy(absent) = %v, want sql.ErrNoRows", err)
	}
	var referenced *UpstreamProxyReferencedError
	if err := s.DeleteUpstreamProxy(ctx, "corp"); !errors.As(err, &referenced) {
		t.Fatalf("DeleteUpstreamProxy(referenced) = %v, want conflict", err)
	}
	if _, err := s.GetUpstreamProxyByName(ctx, "corp"); err != nil {
		t.Fatalf("referenced proxy unexpectedly removed: %v", err)
	}
	if _, err := s.SetBrokerConfig(ctx, vault.ID, "[]"); err != nil {
		t.Fatalf("clearing reference: %v", err)
	}
	if err := s.DeleteUpstreamProxy(ctx, "corp"); err != nil {
		t.Fatalf("DeleteUpstreamProxy: %v", err)
	}
	if _, err := s.GetUpstreamProxyByName(ctx, "corp"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("proxy survived deletion: %v", err)
	}
}

func TestUpstreamProxyReferencesUseExactNameMatchSQLite(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	insertProxy(t, s, &UpstreamProxy{Name: "Corp", Scheme: "http", Host: "corp:3128", OnFailure: "fail_closed", Enabled: true})
	insertProxy(t, s, &UpstreamProxy{Name: "corp", Scheme: "http", Host: "lower:3128", OnFailure: "fail_closed", Enabled: true})

	vault, err := s.CreateVault(ctx, "case-sensitive-reference")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if _, err := s.SetBrokerConfig(ctx, vault.ID, `[{"name":"service","host":"example.com","upstream_proxy":"Corp"}]`); err != nil {
		t.Fatalf("seeding broker config: %v", err)
	}

	refs, err := s.CountUpstreamProxyReferences(ctx, "corp")
	if err != nil {
		t.Fatalf("CountUpstreamProxyReferences(corp): %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("references for corp = %v, want none", refs)
	}
	refs, err = s.CountUpstreamProxyReferences(ctx, "Corp")
	if err != nil {
		t.Fatalf("CountUpstreamProxyReferences(Corp): %v", err)
	}
	if len(refs) != 1 || refs[0] != "case-sensitive-reference/service" {
		t.Fatalf("references for Corp = %v, want case-sensitive-reference/service", refs)
	}

	if err := s.DeleteUpstreamProxy(ctx, "corp"); err != nil {
		t.Fatalf("DeleteUpstreamProxy(corp): %v", err)
	}
	if _, err := s.GetUpstreamProxyByName(ctx, "corp"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("lowercase profile survived deletion: %v", err)
	}
	if p, err := s.GetUpstreamProxyByName(ctx, "Corp"); err != nil || p.Name != "Corp" {
		t.Fatalf("referenced Corp profile lookup = (%v, %v), want retained Corp", p, err)
	}

	var referenced *UpstreamProxyReferencedError
	if err := s.DeleteUpstreamProxy(ctx, "Corp"); !errors.As(err, &referenced) {
		t.Fatalf("DeleteUpstreamProxy(Corp) = %v, want referenced conflict", err)
	}
	if p, err := s.GetUpstreamProxyByName(ctx, "Corp"); err != nil || p.Name != "Corp" {
		t.Fatalf("referenced Corp profile was not retained: (%v, %v)", p, err)
	}
}

func TestUpstreamProxyMalformedServicesBlockDelete(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	insertProxy(t, s, &UpstreamProxy{Name: "bad-json", Scheme: "http", Host: "proxy:3128", Enabled: true})
	vault, err := s.CreateVault(ctx, "bad-json-vault")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE broker_configs SET services_json = ? WHERE vault_id = ?`, `not-json`, vault.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUpstreamProxy(ctx, "bad-json"); err == nil {
		t.Fatal("malformed services JSON must block deletion")
	}
	if _, err := s.GetUpstreamProxyByName(ctx, "bad-json"); err != nil {
		t.Fatalf("proxy deleted despite malformed reference data: %v", err)
	}
}

func TestBrokerConfigAndProposalRejectUnknownUpstreamProxy(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, err := s.CreateVault(ctx, "unknown-proxy")
	if err != nil {
		t.Fatal(err)
	}
	services := `[{"name":"svc","host":"example.com","upstream_proxy":"missing"}]`
	_, err = s.SetBrokerConfig(ctx, vault.ID, services)
	var unknown *UnknownUpstreamProxyError
	if !errors.As(err, &unknown) || unknown.Name != "missing" {
		t.Fatalf("SetBrokerConfig error = %v, want unknown profile missing", err)
	}
	proposal, err := s.CreateProposal(ctx, vault.ID, "session", "[]", "{}", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.ApplyProposal(ctx, vault.ID, proposal.ID, services, nil, nil, nil)
	unknown = nil
	if !errors.As(err, &unknown) || unknown.Name != "missing" {
		t.Fatalf("ApplyProposal error = %v, want unknown profile missing", err)
	}
}

func TestUpstreamProxyConcurrentInvariantsSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invariants.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	assertConcurrentProxyInvariants(t, first, second)
}

func TestUpstreamProxyPostgresInvariants(t *testing.T) {
	rawURL := os.Getenv("AGENT_VAULT_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set AGENT_VAULT_TEST_POSTGRES_URL to an isolated local fixture database")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1") || strings.TrimPrefix(parsed.Path, "/") != "agent_vault_review" {
		t.Fatal("PostgreSQL fixture URL must target localhost database agent_vault_review")
	}
	admin, err := sql.Open("pgx", rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("proxy_invariants_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	parsed.RawQuery = strings.Trim(parsed.RawQuery+"&search_path="+schema, "&")
	fixtureURL := parsed.String()
	first, err := openPostgres(fixtureURL)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openPostgres(fixtureURL)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	assertConcurrentProxyInvariants(t, first, second)
}

func assertConcurrentProxyInvariants(t *testing.T, first, second *SQLStore) {
	t.Helper()
	ctx := context.Background()
	for _, name := range []string{"promote-a", "promote-b"} {
		if err := first.CreateUpstreamProxy(ctx, &UpstreamProxy{Name: name, Scheme: "http", Host: "proxy:3128", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	for i, name := range []string{"promote-a", "promote-b"} {
		go func(i int, name string) {
			defer wg.Done()
			<-start
			promote := true
			writer := first
			if i == 1 {
				writer = second
			}
			_, errs[i] = writer.UpdateUpstreamProxy(ctx, UpdateUpstreamProxyParams{Name: name, IsDefault: &promote})
		}(i, name)
	}
	close(start)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent default promotion: %v", err)
		}
	}
	var defaults int
	if err := first.db.QueryRow(`SELECT COUNT(*) FROM upstream_proxies WHERE is_default = TRUE`).Scan(&defaults); err != nil {
		t.Fatal(err)
	}
	if defaults != 1 {
		t.Fatalf("concurrent promotions left %d defaults, want exactly one", defaults)
	}

	defaultProxy, err := first.GetDefaultUpstreamProxy(ctx)
	if err != nil {
		t.Fatalf("resolving the default after concurrent promotion: %v", err)
	}
	if defaultProxy == nil || (defaultProxy.Name != "promote-a" && defaultProxy.Name != "promote-b") {
		t.Fatalf("default profile = %+v, want one of the promoted profiles", defaultProxy)
	}

	if err := first.CreateUpstreamProxy(ctx, &UpstreamProxy{Name: "race-reference", Scheme: "http", Host: "proxy:3128", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	vault, err := first.CreateVault(ctx, "race-reference-vault")
	if err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	wg = sync.WaitGroup{}
	var writeErr, deleteErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, writeErr = first.SetBrokerConfig(ctx, vault.ID, `[{"name":"svc","host":"example.com","upstream_proxy":"race-reference"}]`)
	}()
	go func() {
		defer wg.Done()
		<-start
		deleteErr = second.DeleteUpstreamProxy(ctx, "race-reference")
	}()
	close(start)
	wg.Wait()
	config, configErr := first.GetBrokerConfig(ctx, vault.ID)
	_, proxyErr := first.GetUpstreamProxyByName(ctx, "race-reference")
	hasRef := configErr == nil && strings.Contains(config.ServicesJSON, `"upstream_proxy":"race-reference"`)
	if hasRef && proxyErr != nil {
		t.Fatalf("race left dangling reference: write=%v delete=%v", writeErr, deleteErr)
	}
	if writeErr == nil {
		var referenced *UpstreamProxyReferencedError
		if !errors.As(deleteErr, &referenced) {
			t.Fatalf("successful write must make delete conflict, got %v", deleteErr)
		}
	} else {
		var unknown *UnknownUpstreamProxyError
		if !errors.As(writeErr, &unknown) || deleteErr != nil || proxyErr == nil {
			t.Fatalf("delete-winning race = write %v, delete %v, profile err %v", writeErr, deleteErr, proxyErr)
		}
	}
	if err := first.CreateUpstreamProxy(ctx, &UpstreamProxy{Name: "proposal-reference", Scheme: "http", Host: "proxy:3128", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	proposal, err := first.CreateProposal(ctx, vault.ID, "session", "[]", "{}", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.SetBrokerConfig(ctx, vault.ID, "[]"); err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	wg = sync.WaitGroup{}
	var applyErr, proposalDeleteErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		applyErr = first.ApplyProposal(ctx, vault.ID, proposal.ID,
			`[{"name":"svc","host":"example.com","upstream_proxy":"proposal-reference"}]`,
			nil, nil, nil)
	}()
	go func() {
		defer wg.Done()
		<-start
		proposalDeleteErr = second.DeleteUpstreamProxy(ctx, "proposal-reference")
	}()
	close(start)
	wg.Wait()
	config, configErr = first.GetBrokerConfig(ctx, vault.ID)
	_, proxyErr = first.GetUpstreamProxyByName(ctx, "proposal-reference")
	hasRef = configErr == nil && strings.Contains(config.ServicesJSON, `"upstream_proxy":"proposal-reference"`)
	if hasRef && proxyErr != nil {
		t.Fatalf("proposal race left dangling reference: apply=%v delete=%v", applyErr, proposalDeleteErr)
	}
	if applyErr == nil {
		var referenced *UpstreamProxyReferencedError
		if !errors.As(proposalDeleteErr, &referenced) {
			t.Fatalf("successful proposal apply must make delete conflict, got %v", proposalDeleteErr)
		}
	} else {
		var unknown *UnknownUpstreamProxyError
		if !errors.As(applyErr, &unknown) || proposalDeleteErr != nil || proxyErr == nil {
			t.Fatalf("delete-winning proposal race = apply %v, delete %v, profile err %v", applyErr, proposalDeleteErr, proxyErr)
		}
	}
}
