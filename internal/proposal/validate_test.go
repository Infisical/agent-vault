package proposal

import (
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func bearerAuth(token string) *broker.Auth {
	return &broker.Auth{Type: "bearer", Token: token}
}

func customAuth(headers map[string]string) *broker.Auth {
	return &broker.Auth{Type: "custom", Headers: headers}
}

func TestValidateValid(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
	}
	creds := []CredentialSlot{
		{Action: ActionSet, Key: "STRIPE_KEY", Description: "Stripe credential key"},
	}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateNoRulesOrCredentials(t *testing.T) {
	err := Validate(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "at least one service or credential") {
		t.Fatalf("expected error, got %v", err)
	}
}

func TestValidateEmptyHost(t *testing.T) {
	services := []Service{{Action: ActionSet, Host: "", Auth: bearerAuth("KEY")}}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("expected host required error, got %v", err)
	}
}

func TestValidateMissingAuthForSet(t *testing.T) {
	services := []Service{{Action: ActionSet, Host: "example.com"}}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "auth or enabled") {
		t.Fatalf("expected auth-or-enabled required error, got %v", err)
	}
}

func TestValidateEnabledOnlySetValid(t *testing.T) {
	disabled := false
	services := []Service{{Action: ActionSet, Host: "example.com", Enabled: &disabled}}
	if err := Validate(services, nil); err != nil {
		t.Fatalf("expected enable-only set to validate, got %v", err)
	}
}

func TestValidateTooManyRules(t *testing.T) {
	services := make([]Service, MaxServices+1)
	for i := range services {
		services[i] = Service{Action: ActionSet, Host: "example.com", Auth: bearerAuth("KEY")}
	}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "too many services") {
		t.Fatalf("expected too many services error, got %v", err)
	}
}

func TestValidateUnreferencedCredentialSlot(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
	}
	creds := []CredentialSlot{
		{Action: ActionSet, Key: "STRIPE_KEY"},
		{Action: ActionSet, Key: "ORPHAN_KEY"},
	}
	err := Validate(services, creds)
	if err == nil || !strings.Contains(err.Error(), "ORPHAN_KEY") {
		t.Fatalf("expected unreferenced error, got %v", err)
	}
}

func TestValidateDuplicateCredentialSlot(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "example.com", Auth: customAuth(map[string]string{"X": "{{ K }}"})},
	}
	creds := []CredentialSlot{{Action: ActionSet, Key: "K"}, {Action: ActionSet, Key: "K"}}
	err := Validate(services, creds)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestValidateNoCredentialsAllowed(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "example.com", Auth: customAuth(map[string]string{"X-Static": "fixed-value"})},
	}
	if err := Validate(services, nil); err != nil {
		t.Fatalf("expected valid with no credentials, got %v", err)
	}
}

func TestValidateInvalidAction(t *testing.T) {
	services := []Service{{Action: "bogus", Host: "example.com"}}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid action") {
		t.Fatalf("expected invalid action error, got %v", err)
	}
}

func TestValidateDeleteRuleNoAuth(t *testing.T) {
	services := []Service{
		{Action: ActionDelete, Host: "api.stripe.com"},
	}
	if err := Validate(services, nil); err != nil {
		t.Fatalf("expected delete service without auth to be valid, got %v", err)
	}
}

func TestValidateDeleteOnlyCredentials(t *testing.T) {
	creds := []CredentialSlot{
		{Action: ActionDelete, Key: "OLD_TOKEN"},
	}
	if err := Validate(nil, creds); err != nil {
		t.Fatalf("expected delete-only credentials proposal to be valid, got %v", err)
	}
}

func TestValidateDeleteCredentialNotReferencedByRule(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "example.com", Auth: customAuth(map[string]string{"X-Static": "fixed"})},
	}
	creds := []CredentialSlot{
		{Action: ActionDelete, Key: "UNUSED_KEY"},
	}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("expected delete credential without service ref to be valid, got %v", err)
	}
}

func TestValidateInvalidCredentialAction(t *testing.T) {
	creds := []CredentialSlot{{Action: "bogus", Key: "K"}}
	err := Validate(nil, creds)
	if err == nil || !strings.Contains(err.Error(), "invalid action") {
		t.Fatalf("expected invalid action error, got %v", err)
	}
}

func TestValidateCredentialKeyFormat(t *testing.T) {
	tests := []struct {
		key     string
		wantErr bool
	}{
		{"STRIPE_KEY", false},
		{"GITHUB_TOKEN", false},
		{"API_KEY_2", false},
		{"K", false},
		{"stripe_key", true},
		{"Stripe_Key", true},
		{"my-key", true},
		{"2KEY", true},
		{"_KEY", true},
		{"KEY WITH SPACE", true},
	}
	for _, tt := range tests {
		services := []Service{
			{Action: ActionSet, Host: "example.com", Auth: bearerAuth(tt.key)},
		}
		creds := []CredentialSlot{{Action: ActionSet, Key: tt.key}}
		err := Validate(services, creds)
		if tt.wantErr && err == nil {
			t.Errorf("key %q: expected error, got nil", tt.key)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("key %q: expected valid, got %v", tt.key, err)
		}
	}
}

func TestValidateDeleteCredentialKeyFormat(t *testing.T) {
	creds := []CredentialSlot{{Action: ActionDelete, Key: "bad_key"}}
	err := Validate(nil, creds)
	if err == nil || !strings.Contains(err.Error(), "UPPER_SNAKE_CASE") {
		t.Fatalf("expected format error for delete credential, got %v", err)
	}
}

func TestValidateBasicAuth(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.ashby.com", Auth: &broker.Auth{Type: "basic", Username: "ASHBY_KEY"}},
	}
	creds := []CredentialSlot{{Action: ActionSet, Key: "ASHBY_KEY"}}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("expected valid basic auth, got %v", err)
	}
}

func TestValidateApiKeyAuth(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.openai.com", Auth: &broker.Auth{Type: "api-key", Key: "OPENAI_KEY", Header: "Authorization", Prefix: "Bearer "}},
	}
	creds := []CredentialSlot{{Action: ActionSet, Key: "OPENAI_KEY"}}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("expected valid api-key auth, got %v", err)
	}
}

// --- ValidateCredentialRefs tests ---

func TestValidateCredentialRefsAllInSlots(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "STRIPE_KEY"}}
	if err := ValidateCredentialRefs(services, slots, nil); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateCredentialRefsAllInExisting(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
	}
	if err := ValidateCredentialRefs(services, nil, []string{"STRIPE_KEY"}); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateCredentialRefsMixed(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
		{Action: ActionSet, Host: "*.github.com", Auth: bearerAuth("GITHUB_TOKEN")},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "STRIPE_KEY"}}
	existing := []string{"GITHUB_TOKEN"}
	if err := ValidateCredentialRefs(services, slots, existing); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateCredentialRefsMissing(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: bearerAuth("MISSING_KEY")},
	}
	err := ValidateCredentialRefs(services, nil, []string{"OTHER_KEY"})
	if err == nil || !strings.Contains(err.Error(), "MISSING_KEY") {
		t.Fatalf("expected missing ref error, got %v", err)
	}
}

func TestValidateCredentialRefsCustomNoTemplates(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "example.com", Auth: customAuth(map[string]string{"X-Static": "fixed-value"})},
	}
	if err := ValidateCredentialRefs(services, nil, nil); err != nil {
		t.Fatalf("expected valid with no templates, got %v", err)
	}
}

func TestValidateCredentialRefsSkipsDeleteRules(t *testing.T) {
	services := []Service{
		{Action: ActionDelete, Host: "api.stripe.com"},
		{Action: ActionSet, Host: "example.com", Auth: customAuth(map[string]string{"X": "{{ K }}"})},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "K"}}
	if err := ValidateCredentialRefs(services, slots, nil); err != nil {
		t.Fatalf("expected valid (delete services skipped), got %v", err)
	}
}

func TestValidateCredentialRefsDeleteSlotsNotAvailable(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "example.com", Auth: customAuth(map[string]string{"X": "{{ K }}"})},
	}
	slots := []CredentialSlot{{Action: ActionDelete, Key: "K"}}
	err := ValidateCredentialRefs(services, slots, nil)
	if err == nil || !strings.Contains(err.Error(), "\"K\"") {
		t.Fatalf("expected missing ref error for delete slot, got %v", err)
	}
}

func TestValidateCredentialRefsBasicAuth(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Host: "api.ashby.com", Auth: &broker.Auth{Type: "basic", Username: "USER", Password: "PASS"}},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "USER"}, {Action: ActionSet, Key: "PASS"}}
	if err := ValidateCredentialRefs(services, slots, nil); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}
