package proposal

import (
	"encoding/json"
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
		{Action: ActionSet, Name: "api-stripe-com", Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
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
	services := []Service{{Action: ActionSet, Name: "svc", Host: "", Auth: bearerAuth("KEY")}}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("expected host required error, got %v", err)
	}
}

func TestValidateMissingAuthForSet(t *testing.T) {
	services := []Service{{Action: ActionSet, Name: "example-com", Host: "example.com"}}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "auth or enabled") {
		t.Fatalf("expected auth-or-enabled required error, got %v", err)
	}
}

func TestValidateEnabledOnlySetValid(t *testing.T) {
	disabled := false
	services := []Service{{Action: ActionSet, Name: "example-com", Host: "example.com", Enabled: &disabled}}
	if err := Validate(services, nil); err != nil {
		t.Fatalf("expected enable-only set to validate, got %v", err)
	}
}

func TestValidateTooManyRules(t *testing.T) {
	services := make([]Service, MaxServices+1)
	for i := range services {
		services[i] = Service{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: bearerAuth("KEY")}
	}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "too many services") {
		t.Fatalf("expected too many services error, got %v", err)
	}
}

func TestValidateUnreferencedCredentialSlot(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "api-stripe-com", Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
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
		{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: customAuth(map[string]string{"X": "{{ K }}"})},
	}
	creds := []CredentialSlot{{Action: ActionSet, Key: "K"}, {Action: ActionSet, Key: "K"}}
	err := Validate(services, creds)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestValidateNoCredentialsAllowed(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: customAuth(map[string]string{"X-Static": "fixed-value"})},
	}
	if err := Validate(services, nil); err != nil {
		t.Fatalf("expected valid with no credentials, got %v", err)
	}
}

func TestValidateInvalidAction(t *testing.T) {
	services := []Service{{Action: "bogus", Name: "example-com", Host: "example.com"}}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid action") {
		t.Fatalf("expected invalid action error, got %v", err)
	}
}

func TestValidateDeleteRuleNoAuth(t *testing.T) {
	services := []Service{
		{Action: ActionDelete, Name: "api-stripe-com", Host: "api.stripe.com"},
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
		{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: customAuth(map[string]string{"X-Static": "fixed"})},
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
			{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: bearerAuth(tt.key)},
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
		{Action: ActionSet, Name: "api-ashby-com", Host: "api.ashby.com", Auth: &broker.Auth{Type: "basic", Username: "ASHBY_KEY"}},
	}
	creds := []CredentialSlot{{Action: ActionSet, Key: "ASHBY_KEY"}}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("expected valid basic auth, got %v", err)
	}
}

func TestValidateApiKeyAuth(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "api-openai-com", Host: "api.openai.com", Auth: &broker.Auth{Type: "api-key", Key: "OPENAI_KEY", Header: "Authorization", Prefix: "Bearer "}},
	}
	creds := []CredentialSlot{{Action: ActionSet, Key: "OPENAI_KEY"}}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("expected valid api-key auth, got %v", err)
	}
}

func TestValidateCredentialAcquisitionModes(t *testing.T) {
	for _, mode := range []AcquisitionMode{
		AcquisitionModeNative,
		AcquisitionModeGuided,
		AcquisitionModeOAuth,
		AcquisitionModeDevice,
		AcquisitionModeServerPassthrough,
	} {
		t.Run(string(mode), func(t *testing.T) {
			creds := []CredentialSlot{{
				Action: ActionSet,
				Key:    "GITHUB_TOKEN",
				Type:   "static",
				Acquisition: &AcquisitionRef{
					Handler: "github-cli",
					Profile: "github.com",
					Mode:    mode,
				},
			}}
			if err := ValidateWithOptions(nil, creds, ValidationOptions{CredentialAcquisitionEnabled: true}); err != nil {
				t.Fatalf("expected mode %q to be valid, got %v", mode, err)
			}
		})
	}
}

func TestValidateCredentialAcquisitionConflicts(t *testing.T) {
	value := "secret"
	oauth := &OAuthConfig{TokenURL: "https://example.com/token"}
	valid := func() CredentialSlot {
		return CredentialSlot{
			Action:      ActionSet,
			Key:         "TOKEN",
			Type:        "static",
			Acquisition: &AcquisitionRef{Handler: "provider", Profile: "default", Mode: AcquisitionModeNative},
		}
	}

	tests := []struct {
		name string
		edit func(*CredentialSlot)
		want string
	}{
		{"delete", func(v *CredentialSlot) { v.Action = ActionDelete }, "delete"},
		{"value", func(v *CredentialSlot) { v.Value = &value }, "value"},
		{"has value", func(v *CredentialSlot) { v.HasValue = true }, "has_value"},
		{"oauth type", func(v *CredentialSlot) { v.Type = "oauth" }, "oauth"},
		{"oauth config", func(v *CredentialSlot) { v.OAuth = oauth }, "oauth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential := valid()
			tt.edit(&credential)
			err := ValidateWithOptions(nil, []CredentialSlot{credential}, ValidationOptions{CredentialAcquisitionEnabled: true})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestValidateCredentialAcquisitionIdentifiers(t *testing.T) {
	tests := []struct {
		name    string
		handler string
		profile string
		want    string
	}{
		{"empty handler", "", "default", "handler"},
		{"invalid handler", "../provider", "default", "handler"},
		{"uppercase handler", "Provider", "default", "handler"},
		{"empty profile", "provider", "", "profile"},
		{"invalid profile", "provider", "default profile", "profile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential := CredentialSlot{
				Action:      ActionSet,
				Key:         "TOKEN",
				Acquisition: &AcquisitionRef{Handler: tt.handler, Profile: tt.profile, Mode: AcquisitionModeNative},
			}
			err := ValidateWithOptions(nil, []CredentialSlot{credential}, ValidationOptions{CredentialAcquisitionEnabled: true})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestValidateCredentialAcquisitionIdentifierBoundaries(t *testing.T) {
	for _, id := range []string{"a", strings.Repeat("a", 64)} {
		credential := CredentialSlot{
			Action:      ActionSet,
			Key:         "TOKEN",
			Acquisition: &AcquisitionRef{Handler: id, Profile: id, Mode: AcquisitionModeNative},
		}
		if err := ValidateWithOptions(nil, []CredentialSlot{credential}, ValidationOptions{CredentialAcquisitionEnabled: true}); err != nil {
			t.Errorf("expected identifier length %d to be accepted: %v", len(id), err)
		}
	}

	for _, id := range []string{strings.Repeat("a", 65), "-provider", ".provider", "_provider"} {
		credential := CredentialSlot{
			Action:      ActionSet,
			Key:         "TOKEN",
			Acquisition: &AcquisitionRef{Handler: id, Profile: "default", Mode: AcquisitionModeNative},
		}
		if err := ValidateWithOptions(nil, []CredentialSlot{credential}, ValidationOptions{CredentialAcquisitionEnabled: true}); err == nil {
			t.Errorf("expected identifier %q to be rejected", id)
		}
	}
}

func TestValidateCredentialAcquisitionRejectsUnsupportedAndBrowserModes(t *testing.T) {
	for _, mode := range []AcquisitionMode{"", "browser", "dom", "browser_dom", "cdp", "native_messaging", "other"} {
		t.Run(string(mode), func(t *testing.T) {
			credential := CredentialSlot{
				Action:      ActionSet,
				Key:         "TOKEN",
				Acquisition: &AcquisitionRef{Handler: "provider", Profile: "default", Mode: mode},
			}
			if err := ValidateWithOptions(nil, []CredentialSlot{credential}, ValidationOptions{CredentialAcquisitionEnabled: true}); err == nil {
				t.Fatalf("expected mode %q to be rejected", mode)
			}
		})
	}
}

func TestAcquisitionRefJSONRejectsUnknownFields(t *testing.T) {
	for _, field := range []string{"executable", "args", "environment", "selector", "dom_selector", "unknown"} {
		raw := `{"action":"set","key":"TOKEN","acquisition":{"handler":"provider","profile":"default","mode":"native","` + field + `":"override"}}`
		var slot CredentialSlot
		if err := json.Unmarshal([]byte(raw), &slot); err == nil {
			t.Errorf("expected acquisition field %q to be rejected", field)
		}
	}
}

func TestAcquisitionRefJSONRejectsDuplicateAndNonCanonicalFields(t *testing.T) {
	for _, raw := range []string{
		`{"action":"set","key":"TOKEN","acquisition":{"handler":"provider","handler":"other","profile":"default","mode":"native"}}`,
		`{"action":"set","key":"TOKEN","acquisition":{"Handler":"provider","profile":"default","mode":"native"}}`,
		`{"action":"set","key":"TOKEN","acquisition":{"handler":"provider","PROFILE":"default","mode":"native"}}`,
	} {
		var slot CredentialSlot
		if err := json.Unmarshal([]byte(raw), &slot); err == nil {
			t.Errorf("expected non-canonical acquisition JSON to be rejected: %s", raw)
		}
	}
}

func TestValidateRejectsAcquisitionWhenFeatureDisabled(t *testing.T) {
	credential := CredentialSlot{
		Action:      ActionSet,
		Key:         "TOKEN",
		Acquisition: &AcquisitionRef{Handler: "provider", Profile: "default", Mode: AcquisitionModeNative},
	}
	if err := Validate(nil, []CredentialSlot{credential}); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-by-default rejection, got %v", err)
	}
}

func TestCredentialAcquisitionFeatureGateDoesNotChangeExistingProposalValidation(t *testing.T) {
	credential := CredentialSlot{Action: ActionSet, Key: "TOKEN", Type: "static"}
	withoutGate := Validate(nil, []CredentialSlot{credential})
	withGate := ValidateWithOptions(nil, []CredentialSlot{credential}, ValidationOptions{CredentialAcquisitionEnabled: true})
	if withoutGate != nil || withGate != nil {
		t.Fatalf("feature gate must not alter non-acquisition proposals: disabled=%v enabled=%v", withoutGate, withGate)
	}
}

func TestCredentialSlotJSONWithoutAcquisitionRemainsCompatible(t *testing.T) {
	var staticSlot CredentialSlot
	if err := json.Unmarshal([]byte(`{"action":"set","key":"TOKEN","type":"static","value":"secret"}`), &staticSlot); err != nil {
		t.Fatalf("decode existing static slot: %v", err)
	}
	if err := Validate(nil, []CredentialSlot{staticSlot}); err != nil {
		t.Fatalf("validate existing static slot: %v", err)
	}

	var oauthSlot CredentialSlot
	if err := json.Unmarshal([]byte(`{"action":"set","key":"TOKEN","type":"oauth","oauth":{"token_url":"https://example.com/token"}}`), &oauthSlot); err != nil {
		t.Fatalf("decode existing oauth slot: %v", err)
	}
	if err := Validate(nil, []CredentialSlot{oauthSlot}); err != nil {
		t.Fatalf("validate existing oauth slot: %v", err)
	}
}

// --- ValidateCredentialRefs tests ---

func TestValidateCredentialRefsAllInSlots(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "api-stripe-com", Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "STRIPE_KEY"}}
	if err := ValidateCredentialRefs(services, slots, nil); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateCredentialRefsAllInExisting(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "api-stripe-com", Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
	}
	if err := ValidateCredentialRefs(services, nil, []string{"STRIPE_KEY"}); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateCredentialRefsMixed(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "api-stripe-com", Host: "api.stripe.com", Auth: bearerAuth("STRIPE_KEY")},
		{Action: ActionSet, Name: "github-com", Host: "*.github.com", Auth: bearerAuth("GITHUB_TOKEN")},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "STRIPE_KEY"}}
	existing := []string{"GITHUB_TOKEN"}
	if err := ValidateCredentialRefs(services, slots, existing); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateCredentialRefsMissing(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "api-stripe-com", Host: "api.stripe.com", Auth: bearerAuth("MISSING_KEY")},
	}
	err := ValidateCredentialRefs(services, nil, []string{"OTHER_KEY"})
	if err == nil || !strings.Contains(err.Error(), "MISSING_KEY") {
		t.Fatalf("expected missing ref error, got %v", err)
	}
}

func TestValidateCredentialRefsCustomNoTemplates(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: customAuth(map[string]string{"X-Static": "fixed-value"})},
	}
	if err := ValidateCredentialRefs(services, nil, nil); err != nil {
		t.Fatalf("expected valid with no templates, got %v", err)
	}
}

func TestValidateCredentialRefsSkipsDeleteRules(t *testing.T) {
	services := []Service{
		{Action: ActionDelete, Name: "api-stripe-com", Host: "api.stripe.com"},
		{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: customAuth(map[string]string{"X": "{{ K }}"})},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "K"}}
	if err := ValidateCredentialRefs(services, slots, nil); err != nil {
		t.Fatalf("expected valid (delete services skipped), got %v", err)
	}
}

func TestValidateCredentialRefsDeleteSlotsNotAvailable(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "example-com", Host: "example.com", Auth: customAuth(map[string]string{"X": "{{ K }}"})},
	}
	slots := []CredentialSlot{{Action: ActionDelete, Key: "K"}}
	err := ValidateCredentialRefs(services, slots, nil)
	if err == nil || !strings.Contains(err.Error(), "\"K\"") {
		t.Fatalf("expected missing ref error for delete slot, got %v", err)
	}
}

func TestValidateCredentialRefsBasicAuth(t *testing.T) {
	services := []Service{
		{Action: ActionSet, Name: "api-ashby-com", Host: "api.ashby.com", Auth: &broker.Auth{Type: "basic", Username: "USER", Password: "PASS"}},
	}
	slots := []CredentialSlot{{Action: ActionSet, Key: "USER"}, {Action: ActionSet, Key: "PASS"}}
	if err := ValidateCredentialRefs(services, slots, nil); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

// --- Substitution proposal tests ---

func TestValidateProposalSubstitutionWithAuth(t *testing.T) {
	services := []Service{{
		Action: ActionSet,
		Name:   "api-twilio-com",
		Host:   "api.twilio.com",
		Auth:   &broker.Auth{Type: "basic", Username: "TWILIO_ACCOUNT_SID", Password: "TWILIO_AUTH_TOKEN"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}}
	creds := []CredentialSlot{
		{Action: ActionSet, Key: "TWILIO_ACCOUNT_SID"},
		{Action: ActionSet, Key: "TWILIO_AUTH_TOKEN"},
	}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateProposalSubstitutionWithoutAuth(t *testing.T) {
	on := true
	services := []Service{{
		Action:  ActionSet,
		Name:    "api-twilio-com",
		Host:    "api.twilio.com",
		Enabled: &on,
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}}
	err := Validate(services, nil)
	if err == nil || !strings.Contains(err.Error(), "substitutions require auth") {
		t.Fatalf("expected error coupling substitutions to auth, got %v", err)
	}
}

func TestValidateProposalSubstitutionInvalidPlaceholder(t *testing.T) {
	services := []Service{{
		Action: ActionSet,
		Name:   "api-twilio-com",
		Host:   "api.twilio.com",
		Auth:   bearerAuth("TWILIO_ACCOUNT_SID"),
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "account_sid", In: []string{"path"}},
		},
	}}
	creds := []CredentialSlot{{Action: ActionSet, Key: "TWILIO_ACCOUNT_SID"}}
	err := Validate(services, creds)
	if err == nil || !strings.Contains(err.Error(), "delimiter") {
		t.Fatalf("expected delimiter error for bare-word placeholder, got %v", err)
	}
}

func TestValidateProposalSubstitutionRequiresCredSlot(t *testing.T) {
	services := []Service{{
		Action: ActionSet,
		Name:   "api-twilio-com",
		Host:   "api.twilio.com",
		Auth:   bearerAuth("TWILIO_AUTH_TOKEN"),
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}}
	creds := []CredentialSlot{{Action: ActionSet, Key: "TWILIO_AUTH_TOKEN"}}
	if err := Validate(services, creds); err != nil {
		t.Fatalf("intra-proposal Validate should accept the slot via the auth ref check; got %v", err)
	}
	if err := ValidateCredentialRefs(services, creds, nil); err == nil || !strings.Contains(err.Error(), "TWILIO_ACCOUNT_SID") {
		t.Fatalf("expected ValidateCredentialRefs to flag missing substitution credential, got %v", err)
	}
}

func TestValidateCredentialRefsSubstitutionResolvesFromExisting(t *testing.T) {
	services := []Service{{
		Action: ActionSet,
		Name:   "api-twilio-com",
		Host:   "api.twilio.com",
		Auth:   bearerAuth("TWILIO_AUTH_TOKEN"),
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}}
	creds := []CredentialSlot{{Action: ActionSet, Key: "TWILIO_AUTH_TOKEN"}}
	if err := ValidateCredentialRefs(services, creds, []string{"TWILIO_ACCOUNT_SID"}); err != nil {
		t.Fatalf("expected substitution credential to resolve from existing vault keys, got %v", err)
	}
}
