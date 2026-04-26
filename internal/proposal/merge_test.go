package proposal

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func mergeBearer(token string) *broker.Auth {
	return &broker.Auth{Type: "bearer", Token: token}
}

func TestMergeServicesSetAppend(t *testing.T) {
	existing := []broker.Service{
		{Host: "api.github.com", Auth: broker.Auth{Type: "bearer", Token: "GH"}},
	}
	proposed := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Description: "Stripe", Auth: mergeBearer("SK")},
	}

	merged, warnings := MergeServices(existing, proposed)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(merged) != 2 {
		t.Fatalf("expected 2 services, got %d", len(merged))
	}
	if merged[1].Host != "api.stripe.com" {
		t.Fatalf("expected appended host api.stripe.com, got %s", merged[1].Host)
	}
	if merged[1].Description == nil || *merged[1].Description != "Stripe" {
		t.Fatalf("expected description 'Stripe'")
	}
}

func TestMergeServicesSetEnabledOnlyPreservesAuth(t *testing.T) {
	disabled := false
	existing := []broker.Service{
		{Host: "api.stripe.com", Auth: broker.Auth{Type: "bearer", Token: "OLD"}},
	}
	proposed := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Enabled: &disabled},
	}

	merged, warnings := MergeServices(existing, proposed)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(merged) != 1 {
		t.Fatalf("expected 1 service, got %d", len(merged))
	}
	if merged[0].Auth.Token != "OLD" {
		t.Fatalf("expected Auth preserved (token OLD), got %q", merged[0].Auth.Token)
	}
	if merged[0].Enabled == nil || *merged[0].Enabled != false {
		t.Fatalf("expected Enabled=false, got %v", merged[0].Enabled)
	}
}

func TestMergeServicesSetReplacesExisting(t *testing.T) {
	existing := []broker.Service{
		{Host: "api.stripe.com", Auth: broker.Auth{Type: "bearer", Token: "OLD"}},
	}
	proposed := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: mergeBearer("NEW")},
	}

	merged, warnings := MergeServices(existing, proposed)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(merged) != 1 {
		t.Fatalf("expected 1 service, got %d", len(merged))
	}
	if merged[0].Auth.Token != "NEW" {
		t.Fatalf("expected replaced service with token NEW, got %s", merged[0].Auth.Token)
	}
}

func TestMergeServicesDelete(t *testing.T) {
	existing := []broker.Service{
		{Host: "api.github.com", Auth: broker.Auth{Type: "bearer", Token: "GH"}},
		{Host: "api.stripe.com", Auth: broker.Auth{Type: "bearer", Token: "SK"}},
	}
	proposed := []Service{
		{Action: ActionDelete, Host: "api.stripe.com"},
	}

	merged, warnings := MergeServices(existing, proposed)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(merged) != 1 {
		t.Fatalf("expected 1 service after delete, got %d", len(merged))
	}
	if merged[0].Host != "api.github.com" {
		t.Fatalf("expected remaining host api.github.com, got %s", merged[0].Host)
	}
}

func TestMergeServicesDeleteNonExistent(t *testing.T) {
	existing := []broker.Service{
		{Host: "api.github.com", Auth: broker.Auth{Type: "bearer", Token: "GH"}},
	}
	proposed := []Service{
		{Action: ActionDelete, Host: "api.stripe.com"},
	}

	merged, warnings := MergeServices(existing, proposed)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if len(merged) != 1 {
		t.Fatalf("expected 1 service unchanged, got %d", len(merged))
	}
}

func TestMergeServicesMixed(t *testing.T) {
	existing := []broker.Service{
		{Host: "api.github.com", Auth: broker.Auth{Type: "bearer", Token: "GH"}},
		{Host: "api.slack.com", Auth: broker.Auth{Type: "bearer", Token: "SLACK"}},
	}
	proposed := []Service{
		{Action: ActionSet, Host: "api.stripe.com", Auth: mergeBearer("SK")},
		{Action: ActionDelete, Host: "api.slack.com"},
		{Action: ActionSet, Host: "api.github.com", Auth: mergeBearer("GH_NEW")},
	}

	merged, warnings := MergeServices(existing, proposed)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(merged) != 2 {
		t.Fatalf("expected 2 services (1 added, 1 updated, 1 deleted), got %d", len(merged))
	}
	if merged[0].Auth.Token != "GH_NEW" {
		t.Fatalf("expected updated github service")
	}
	if merged[1].Host != "api.stripe.com" {
		t.Fatalf("expected stripe appended")
	}
}

func TestMergeServicesEmpty(t *testing.T) {
	merged, warnings := MergeServices(nil, []Service{
		{Action: ActionSet, Host: "example.com", Auth: mergeBearer("KEY")},
	})
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(merged) != 1 {
		t.Fatalf("expected 1 service, got %d", len(merged))
	}
}

func TestMergeServicesNoDescription(t *testing.T) {
	merged, _ := MergeServices(nil, []Service{
		{Action: ActionSet, Host: "example.com", Auth: mergeBearer("KEY")},
	})
	if merged[0].Description != nil {
		t.Fatalf("expected nil description, got %v", merged[0].Description)
	}
}

func TestMergeServicesBasicAuth(t *testing.T) {
	existing := []broker.Service{
		{Host: "api.ashby.com", Auth: broker.Auth{Type: "bearer", Token: "OLD"}},
	}
	proposed := []Service{
		{Action: ActionSet, Host: "api.ashby.com", Auth: &broker.Auth{Type: "basic", Username: "ASHBY_KEY"}},
	}
	merged, _ := MergeServices(existing, proposed)
	if merged[0].Auth.Type != "basic" {
		t.Fatalf("expected basic auth type, got %s", merged[0].Auth.Type)
	}
	if merged[0].Auth.Username != "ASHBY_KEY" {
		t.Fatalf("expected username ASHBY_KEY, got %s", merged[0].Auth.Username)
	}
}

func TestMergeServicesCopiesSubstitutions(t *testing.T) {
	proposed := []Service{{
		Action: ActionSet,
		Host:   "api.twilio.com",
		Auth:   &broker.Auth{Type: "basic", Username: "TWILIO_ACCOUNT_SID", Password: "TWILIO_AUTH_TOKEN"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}}
	merged, _ := MergeServices(nil, proposed)
	if len(merged) != 1 || len(merged[0].Substitutions) != 1 {
		t.Fatalf("expected 1 substitution carried through, got %+v", merged)
	}
	if merged[0].Substitutions[0].Placeholder != "__account_sid__" {
		t.Fatalf("expected placeholder copied, got %+v", merged[0].Substitutions[0])
	}
	// Mutating proposed must not affect merged (defensive copy).
	proposed[0].Substitutions[0].Placeholder = "__mutated__"
	if merged[0].Substitutions[0].Placeholder != "__account_sid__" {
		t.Fatal("merged service substitution aliased the proposal slice")
	}
}

func TestMergeServicesEnableOnlyPreservesSubstitutions(t *testing.T) {
	on := false
	existing := []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "basic", Username: "TWILIO_ACCOUNT_SID", Password: "TWILIO_AUTH_TOKEN"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}}
	proposed := []Service{{Action: ActionSet, Host: "api.twilio.com", Enabled: &on}}
	merged, _ := MergeServices(existing, proposed)
	if len(merged[0].Substitutions) != 1 || merged[0].Substitutions[0].Placeholder != "__account_sid__" {
		t.Fatalf("expected substitutions preserved on enable-only update, got %+v", merged[0])
	}
	if merged[0].Enabled == nil || *merged[0].Enabled != false {
		t.Fatalf("expected enabled overlay applied, got %+v", merged[0].Enabled)
	}
}

func TestMergeServicesAuthOnlyUpdatePreservesSubstitutions(t *testing.T) {
	// Operators rotating credentials shouldn't lose URL rewriting as a
	// side effect.
	existing := []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "basic", Username: "TWILIO_ACCOUNT_SID", Password: "TWILIO_AUTH_TOKEN"},
		Substitutions: []broker.Substitution{
			{Key: "TWILIO_ACCOUNT_SID", Placeholder: "__account_sid__", In: []string{"path"}},
		},
	}}
	proposed := []Service{{
		Action: ActionSet,
		Host:   "api.twilio.com",
		Auth:   &broker.Auth{Type: "bearer", Token: "TWILIO_AUTH_TOKEN"},
	}}
	merged, _ := MergeServices(existing, proposed)
	if merged[0].Auth.Type != "bearer" {
		t.Fatalf("expected auth replaced with bearer, got %+v", merged[0].Auth)
	}
	if len(merged[0].Substitutions) != 1 || merged[0].Substitutions[0].Placeholder != "__account_sid__" {
		t.Fatalf("expected existing substitutions preserved, got %+v", merged[0].Substitutions)
	}
}

func TestMergeServicesAuthAndSubsReplacesSubstitutions(t *testing.T) {
	existing := []broker.Service{{
		Host: "api.twilio.com",
		Auth: broker.Auth{Type: "passthrough"},
		Substitutions: []broker.Substitution{
			{Key: "OLD_KEY", Placeholder: "__old__", In: []string{"path"}},
		},
	}}
	proposed := []Service{{
		Action: ActionSet,
		Host:   "api.twilio.com",
		Auth:   &broker.Auth{Type: "passthrough"},
		Substitutions: []broker.Substitution{
			{Key: "NEW_KEY", Placeholder: "__new__", In: []string{"path"}},
		},
	}}
	merged, _ := MergeServices(existing, proposed)
	if len(merged[0].Substitutions) != 1 || merged[0].Substitutions[0].Placeholder != "__new__" {
		t.Fatalf("expected substitutions replaced, got %+v", merged[0].Substitutions)
	}
}
