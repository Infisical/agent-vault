package contextbinding

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testProjectID = "9ee48ba0-ff1c-4792-aa10-cb95748ae537"
	testMachineID = "7807737D-53A7-5792-BFCB-AC25AD2441F8"
	testBindingID = "ctx_01JQ6T9J2WR8MVB7F2K4N6P8RA"
)

func validTuple() Tuple {
	return Tuple{
		OriginType:                          OriginCodex,
		OriginCodexThreadID:                 "01a026f1-a339-77c3-bbc1-a0071b64171c",
		OriginCodexSessionID:                "01a026f1-a339-77c3-bbc1-a0071b64171c",
		PerplexityProjectID:                 testProjectID,
		RegisteredPersonalComputerMachineID: testMachineID,
		RuntimeDeviceID:                     "macos:" + testMachineID,
		WorkspaceRoot:                       "/Users/pv/zbst-tech",
	}
}

func TestTupleValidateAcceptsCodexContext(t *testing.T) {
	if err := validTuple().Validate(); err != nil {
		t.Fatalf("expected valid tuple, got %v", err)
	}
}

func TestTupleValidateRejectsMissingOrInvalidFields(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Tuple)
		want string
	}{
		{"origin type", func(v *Tuple) { v.OriginType = "browser" }, "origin_type"},
		{"thread", func(v *Tuple) { v.OriginCodexThreadID = "" }, "origin_codex_thread_id"},
		{"thread shape", func(v *Tuple) { v.OriginCodexThreadID = "thread" }, "origin_codex_thread_id"},
		{"session", func(v *Tuple) { v.OriginCodexSessionID = "" }, "origin_codex_session_id"},
		{"session shape", func(v *Tuple) { v.OriginCodexSessionID = "session" }, "origin_codex_session_id"},
		{"project uuid", func(v *Tuple) { v.PerplexityProjectID = "project" }, "perplexity_project_id"},
		{"raw project uuid", func(v *Tuple) { v.PerplexityProjectID = "9ee48ba0ff1c4792aa10cb95748ae537" }, "perplexity_project_id"},
		{"urn project uuid", func(v *Tuple) { v.PerplexityProjectID = "urn:uuid:9ee48ba0-ff1c-4792-aa10-cb95748ae537" }, "perplexity_project_id"},
		{"brace project uuid", func(v *Tuple) { v.PerplexityProjectID = "{9ee48ba0-ff1c-4792-aa10-cb95748ae537}" }, "perplexity_project_id"},
		{"nil project uuid", func(v *Tuple) { v.PerplexityProjectID = "00000000-0000-0000-0000-000000000000" }, "perplexity_project_id"},
		{"invalid project variant", func(v *Tuple) { v.PerplexityProjectID = "9ee48ba0-ff1c-4792-0a10-cb95748ae537" }, "perplexity_project_id"},
		{"machine uuid", func(v *Tuple) { v.RegisteredPersonalComputerMachineID = "machine" }, "registered_personal_computer_machine_id"},
		{"nil machine uuid", func(v *Tuple) { v.RegisteredPersonalComputerMachineID = "00000000-0000-0000-0000-000000000000" }, "registered_personal_computer_machine_id"},
		{"runtime device", func(v *Tuple) { v.RuntimeDeviceID = "" }, "runtime_device_id"},
		{"relative workspace", func(v *Tuple) { v.WorkspaceRoot = "relative/path" }, "workspace_root"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := validTuple()
			tt.edit(&value)
			err := value.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestTupleValidateAllowsEqualThreadAndSessionIdentifiers(t *testing.T) {
	value := validTuple()
	value.OriginCodexSessionID = value.OriginCodexThreadID
	if err := value.Validate(); err != nil {
		t.Fatalf("thread and session are distinct fields but may carry the same verified identifier: %v", err)
	}
}

func TestMachineMatchesUsesExactRegisteredMachineIDOnly(t *testing.T) {
	tuple := validTuple()
	if !tuple.MachineMatches(testMachineID) {
		t.Fatal("expected exact machine ID to match")
	}

	for _, candidate := range []string{
		"macos:" + testMachineID,
		strings.ToLower(testMachineID),
		strings.ReplaceAll(testMachineID, "-", ""),
		"prefix-" + testMachineID,
		testMachineID + "-suffix",
		tuple.RuntimeDeviceID,
	} {
		if tuple.MachineMatches(candidate) {
			t.Fatalf("non-exact machine ID %q must not authorize", candidate)
		}
	}
}

func TestValidateBindingID(t *testing.T) {
	for _, id := range []string{
		"0123456789abcdefghijklmnop",
		testBindingID,
		strings.Repeat("A", 64),
	} {
		if err := ValidateBindingID(id); err != nil {
			t.Errorf("expected %q to be valid: %v", id, err)
		}
	}

	for _, id := range []string{
		strings.Repeat("a", 25),
		strings.Repeat("a", 65),
		"ctx_01JQ6T9J2WR8MVB7F2K4N6P8R!",
		"ctx 01JQ6T9J2WR8MVB7F2K4N6P8RA",
	} {
		if err := ValidateBindingID(id); err == nil {
			t.Errorf("expected %q to be rejected", id)
		}
	}
}

func TestDecodeReferenceIsStrict(t *testing.T) {
	ref, err := DecodeReference([]byte(`{"context_binding_id":"` + testBindingID + `"}`))
	if err != nil {
		t.Fatalf("decode valid reference: %v", err)
	}
	if ref.ContextBindingID != testBindingID {
		t.Fatalf("unexpected binding ID %q", ref.ContextBindingID)
	}

	for _, raw := range []string{
		`{}`,
		`{"context_binding_id":"` + testBindingID + `","machine_id":"` + testMachineID + `"}`,
		`{"context_binding_id":"` + testBindingID + `","runtime_device_id":"macos:` + testMachineID + `"}`,
		`{"context_binding_id":"` + testBindingID + `","unknown":true}`,
		`{"context_binding_id":"` + testBindingID + `","context_binding_id":"` + strings.Repeat("A", 26) + `"}`,
		`{"Context_Binding_ID":"` + testBindingID + `"}`,
		`{"context_binding_id":"` + testBindingID + `"}{"context_binding_id":"` + testBindingID + `"}`,
	} {
		if _, err := DecodeReference([]byte(raw)); err == nil {
			t.Errorf("expected strict decoder to reject %s", raw)
		}
	}
}

func TestReferenceJSONUnmarshalIsStrict(t *testing.T) {
	var ref Reference
	err := json.Unmarshal([]byte(`{"context_binding_id":"`+testBindingID+`","origin_codex_thread_id":"override"}`), &ref)
	if err == nil {
		t.Fatal("expected tuple-member override to be rejected")
	}
}
