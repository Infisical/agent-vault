package contextbinding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const OriginCodex = "codex"

var bindingIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{26,64}$`)

// Tuple is the immutable context represented by a context binding.
// RegisteredPersonalComputerMachineID is the registered Perplexity Personal
// Computer machine ID. RuntimeDeviceID is diagnostic metadata only and must
// never be used for authorization.
type Tuple struct {
	OriginType                          string `json:"origin_type"`
	OriginCodexThreadID                 string `json:"origin_codex_thread_id"`
	OriginCodexSessionID                string `json:"origin_codex_session_id"`
	PerplexityProjectID                 string `json:"perplexity_project_id"`
	RegisteredPersonalComputerMachineID string `json:"registered_personal_computer_machine_id"`
	RuntimeDeviceID                     string `json:"runtime_device_id"`
	WorkspaceRoot                       string `json:"workspace_root,omitempty"`
}

// Validate checks the platform-neutral shape of a context tuple. It does not
// authenticate any member or prove that the workstation owns MachineID.
func (t Tuple) Validate() error {
	if t.OriginType != OriginCodex {
		return fmt.Errorf("origin_type must be %q", OriginCodex)
	}
	if !validRFCUUID(t.OriginCodexThreadID) {
		return fmt.Errorf("origin_codex_thread_id must be a UUID")
	}
	if !validRFCUUID(t.OriginCodexSessionID) {
		return fmt.Errorf("origin_codex_session_id must be a UUID")
	}
	if !validRFCUUID(t.PerplexityProjectID) {
		return fmt.Errorf("perplexity_project_id must be a UUID")
	}
	if !validRFCUUID(t.RegisteredPersonalComputerMachineID) {
		return fmt.Errorf("registered_personal_computer_machine_id must be the exact registered UUID")
	}
	if t.RuntimeDeviceID == "" {
		return fmt.Errorf("runtime_device_id is required for diagnostics")
	}
	if t.WorkspaceRoot != "" && !filepath.IsAbs(t.WorkspaceRoot) {
		return fmt.Errorf("workspace_root must be absolute when provided")
	}
	return nil
}

// MachineMatches returns true only for byte-for-byte equality with the
// registered machine ID. It intentionally performs no case folding, prefix
// stripping, UUID reformatting, substring matching, or runtime-device lookup.
func (t Tuple) MachineMatches(candidate string) bool {
	return candidate == t.RegisteredPersonalComputerMachineID
}

// ValidateBindingID validates an opaque context binding identifier without
// interpreting or normalizing it.
func ValidateBindingID(id string) error {
	if !bindingIDPattern.MatchString(id) {
		return fmt.Errorf("context_binding_id must contain 26..64 URL-safe characters")
	}
	return nil
}

// Reference is the only context-binding shape accepted from callers. Tuple
// members are server-owned and cannot be overridden through this reference.
type Reference struct {
	ContextBindingID string `json:"context_binding_id"`
}

// UnmarshalJSON rejects tuple-member overrides and every other unknown field.
func (r *Reference) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode context binding reference: %w", err)
	}
	if opening != json.Delim('{') {
		return fmt.Errorf("decode context binding reference: expected JSON object")
	}

	var decoded Reference
	seen := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode context binding reference: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("decode context binding reference: expected object key")
		}
		if key != "context_binding_id" {
			return fmt.Errorf("decode context binding reference: unknown field %q", key)
		}
		if seen {
			return fmt.Errorf("decode context binding reference: duplicate field %q", key)
		}
		seen = true
		if err := decoder.Decode(&decoded.ContextBindingID); err != nil {
			return fmt.Errorf("decode context binding reference field %q: %w", key, err)
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode context binding reference: %w", err)
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("decode context binding reference: expected end of JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode context binding reference: unexpected trailing JSON value")
		}
		return fmt.Errorf("decode context binding reference: %w", err)
	}
	if err := ValidateBindingID(decoded.ContextBindingID); err != nil {
		return err
	}
	*r = decoded
	return nil
}

// DecodeReference decodes exactly one strict context-binding reference.
func DecodeReference(data []byte) (Reference, error) {
	var ref Reference
	if err := json.Unmarshal(data, &ref); err != nil {
		return Reference{}, err
	}
	return ref, nil
}

func validRFCUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil &&
		strings.EqualFold(parsed.String(), value) &&
		parsed != uuid.Nil &&
		parsed.Variant() == uuid.RFC4122
}
