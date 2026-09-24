package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

const maxVaultAcquisitionPolicyHandlers = 64

// SetVaultAcquisitionPolicy validates the exact handler IDs and persists the
// policy in one transaction. Handler rows are locked before the settings write
// so a concurrent disable/delete cannot commit between validation and policy
// persistence.
func (s *SQLStore) SetVaultAcquisitionPolicy(ctx context.Context, vaultID string, policy VaultAcquisitionPolicy) error {
	if !acquisitionHandlerVaultPattern.MatchString(vaultID) {
		return ErrAcquisitionPolicyHandlerUnavailable
	}
	if policy.EnabledHandlers == nil {
		policy.EnabledHandlers = []string{}
	}
	handlerIDs, err := validateVaultAcquisitionPolicyHandlerIDs(policy.EnabledHandlers)
	if err != nil {
		return err
	}
	policy.EnabledHandlers = handlerIDs
	raw, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encoding vault acquisition policy: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	forUpdate := s.dialect.ForUpdateClause()
	for _, id := range handlerIDs {
		if forUpdate == "" {
			// SQLite has no SELECT FOR UPDATE. This no-op write obtains the
			// database write lock before validation and holds it until commit.
			result, err := tx.ExecContext(ctx, `UPDATE acquisition_handlers SET updated_at = updated_at WHERE id = ?`, id)
			if err != nil {
				return err
			}
			if affected, err := result.RowsAffected(); err != nil || affected != 1 {
				if err != nil {
					return err
				}
				return ErrAcquisitionPolicyHandlerUnavailable
			}
		}

		query := `SELECT kind, enabled, allowed_vaults_json FROM acquisition_handlers WHERE id = ?`
		if forUpdate != "" {
			query += " " + forUpdate
		}
		var kind string
		var enabledRaw interface{}
		var allowedVaultsJSON string
		if err := tx.QueryRowContext(ctx, s.dialect.Rebind(query), id).Scan(&kind, &enabledRaw, &allowedVaultsJSON); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAcquisitionPolicyHandlerUnavailable
			}
			return err
		}
		enabled, err := s.dialect.ScanBool(enabledRaw)
		if err != nil {
			return err
		}
		var allowedVaults []string
		if kind == AcquisitionHandlerKindBrowserDOM {
			return ErrBrowserDOMAcquisitionUnavailable
		}
		if !enabled || json.Unmarshal([]byte(allowedVaultsJSON), &allowedVaults) != nil || !containsExactString(allowedVaults, vaultID) {
			return ErrAcquisitionPolicyHandlerUnavailable
		}
	}

	nowVal := s.now()
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO vault_settings (vault_id, key, value, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(vault_id, key) DO UPDATE SET value = excluded.value, updated_at = ?`),
		vaultID, VaultSettingCredentialAcquisitionPolicy, string(raw), nowVal, nowVal); err != nil {
		return err
	}
	return tx.Commit()
}

func validateVaultAcquisitionPolicyHandlerIDs(ids []string) ([]string, error) {
	if ids == nil || len(ids) > maxVaultAcquisitionPolicyHandlers {
		return nil, ErrAcquisitionPolicyHandlerUnavailable
	}
	validated := make([]string, len(ids))
	copy(validated, ids)
	slices.Sort(validated)
	for index, id := range validated {
		if ValidateAcquisitionHandlerID(id) != nil || index > 0 && validated[index-1] == id {
			return nil, ErrAcquisitionPolicyHandlerUnavailable
		}
	}
	return validated, nil
}

// ParseVaultAcquisitionPolicyJSON decodes the persisted policy as a closed,
// canonical object. Standard encoding/json struct decoding accepts unknown
// and duplicate fields and coerces null booleans to false, which is too
// permissive for an admission-control policy.
func ParseVaultAcquisitionPolicyJSON(raw string) (VaultAcquisitionPolicy, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return VaultAcquisitionPolicy{}, fmt.Errorf("acquisition policy must be an object")
	}
	var policy VaultAcquisitionPolicy
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return VaultAcquisitionPolicy{}, fmt.Errorf("decoding acquisition policy: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return VaultAcquisitionPolicy{}, fmt.Errorf("acquisition policy key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return VaultAcquisitionPolicy{}, fmt.Errorf("duplicate acquisition policy field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "enabled_handlers":
			var value *[]string
			if err := decoder.Decode(&value); err != nil || value == nil {
				return VaultAcquisitionPolicy{}, fmt.Errorf("enabled_handlers must be an array")
			}
			policy.EnabledHandlers = *value
		case "browser_dom_enabled":
			var value *bool
			if err := decoder.Decode(&value); err != nil || value == nil {
				return VaultAcquisitionPolicy{}, fmt.Errorf("browser_dom_enabled must be a boolean")
			}
			policy.BrowserDOMEnabled = *value
		default:
			return VaultAcquisitionPolicy{}, fmt.Errorf("unknown acquisition policy field %q", key)
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return VaultAcquisitionPolicy{}, fmt.Errorf("acquisition policy object is incomplete")
	}
	if _, ok := seen["enabled_handlers"]; !ok {
		return VaultAcquisitionPolicy{}, fmt.Errorf("enabled_handlers is required")
	}
	if _, ok := seen["browser_dom_enabled"]; !ok {
		return VaultAcquisitionPolicy{}, fmt.Errorf("browser_dom_enabled is required")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return VaultAcquisitionPolicy{}, fmt.Errorf("acquisition policy has trailing data")
	}
	validated, err := validateVaultAcquisitionPolicyHandlerIDs(policy.EnabledHandlers)
	if err != nil {
		return VaultAcquisitionPolicy{}, err
	}
	policy.EnabledHandlers = validated
	return policy, nil
}
