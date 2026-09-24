package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

const maxVaultAcquisitionPolicyHandlers = 64

// SetVaultAcquisitionPolicy validates the exact handler IDs and persists the
// policy in one transaction. Handler rows are locked before the settings write
// so a concurrent disable/delete cannot commit between validation and policy
// persistence.
func (s *SQLStore) SetVaultAcquisitionPolicy(ctx context.Context, vaultID string, policy VaultAcquisitionPolicy) error {
	if !acquisitionHandlerVaultPattern.MatchString(vaultID) || len(policy.EnabledHandlers) > maxVaultAcquisitionPolicyHandlers {
		return ErrAcquisitionPolicyHandlerUnavailable
	}
	handlerIDs := append([]string(nil), policy.EnabledHandlers...)
	slices.Sort(handlerIDs)
	for index, id := range handlerIDs {
		if ValidateAcquisitionHandlerID(id) != nil || index > 0 && handlerIDs[index-1] == id {
			return ErrAcquisitionPolicyHandlerUnavailable
		}
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

		query := `SELECT enabled, allowed_vaults_json FROM acquisition_handlers WHERE id = ?`
		if forUpdate != "" {
			query += " " + forUpdate
		}
		var enabledRaw interface{}
		var allowedVaultsJSON string
		if err := tx.QueryRowContext(ctx, s.dialect.Rebind(query), id).Scan(&enabledRaw, &allowedVaultsJSON); err != nil {
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
