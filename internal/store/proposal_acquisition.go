package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Infisical/agent-vault/internal/proposal"
	"github.com/google/uuid"
)

const proposalAcquisitionColumns = `id, vault_id, proposal_id, credential_key, attempt,
	handler_id, handler_generation, profile, mode, state, context_binding_id,
	source, error_code, credential_expires_at, continuation_ticket_hash,
	continuation_expires_at, continuation_used_at, started_at, completed_at,
	created_at, updated_at`

const continuationTicketTTL = 5 * time.Minute

type acquisitionScanner interface {
	Scan(dest ...interface{}) error
}

func (s *SQLStore) scanProposalAcquisition(scan acquisitionScanner) (*ProposalAcquisition, error) {
	var job ProposalAcquisition
	var credentialExpiresAt, continuationExpiresAt, continuationUsedAt interface{}
	var startedAt, completedAt, createdAt, updatedAt interface{}
	if err := scan.Scan(
		&job.ID, &job.VaultID, &job.ProposalID, &job.CredentialKey, &job.Attempt,
		&job.HandlerID, &job.HandlerGeneration, &job.Profile, &job.Mode, &job.State, &job.ContextBindingID,
		&job.Source, &job.ErrorCode, &credentialExpiresAt, &job.ContinuationTicketHash,
		&continuationExpiresAt, &continuationUsedAt, &startedAt, &completedAt,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	var err error
	if job.CredentialExpiresAt, err = s.dialect.ScanNullableTime(credentialExpiresAt); err != nil {
		return nil, err
	}
	if job.ContinuationExpiresAt, err = s.dialect.ScanNullableTime(continuationExpiresAt); err != nil {
		return nil, err
	}
	if job.ContinuationUsedAt, err = s.dialect.ScanNullableTime(continuationUsedAt); err != nil {
		return nil, err
	}
	if job.StartedAt, err = s.dialect.ScanNullableTime(startedAt); err != nil {
		return nil, err
	}
	if job.CompletedAt, err = s.dialect.ScanNullableTime(completedAt); err != nil {
		return nil, err
	}
	if job.CreatedAt, err = s.dialect.ScanTime(createdAt); err != nil {
		return nil, err
	}
	if job.UpdatedAt, err = s.dialect.ScanTime(updatedAt); err != nil {
		return nil, err
	}
	job.ContinuationTicketHash = append([]byte(nil), job.ContinuationTicketHash...)
	return &job, nil
}

func validateProposalAcquisitionStart(start ProposalAcquisitionStart) error {
	if !acquisitionHandlerVaultPattern.MatchString(start.VaultID) || start.ProposalID <= 0 {
		return fmt.Errorf("invalid proposal acquisition target")
	}
	if !acquisitionHandlerKeyPattern.MatchString(start.CredentialKey) {
		return fmt.Errorf("invalid proposal acquisition credential key")
	}
	if err := ValidateAcquisitionHandlerID(start.HandlerID); err != nil {
		return err
	}
	if !acquisitionHandlerProfilePattern.MatchString(start.Profile) {
		return fmt.Errorf("invalid proposal acquisition profile")
	}
	switch start.Mode {
	case "native", "guided", "oauth", "device", "server_passthrough":
		return nil
	default:
		return fmt.Errorf("invalid proposal acquisition mode")
	}
}

// StartProposalAcquisition creates a queued attempt after resolving the exact
// active proposal binding and current enabled handler generation in one
// transaction. The partial unique index is the final concurrent-start guard.
func (s *SQLStore) StartProposalAcquisition(ctx context.Context, start ProposalAcquisitionStart) (*ProposalAcquisition, error) {
	if err := validateProposalAcquisitionStart(start); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	forUpdate := s.dialect.ForUpdateClause()
	if forUpdate != "" {
		forUpdate = " " + forUpdate
	}
	if err := s.requireCredentialAcquisitionEnabled(ctx, tx, forUpdate); err != nil {
		return nil, err
	}
	var proposalStatus, credentialsJSON string
	var contextBindingID sql.NullString
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT status, context_binding_id, credentials_json
		FROM proposals WHERE vault_id = ? AND id = ?`+forUpdate), start.VaultID, start.ProposalID).
		Scan(&proposalStatus, &contextBindingID, &credentialsJSON); err != nil {
		return nil, err
	}
	if proposalStatus != "pending" {
		return nil, ErrProposalStateConflict
	}
	if !contextBindingID.Valid || contextBindingID.String == "" {
		return nil, ErrProposalAcquisitionContextBindingRequired
	}
	if !proposalAcquisitionDeclarationMatches(credentialsJSON, start) {
		return nil, ErrProposalAcquisitionDeclarationMismatch
	}
	if err := s.lockActiveContextBinding(ctx, tx, contextBindingID.String); err != nil {
		return nil, err
	}

	var generation, handlerKind, allowedKeysJSON, allowedVaultsJSON, allowedProfilesJSON string
	var enabledRaw interface{}
	if forUpdate == "" {
		// SQLite has no SELECT FOR UPDATE. Acquire its write lock before
		// resolving the handler and policy so a concurrent policy update or
		// handler disable cannot interleave with admission.
		result, err := tx.ExecContext(ctx, `UPDATE acquisition_handlers SET updated_at = updated_at WHERE id = ?`, start.HandlerID)
		if err != nil {
			return nil, err
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			if err != nil {
				return nil, err
			}
			return nil, ErrAcquisitionHandlerUnavailable
		}
	}
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT generation, kind, allowed_keys_json,
		allowed_vaults_json, allowed_profiles_json, enabled FROM acquisition_handlers WHERE id = ?`+forUpdate), start.HandlerID).
		Scan(&generation, &handlerKind, &allowedKeysJSON, &allowedVaultsJSON, &allowedProfilesJSON, &enabledRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAcquisitionHandlerUnavailable
		}
		return nil, err
	}
	enabled, err := s.dialect.ScanBool(enabledRaw)
	if err != nil {
		return nil, err
	}
	var allowedKeys, allowedVaults, allowedProfiles []string
	if json.Unmarshal([]byte(allowedKeysJSON), &allowedKeys) != nil ||
		json.Unmarshal([]byte(allowedVaultsJSON), &allowedVaults) != nil ||
		json.Unmarshal([]byte(allowedProfilesJSON), &allowedProfiles) != nil ||
		!enabled || !containsExactString(allowedKeys, start.CredentialKey) ||
		!containsExactString(allowedVaults, start.VaultID) ||
		!containsExactString(allowedProfiles, start.Profile) {
		return nil, ErrAcquisitionHandlerUnavailable
	}
	// Browser DOM capture remains fail-closed until a provider path enforces
	// signed recipes, origin/path restrictions, and capture suppression. The
	// stored vault opt-in is intentionally not sufficient to execute it.
	if handlerKind == AcquisitionHandlerKindBrowserDOM {
		return nil, ErrBrowserDOMAcquisitionUnavailable
	}
	if err := s.requireVaultAcquisitionPolicyHandler(ctx, tx, start.VaultID, start.HandlerID, forUpdate); err != nil {
		return nil, err
	}

	var attempt int
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COALESCE(MAX(attempt), 0) + 1
		FROM proposal_acquisitions WHERE vault_id = ? AND proposal_id = ? AND credential_key = ?`),
		start.VaultID, start.ProposalID, start.CredentialKey).Scan(&attempt); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	job := &ProposalAcquisition{
		ID: uuid.NewString(), VaultID: start.VaultID, ProposalID: start.ProposalID,
		CredentialKey: start.CredentialKey, Attempt: attempt, HandlerID: start.HandlerID,
		HandlerGeneration: generation, Profile: start.Profile, Mode: start.Mode,
		State: AcquisitionQueued, ContextBindingID: contextBindingID.String,
		CreatedAt: now, UpdatedAt: now,
	}
	result, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO proposal_acquisitions
		(id, vault_id, proposal_id, credential_key, attempt, handler_id, handler_generation,
		 profile, mode, state, context_binding_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`),
		job.ID, job.VaultID, job.ProposalID, job.CredentialKey, job.Attempt, job.HandlerID,
		job.HandlerGeneration, job.Profile, job.Mode, job.State, job.ContextBindingID,
		s.dialect.FormatTime(now), s.dialect.FormatTime(now),
	)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return nil, ErrProposalAcquisitionActive
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

func proposalAcquisitionDeclarationMatches(credentialsJSON string, start ProposalAcquisitionStart) bool {
	var slots []proposal.CredentialSlot
	if err := json.Unmarshal([]byte(credentialsJSON), &slots); err != nil {
		return false
	}
	matches := 0
	for _, slot := range slots {
		if slot.Action != proposal.ActionSet || slot.Key != start.CredentialKey || slot.Acquisition == nil {
			continue
		}
		if slot.Acquisition.Handler != start.HandlerID || slot.Acquisition.Profile != start.Profile || string(slot.Acquisition.Mode) != start.Mode {
			return false
		}
		matches++
	}
	return matches == 1
}

func (s *SQLStore) requireCredentialAcquisitionEnabled(ctx context.Context, tx *sql.Tx, forUpdate string) error {
	if forUpdate == "" {
		result, err := tx.ExecContext(ctx, `UPDATE instance_settings SET updated_at = updated_at WHERE key = ?`,
			InstanceSettingCredentialAcquisitionEnabled)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			if err != nil {
				return err
			}
			return ErrCredentialAcquisitionDisabled
		}
	}
	query := `SELECT value FROM instance_settings WHERE key = ?`
	if forUpdate != "" {
		query += forUpdate
	}
	var value string
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(query), InstanceSettingCredentialAcquisitionEnabled).Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCredentialAcquisitionDisabled
		}
		return err
	}
	if value != "true" {
		return ErrCredentialAcquisitionDisabled
	}
	return nil
}

func (s *SQLStore) requireVaultAcquisitionPolicyHandler(
	ctx context.Context,
	tx *sql.Tx,
	vaultID, handlerID string,
	forUpdate string,
) error {
	if forUpdate == "" {
		result, err := tx.ExecContext(ctx, `UPDATE vault_settings SET updated_at = updated_at
			WHERE vault_id = ? AND key = ?`, vaultID, VaultSettingCredentialAcquisitionPolicy)
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
	query := `SELECT value FROM vault_settings WHERE vault_id = ? AND key = ?`
	if forUpdate != "" {
		query += " " + forUpdate
	}
	var raw string
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(query), vaultID, VaultSettingCredentialAcquisitionPolicy).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAcquisitionPolicyHandlerUnavailable
		}
		return err
	}
	policy, err := ParseVaultAcquisitionPolicyJSON(raw)
	if err != nil || !containsExactString(policy.EnabledHandlers, handlerID) {
		return ErrAcquisitionPolicyHandlerUnavailable
	}
	return nil
}

func containsExactString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func (s *SQLStore) GetProposalAcquisition(ctx context.Context, vaultID string, proposalID int, credentialKey string) (*ProposalAcquisition, error) {
	return s.scanProposalAcquisition(s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT `+proposalAcquisitionColumns+`
		FROM proposal_acquisitions WHERE vault_id = ? AND proposal_id = ? AND credential_key = ?
		ORDER BY attempt DESC LIMIT 1`), vaultID, proposalID, credentialKey))
}

func (s *SQLStore) GetProposalAcquisitionByID(ctx context.Context, id string) (*ProposalAcquisition, error) {
	return s.scanProposalAcquisition(s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT `+proposalAcquisitionColumns+`
		FROM proposal_acquisitions WHERE id = ?`), id))
}

func (s *SQLStore) ListProposalAcquisitions(ctx context.Context, vaultID string, proposalID int) ([]ProposalAcquisition, error) {
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(`SELECT `+proposalAcquisitionColumns+`
		FROM proposal_acquisitions WHERE vault_id = ? AND proposal_id = ?
		ORDER BY credential_key, attempt DESC`), vaultID, proposalID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var jobs []ProposalAcquisition
	for rows.Next() {
		job, err := s.scanProposalAcquisition(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

func (s *SQLStore) getProposalAcquisitionTx(ctx context.Context, tx *sql.Tx, id string) (*ProposalAcquisition, error) {
	forUpdate := s.dialect.ForUpdateClause()
	if forUpdate != "" {
		forUpdate = " " + forUpdate
	}
	return s.scanProposalAcquisition(tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT `+proposalAcquisitionColumns+`
		FROM proposal_acquisitions WHERE id = ?`+forUpdate), id))
}

func (s *SQLStore) requireActiveAcquisitionContext(ctx context.Context, tx *sql.Tx, job *ProposalAcquisition) error {
	forUpdate := s.dialect.ForUpdateClause()
	if forUpdate != "" {
		forUpdate = " " + forUpdate
	}
	var status string
	var binding sql.NullString
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT status, context_binding_id FROM proposals
		WHERE vault_id = ? AND id = ?`+forUpdate), job.VaultID, job.ProposalID).Scan(&status, &binding); err != nil {
		return err
	}
	if status != "pending" {
		return ErrProposalStateConflict
	}
	if !binding.Valid || binding.String == "" || binding.String != job.ContextBindingID {
		return ErrContextBindingInactive
	}
	return s.lockActiveContextBinding(ctx, tx, job.ContextBindingID)
}

func (s *SQLStore) requireCurrentAcquisitionHandler(ctx context.Context, tx *sql.Tx, job *ProposalAcquisition) error {
	forUpdate := s.dialect.ForUpdateClause()
	if forUpdate != "" {
		forUpdate = " " + forUpdate
	}
	var generation string
	var enabledRaw interface{}
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT generation, enabled
		FROM acquisition_handlers WHERE id = ?`+forUpdate), job.HandlerID).Scan(&generation, &enabledRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAcquisitionHandlerUnavailable
		}
		return err
	}
	enabled, err := s.dialect.ScanBool(enabledRaw)
	if err != nil {
		return err
	}
	if !enabled || generation != job.HandlerGeneration {
		return ErrAcquisitionHandlerUnavailable
	}
	return nil
}

func (s *SQLStore) MarkProposalAcquisitionRunning(ctx context.Context, id string) (*ProposalAcquisition, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	job, err := s.getProposalAcquisitionTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if job.State != AcquisitionQueued {
		return nil, ErrProposalAcquisitionStateConflict
	}
	if err := s.requireActiveAcquisitionContext(ctx, tx, job); err != nil {
		return nil, err
	}
	if err := s.requireCurrentAcquisitionHandler(ctx, tx, job); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE proposal_acquisitions
		SET state = ?, started_at = ?, updated_at = ? WHERE id = ? AND state = ?`),
		AcquisitionRunning, s.dialect.FormatTime(now), s.dialect.FormatTime(now), id, AcquisitionQueued); err != nil {
		return nil, err
	}
	job.State, job.StartedAt, job.UpdatedAt = AcquisitionRunning, &now, now
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

func (s *SQLStore) MarkProposalAcquisitionAwaitingUser(ctx context.Context, id string, ticketHash []byte, expiresAt time.Time) (*ProposalAcquisition, error) {
	now := time.Now().UTC()
	if len(ticketHash) != sha256Size || !expiresAt.After(now) || expiresAt.After(now.Add(continuationTicketTTL)) {
		return nil, fmt.Errorf("invalid continuation ticket metadata")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	job, err := s.getProposalAcquisitionTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if job.State != AcquisitionRunning {
		return nil, ErrProposalAcquisitionStateConflict
	}
	if err := s.requireActiveAcquisitionContext(ctx, tx, job); err != nil {
		return nil, err
	}
	now = now.Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	hashCopy := append([]byte(nil), ticketHash...)
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE proposal_acquisitions
		SET state = ?, continuation_ticket_hash = ?, continuation_expires_at = ?,
		continuation_used_at = NULL, updated_at = ? WHERE id = ? AND state = ?`),
		AcquisitionAwaitingUser, hashCopy, s.dialect.FormatTime(expiresAt), s.dialect.FormatTime(now), id, AcquisitionRunning); err != nil {
		return nil, err
	}
	job.State, job.ContinuationTicketHash, job.ContinuationExpiresAt, job.ContinuationUsedAt, job.UpdatedAt =
		AcquisitionAwaitingUser, hashCopy, &expiresAt, nil, now
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

const sha256Size = 32

func (s *SQLStore) ConsumeProposalAcquisitionContinuation(ctx context.Context, ticketHash []byte, now time.Time) (*ProposalAcquisition, error) {
	if len(ticketHash) != sha256Size {
		return nil, ErrProposalAcquisitionContinuationUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	forUpdate := s.dialect.ForUpdateClause()
	if forUpdate != "" {
		forUpdate = " " + forUpdate
	}
	job, err := s.scanProposalAcquisition(tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT `+proposalAcquisitionColumns+`
		FROM proposal_acquisitions WHERE continuation_ticket_hash = ?`+forUpdate), ticketHash))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProposalAcquisitionContinuationUnavailable
		}
		return nil, err
	}
	if job.State != AcquisitionAwaitingUser || job.ContinuationUsedAt != nil || job.ContinuationExpiresAt == nil || !job.ContinuationExpiresAt.After(now) {
		return nil, ErrProposalAcquisitionContinuationUnavailable
	}
	if err := s.requireActiveAcquisitionContext(ctx, tx, job); err != nil {
		return nil, err
	}
	usedAt := now.UTC().Truncate(time.Second)
	result, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE proposal_acquisitions
		SET continuation_used_at = ?, updated_at = ?
		WHERE id = ? AND state = ? AND continuation_used_at IS NULL AND continuation_expires_at > ?`),
		s.dialect.FormatTime(usedAt), s.dialect.FormatTime(usedAt), job.ID, AcquisitionAwaitingUser, s.dialect.FormatTime(now.UTC()))
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrProposalAcquisitionContinuationUnavailable
	}
	job.ContinuationUsedAt, job.UpdatedAt = &usedAt, usedAt
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

func validateAcquisitionCompletion(credential EncryptedCredential, source string) error {
	if len(credential.Ciphertext) == 0 || len(credential.Nonce) == 0 || !acquisitionHandlerIDPattern.MatchString(source) {
		return fmt.Errorf("invalid acquisition completion")
	}
	return nil
}

func (s *SQLStore) upsertProposalAcquisitionCredential(ctx context.Context, tx *sql.Tx, job *ProposalAcquisition, credential EncryptedCredential) error {
	_, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO proposal_credentials
		(vault_id, proposal_id, key, ciphertext, nonce) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(vault_id, proposal_id, key) DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce`),
		job.VaultID, job.ProposalID, job.CredentialKey, credential.Ciphertext, credential.Nonce)
	return err
}

// CompleteProposalAcquisitionContinuation atomically consumes a live one-time
// continuation, stores only the already-encrypted credential, and marks the
// job succeeded. A crash cannot strand a consumed ticket without its result.
func (s *SQLStore) CompleteProposalAcquisitionContinuation(ctx context.Context, ticketHash []byte, credential EncryptedCredential, source string, credentialExpiresAt *time.Time) (*ProposalAcquisition, error) {
	if len(ticketHash) != sha256Size {
		return nil, ErrProposalAcquisitionContinuationUnavailable
	}
	if err := validateAcquisitionCompletion(credential, source); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	forUpdate := s.dialect.ForUpdateClause()
	if forUpdate != "" {
		forUpdate = " " + forUpdate
	}
	job, err := s.scanProposalAcquisition(tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT `+proposalAcquisitionColumns+`
		FROM proposal_acquisitions WHERE continuation_ticket_hash = ?`+forUpdate), ticketHash))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProposalAcquisitionContinuationUnavailable
		}
		return nil, err
	}
	nowExact := time.Now().UTC()
	if job.State != AcquisitionAwaitingUser || job.ContinuationUsedAt != nil ||
		job.ContinuationExpiresAt == nil || !job.ContinuationExpiresAt.After(nowExact) {
		return nil, ErrProposalAcquisitionContinuationUnavailable
	}
	if err := s.requireActiveAcquisitionContext(ctx, tx, job); err != nil {
		return nil, err
	}
	if err := s.upsertProposalAcquisitionCredential(ctx, tx, job, credential); err != nil {
		return nil, err
	}
	now := nowExact.Truncate(time.Second)
	if credentialExpiresAt != nil {
		t := credentialExpiresAt.UTC().Truncate(time.Second)
		credentialExpiresAt = &t
	}
	result, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE proposal_acquisitions
		SET state = ?, source = ?, error_code = '', credential_expires_at = ?,
		continuation_used_at = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND state = ? AND continuation_used_at IS NULL AND continuation_expires_at > ?`),
		AcquisitionSucceeded, source, s.dialect.FormatNullableTime(credentialExpiresAt),
		s.dialect.FormatTime(now), s.dialect.FormatTime(now), s.dialect.FormatTime(now),
		job.ID, AcquisitionAwaitingUser, s.dialect.FormatTime(nowExact))
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrProposalAcquisitionContinuationUnavailable
	}
	job.State, job.Source, job.ErrorCode = AcquisitionSucceeded, source, ""
	job.CredentialExpiresAt, job.ContinuationUsedAt, job.CompletedAt, job.UpdatedAt =
		credentialExpiresAt, &now, &now, now
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

func (s *SQLStore) CompleteProposalAcquisition(ctx context.Context, id string, credential EncryptedCredential, source string, credentialExpiresAt *time.Time) (*ProposalAcquisition, error) {
	if err := validateAcquisitionCompletion(credential, source); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	job, err := s.getProposalAcquisitionTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if job.State != AcquisitionRunning && job.State != AcquisitionAwaitingUser {
		return nil, ErrProposalAcquisitionStateConflict
	}
	if err := s.requireActiveAcquisitionContext(ctx, tx, job); err != nil {
		return nil, err
	}
	completionTime := time.Now().UTC()
	if job.State == AcquisitionAwaitingUser &&
		(job.ContinuationUsedAt == nil || job.ContinuationExpiresAt == nil || !job.ContinuationExpiresAt.After(completionTime)) {
		return nil, ErrProposalAcquisitionContinuationUnavailable
	}
	if err := s.upsertProposalAcquisitionCredential(ctx, tx, job, credential); err != nil {
		return nil, err
	}
	now := completionTime.Truncate(time.Second)
	if credentialExpiresAt != nil {
		t := credentialExpiresAt.UTC().Truncate(time.Second)
		credentialExpiresAt = &t
	}
	result, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE proposal_acquisitions
		SET state = ?, source = ?, error_code = '', credential_expires_at = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND state IN (?, ?)`), AcquisitionSucceeded, source,
		s.dialect.FormatNullableTime(credentialExpiresAt), s.dialect.FormatTime(now), s.dialect.FormatTime(now),
		id, AcquisitionRunning, AcquisitionAwaitingUser)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrProposalAcquisitionStateConflict
	}
	job.State, job.Source, job.ErrorCode = AcquisitionSucceeded, source, ""
	job.CredentialExpiresAt, job.CompletedAt, job.UpdatedAt = credentialExpiresAt, &now, now
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return job, nil
}

func (s *SQLStore) CancelProposalAcquisition(ctx context.Context, vaultID string, proposalID int, credentialKey string) (*ProposalAcquisition, error) {
	job, err := s.GetProposalAcquisition(ctx, vaultID, proposalID, credentialKey)
	if err != nil {
		return nil, err
	}
	return s.CancelProposalAcquisitionByID(ctx, job.ID)
}

func (s *SQLStore) CancelProposalAcquisitionByID(ctx context.Context, id string) (*ProposalAcquisition, error) {
	job, err := s.GetProposalAcquisitionByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if job.State != AcquisitionQueued && job.State != AcquisitionRunning && job.State != AcquisitionAwaitingUser {
		return nil, ErrProposalAcquisitionStateConflict
	}
	now := time.Now().UTC().Truncate(time.Second)
	result, err := s.db.ExecContext(ctx, s.dialect.Rebind(`UPDATE proposal_acquisitions
		SET state = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND state IN (?, ?, ?)`), AcquisitionCancelled,
		s.dialect.FormatTime(now), s.dialect.FormatTime(now), job.ID,
		AcquisitionQueued, AcquisitionRunning, AcquisitionAwaitingUser)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrProposalAcquisitionStateConflict
	}
	job.State, job.CompletedAt, job.UpdatedAt = AcquisitionCancelled, &now, now
	return job, nil
}

func (s *SQLStore) FailProposalAcquisition(ctx context.Context, id, errorCode string) (*ProposalAcquisition, error) {
	if !acquisitionHandlerIDPattern.MatchString(errorCode) {
		return nil, fmt.Errorf("invalid acquisition error code")
	}
	job, err := s.GetProposalAcquisitionByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if job.State != AcquisitionQueued && job.State != AcquisitionRunning && job.State != AcquisitionAwaitingUser {
		return nil, ErrProposalAcquisitionStateConflict
	}
	now := time.Now().UTC().Truncate(time.Second)
	result, err := s.db.ExecContext(ctx, s.dialect.Rebind(`UPDATE proposal_acquisitions
		SET state = ?, error_code = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND state IN (?, ?, ?)`), AcquisitionFailed, errorCode,
		s.dialect.FormatTime(now), s.dialect.FormatTime(now), id,
		AcquisitionQueued, AcquisitionRunning, AcquisitionAwaitingUser)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, ErrProposalAcquisitionStateConflict
	}
	job.State, job.ErrorCode, job.CompletedAt, job.UpdatedAt = AcquisitionFailed, errorCode, &now, now
	return job, nil
}
