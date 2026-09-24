package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

func TestSetVaultAcquisitionPolicyValidatesHandlersAndPersistsAtomically(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, err := s.GetVault(ctx, DefaultVault)
	if err != nil {
		t.Fatal(err)
	}

	handler := testAcquisitionHandler()
	handler.AllowedVaults = []string{vault.ID}
	created, err := s.CreateAcquisitionHandler(ctx, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAcquisitionHandlerEnabled(ctx, created.ID, true); err != nil {
		t.Fatal(err)
	}

	policy := VaultAcquisitionPolicy{
		EnabledHandlers:   []string{created.ID},
		BrowserDOMEnabled: true,
	}
	if err := s.SetVaultAcquisitionPolicy(ctx, vault.ID, policy); err != nil {
		t.Fatalf("SetVaultAcquisitionPolicy: %v", err)
	}
	raw, err := s.GetVaultSetting(ctx, vault.ID, VaultSettingCredentialAcquisitionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if raw != `{"enabled_handlers":["github-cli"],"browser_dom_enabled":true}` {
		t.Fatalf("stored policy=%q", raw)
	}

	if err := s.SetAcquisitionHandlerEnabled(ctx, created.ID, false); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		policy VaultAcquisitionPolicy
	}{
		{"disabled", VaultAcquisitionPolicy{EnabledHandlers: []string{created.ID}}},
		{"missing", VaultAcquisitionPolicy{EnabledHandlers: []string{"missing"}}},
		{"duplicate", VaultAcquisitionPolicy{EnabledHandlers: []string{created.ID, created.ID}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.DeleteVaultSetting(ctx, vault.ID, VaultSettingCredentialAcquisitionPolicy); err != nil {
				t.Fatal(err)
			}
			err := s.SetVaultAcquisitionPolicy(ctx, vault.ID, tt.policy)
			if !errors.Is(err, ErrAcquisitionPolicyHandlerUnavailable) {
				t.Fatalf("error=%v", err)
			}
			if _, err := s.GetVaultSetting(ctx, vault.ID, VaultSettingCredentialAcquisitionPolicy); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("rejected policy persisted: %v", err)
			}
		})
	}

	if err := s.SetAcquisitionHandlerEnabled(ctx, created.ID, true); err != nil {
		t.Fatal(err)
	}
	created.AllowedVaults = []string{"another-vault"}
	allowedVaults, err := json.Marshal(created.AllowedVaults)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE acquisition_handlers SET allowed_vaults_json = ? WHERE id = ?`, string(allowedVaults), created.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVaultAcquisitionPolicy(ctx, vault.ID, policy); !errors.Is(err, ErrAcquisitionPolicyHandlerUnavailable) {
		t.Fatalf("wrong-vault handler error=%v", err)
	}
}

func TestSetVaultAcquisitionPolicyPersistsCanonicalEmptyHandlerList(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vault, err := s.GetVault(ctx, DefaultVault)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetVaultAcquisitionPolicy(ctx, vault.ID, VaultAcquisitionPolicy{}); err != nil {
		t.Fatal(err)
	}
	raw, err := s.GetVaultSetting(ctx, vault.ID, VaultSettingCredentialAcquisitionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if raw != `{"enabled_handlers":[],"browser_dom_enabled":false}` {
		t.Fatalf("stored policy=%q", raw)
	}
	policy, err := ParseVaultAcquisitionPolicyJSON(raw)
	if err != nil || policy.EnabledHandlers == nil || len(policy.EnabledHandlers) != 0 {
		t.Fatalf("parsed policy=%+v err=%v", policy, err)
	}
}
