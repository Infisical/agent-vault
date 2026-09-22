package store

import (
	"context"
	"testing"
	"time"
)

func TestUserInviteRevokeByID(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// Create a vault for pre-assignment.
	vault, err := s.CreateVault(ctx, "test-vault")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	vaults := []UserInviteVault{{VaultID: vault.ID, VaultName: vault.Name, VaultRole: "member"}}

	// Create a pending invite.
	inv, err := s.CreateUserInvite(ctx, "alice@test.com", "creator-id", "member", time.Now().Add(time.Hour), vaults)
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}
	if inv.Token == "" {
		t.Fatal("expected non-empty token at creation")
	}

	// List pending invites — should contain the invite with an ID but empty token.
	pending, err := s.ListUserInvites(ctx, "pending")
	if err != nil {
		t.Fatalf("ListUserInvites: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending invite, got %d", len(pending))
	}
	if pending[0].ID != inv.ID {
		t.Fatalf("expected ID %d, got %d", inv.ID, pending[0].ID)
	}
	if pending[0].Token != "" {
		t.Fatalf("expected empty token in list response, got %q", pending[0].Token)
	}

	// Revoke by ID using the ID from the list.
	if err := s.RevokeUserInviteByID(ctx, pending[0].ID); err != nil {
		t.Fatalf("RevokeUserInviteByID: %v", err)
	}

	// Verify it's now revoked.
	revoked, err := s.ListUserInvites(ctx, "revoked")
	if err != nil {
		t.Fatalf("ListUserInvites revoked: %v", err)
	}
	if len(revoked) != 1 {
		t.Fatalf("expected 1 revoked invite, got %d", len(revoked))
	}

	// Pending list should be empty now.
	pendingAfter, err := s.ListUserInvites(ctx, "pending")
	if err != nil {
		t.Fatalf("ListUserInvites pending after: %v", err)
	}
	if len(pendingAfter) != 0 {
		t.Fatalf("expected 0 pending after revoke, got %d", len(pendingAfter))
	}
}

func TestUserInviteRevokeByIDNotFound(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	err := s.RevokeUserInviteByID(ctx, 99999)
	if err == nil {
		t.Fatal("expected error for nonexistent invite ID")
	}
}

func TestUserInviteRevokeByIDNotPending(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// Create and accept an invite.
	inv, err := s.CreateUserInvite(ctx, "bob@test.com", "creator-id", "member", time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}
	if err := s.AcceptUserInvite(ctx, inv.Token); err != nil {
		t.Fatalf("AcceptUserInvite: %v", err)
	}

	// Revoke by ID should fail (not pending).
	err = s.RevokeUserInviteByID(ctx, inv.ID)
	if err == nil {
		t.Fatal("expected error for non-pending invite")
	}
}

func TestGetUserInviteByID(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// Create a vault for pre-assignment.
	vault, err := s.CreateVault(ctx, "test-vault-2")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	vaults := []UserInviteVault{{VaultID: vault.ID, VaultName: vault.Name, VaultRole: "admin"}}
	inv, err := s.CreateUserInvite(ctx, "carol@test.com", "creator-id", "member", time.Now().Add(time.Hour), vaults)
	if err != nil {
		t.Fatalf("CreateUserInvite: %v", err)
	}

	// Fetch by ID.
	fetched, err := s.GetUserInviteByID(ctx, inv.ID)
	if err != nil {
		t.Fatalf("GetUserInviteByID: %v", err)
	}
	if fetched.Email != "carol@test.com" {
		t.Fatalf("expected carol@test.com, got %s", fetched.Email)
	}
	if fetched.Status != "pending" {
		t.Fatalf("expected pending, got %s", fetched.Status)
	}
	if len(fetched.Vaults) != 1 || fetched.Vaults[0].VaultName != "test-vault-2" {
		t.Fatalf("expected 1 vault 'test-vault-2', got %+v", fetched.Vaults)
	}

	// Nonexistent ID should error.
	_, err = s.GetUserInviteByID(ctx, 99999)
	if err == nil {
		t.Fatal("expected error for nonexistent invite ID")
	}
}
