package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

const skillBody = "# Deploy\n\nSteps:\n\n1. Run tests\n2. Ship it\n"

func TestSkillCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "skills-crud")

	created, err := s.InsertSkill(ctx, Skill{
		VaultID:     ns.ID,
		Name:        "deploy-staging",
		Description: "How to deploy to staging",
		Content:     skillBody,
	})
	if err != nil {
		t.Fatalf("InsertSkill: %v", err)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatal("InsertSkill returned zero timestamps")
	}

	got, err := s.GetSkill(ctx, ns.ID, "deploy-staging")
	if err != nil {
		t.Fatalf("GetSkill: %v", err)
	}
	if got.Content != skillBody {
		t.Fatalf("body did not round-trip:\ngot  %q\nwant %q", got.Content, skillBody)
	}
	if got.Description != "How to deploy to staging" {
		t.Fatalf("description = %q", got.Description)
	}
	// The timestamps InsertSkill reports must match what the row actually
	// holds, or the UI would show a value that shifts on refresh.
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("CreatedAt drift: stored %v, returned %v", got.CreatedAt, created.CreatedAt)
	}

	// List is name-ordered and carries no body.
	if _, err := s.InsertSkill(ctx, Skill{VaultID: ns.ID, Name: "audit-logs", Content: "x"}); err != nil {
		t.Fatalf("InsertSkill second: %v", err)
	}
	list, err := s.ListSkills(ctx, ns.ID)
	if err != nil {
		t.Fatalf("ListSkills: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 skills, got %d", len(list))
	}
	if list[0].Name != "audit-logs" || list[1].Name != "deploy-staging" {
		t.Fatalf("expected name ordering, got %q, %q", list[0].Name, list[1].Name)
	}
	if list[1].CreatedAt.IsZero() || list[1].UpdatedAt.IsZero() {
		t.Fatal("ListSkills returned zero timestamps")
	}

	// Update in place.
	updated, err := s.UpdateSkill(ctx, ns.ID, "deploy-staging", Skill{
		VaultID:     ns.ID,
		Name:        "deploy-staging",
		Description: "Updated description",
		Content:     "new body",
	})
	if err != nil {
		t.Fatalf("UpdateSkill: %v", err)
	}
	if updated.Description != "Updated description" || updated.Content != "new body" {
		t.Fatalf("update did not apply: %+v", updated)
	}
	if updated.CreatedAt.IsZero() {
		t.Fatal("UpdateSkill dropped CreatedAt")
	}

	// Update with rename.
	renamed, err := s.UpdateSkill(ctx, ns.ID, "deploy-staging", Skill{
		VaultID: ns.ID,
		Name:    "deploy-prod",
		Content: "prod body",
	})
	if err != nil {
		t.Fatalf("UpdateSkill rename: %v", err)
	}
	if renamed.Name != "deploy-prod" {
		t.Fatalf("rename did not apply: %q", renamed.Name)
	}
	if _, err := s.GetSkill(ctx, ns.ID, "deploy-staging"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old name still present after rename, err = %v", err)
	}

	// Delete.
	if err := s.DeleteSkill(ctx, ns.ID, "deploy-prod"); err != nil {
		t.Fatalf("DeleteSkill: %v", err)
	}
	if _, err := s.GetSkill(ctx, ns.ID, "deploy-prod"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestSkillInsertDuplicateReturnsErrSkillExists(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "skills-dup")
	sk := Skill{VaultID: ns.ID, Name: "dup-skill", Content: "a"}
	if _, err := s.InsertSkill(ctx, sk); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSkill(ctx, sk); !errors.Is(err, ErrSkillExists) {
		t.Fatalf("expected ErrSkillExists, got %v", err)
	}
}

func TestSkillNamesAreScopedPerVault(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	a, _ := s.CreateVault(ctx, "skills-vault-a")
	b, _ := s.CreateVault(ctx, "skills-vault-b")

	if _, err := s.InsertSkill(ctx, Skill{VaultID: a.ID, Name: "shared-name", Content: "a"}); err != nil {
		t.Fatal(err)
	}
	// The same name in a different vault must be allowed.
	if _, err := s.InsertSkill(ctx, Skill{VaultID: b.ID, Name: "shared-name", Content: "b"}); err != nil {
		t.Fatalf("same name in another vault should be allowed, got %v", err)
	}
	got, err := s.GetSkill(ctx, b.ID, "shared-name")
	if err != nil {
		t.Fatal(err)
	}
	if got.Content != "b" {
		t.Fatalf("cross-vault leak: content = %q", got.Content)
	}
}

func TestSkillRenameCollisionReturnsErrSkillExists(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "skills-rename")
	if _, err := s.InsertSkill(ctx, Skill{VaultID: ns.ID, Name: "first-skill", Content: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSkill(ctx, Skill{VaultID: ns.ID, Name: "second-skill", Content: "b"}); err != nil {
		t.Fatal(err)
	}

	_, err := s.UpdateSkill(ctx, ns.ID, "first-skill", Skill{
		VaultID: ns.ID, Name: "second-skill", Content: "a",
	})
	if !errors.Is(err, ErrSkillExists) {
		t.Fatalf("expected ErrSkillExists, got %v", err)
	}
	// The collision must not have mutated either row.
	if got, err := s.GetSkill(ctx, ns.ID, "second-skill"); err != nil || got.Content != "b" {
		t.Fatalf("target row was mutated: %+v, err %v", got, err)
	}
}

func TestSkillUpdateAndDeleteMissingReturnErrNoRows(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "skills-missing")

	_, err := s.UpdateSkill(ctx, ns.ID, "nope-skill", Skill{
		VaultID: ns.ID, Name: "nope-skill", Content: "a",
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("UpdateSkill missing: expected sql.ErrNoRows, got %v", err)
	}
	if err := s.DeleteSkill(ctx, ns.ID, "nope-skill"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DeleteSkill missing: expected sql.ErrNoRows, got %v", err)
	}
}

func TestCascadeDeleteVaultRemovesSkills(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ns, _ := s.CreateVault(ctx, "skills-cascade")
	if _, err := s.InsertSkill(ctx, Skill{VaultID: ns.ID, Name: "one-skill", Content: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSkill(ctx, Skill{VaultID: ns.ID, Name: "two-skill", Content: "b"}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteVault(ctx, "skills-cascade"); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListSkills(ctx, ns.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 skills after cascade delete, got %d", len(list))
	}
}
