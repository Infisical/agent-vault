package auth

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
)

func TestSetupWithPasswordAndUnlockRoundTrip(t *testing.T) {
	password := []byte("correct-horse-battery-staple")

	mk, rec, err := SetupWithPassword(password)
	if err != nil {
		t.Fatalf("SetupWithPassword: %v", err)
	}
	defer mk.Wipe()

	if len(mk.Key()) != 32 {
		t.Fatalf("expected 32-byte DEK, got %d", len(mk.Key()))
	}

	// Wrapped DEK fields should be populated, plaintext DEK should be nil.
	if rec.DEKCiphertext == nil || rec.DEKNonce == nil {
		t.Fatal("expected DEKCiphertext and DEKNonce to be set")
	}
	if rec.DEKPlaintext != nil {
		t.Fatal("expected DEKPlaintext to be nil for password-protected setup")
	}

	// Unlock with the same password should succeed and return the same DEK.
	mk2, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer mk2.Wipe()

	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEKs from SetupWithPassword and Unlock differ")
	}
}

func TestSetupPasswordlessAndUnlockRoundTrip(t *testing.T) {
	mk, rec, err := SetupPasswordless()
	if err != nil {
		t.Fatalf("SetupPasswordless: %v", err)
	}
	defer mk.Wipe()

	if len(mk.Key()) != 32 {
		t.Fatalf("expected 32-byte DEK, got %d", len(mk.Key()))
	}

	// Plaintext DEK should be populated, wrapped DEK fields should be nil.
	if rec.DEKPlaintext == nil {
		t.Fatal("expected DEKPlaintext to be set")
	}
	if rec.DEKCiphertext != nil || rec.DEKNonce != nil {
		t.Fatal("expected DEKCiphertext/DEKNonce to be nil for passwordless setup")
	}

	// UnlockPasswordless should return the same DEK.
	mk2, err := UnlockPasswordless(rec)
	if err != nil {
		t.Fatalf("UnlockPasswordless: %v", err)
	}
	defer mk2.Wipe()

	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEKs from SetupPasswordless and UnlockPasswordless differ")
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	password := []byte("correct-password")
	wrong := []byte("wrong-password")

	_, rec, err := SetupWithPassword(password)
	if err != nil {
		t.Fatalf("SetupWithPassword: %v", err)
	}

	_, err = Unlock(wrong, rec)
	if err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestWipeZerosKey(t *testing.T) {
	mk, _, err := SetupPasswordless()
	if err != nil {
		t.Fatalf("SetupPasswordless: %v", err)
	}

	key := mk.Key()
	mk.Wipe()

	for i, b := range key {
		if b != 0 {
			t.Fatalf("byte %d not wiped: got %d", i, b)
		}
	}
}

func TestSetupProducesDifferentDEKs(t *testing.T) {
	mk1, _, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	mk2, _, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}

	if string(mk1.Key()) == string(mk2.Key()) {
		t.Fatal("two SetupPasswordless calls produced the same DEK")
	}
}

func TestWrapDEKRoundTrip(t *testing.T) {
	mk, _, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()

	password := []byte("test-password")
	salt, dekCT, dekNonce, params, err := WrapDEK(mk.Key(), password)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Build a verification record to unlock.
	sentinelCT, sentinelNonce, err := crypto.Encrypt([]byte(sentinel), mk.Key())
	if err != nil {
		t.Fatal(err)
	}

	rec := &VerificationRecord{
		Sentinel:      sentinelCT,
		SentinelNonce: sentinelNonce,
		DEKCiphertext: dekCT,
		DEKNonce:      dekNonce,
		Salt:          salt,
		Params:        params,
	}

	mk2, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock after WrapDEK: %v", err)
	}
	defer mk2.Wipe()

	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEK mismatch after WrapDEK round-trip")
	}
}

func TestPasswordChangePreservesDEK(t *testing.T) {
	oldPw := []byte("old-password")
	newPw := []byte("new-password")

	mk, rec, err := SetupWithPassword(oldPw)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()

	originalDEK := make([]byte, len(mk.Key()))
	copy(originalDEK, mk.Key())

	// Re-wrap the DEK under a new password.
	salt, dekCT, dekNonce, params, err := WrapDEK(mk.Key(), newPw)
	if err != nil {
		t.Fatal(err)
	}

	// Update the verification record.
	rec.DEKCiphertext = dekCT
	rec.DEKNonce = dekNonce
	rec.Salt = salt
	rec.Params = params

	// Old password should no longer work.
	_, err = Unlock(oldPw, rec)
	if err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword with old password, got %v", err)
	}

	// New password should work and return the same DEK.
	mk2, err := Unlock(newPw, rec)
	if err != nil {
		t.Fatalf("Unlock with new password: %v", err)
	}
	defer mk2.Wipe()

	if string(mk2.Key()) != string(originalDEK) {
		t.Fatal("DEK changed after password change — it should be preserved")
	}
}
