package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

var masterPasswordCmd = &cobra.Command{
	Use:   "master-password",
	Short: "Manage the master password that protects the encryption key",
}

var masterPasswordSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set a master password on a passwordless instance",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureServerStopped(); err != nil {
			return err
		}

		db, cleanup, err := openDB()
		if err != nil {
			return err
		}
		defer cleanup()

		ctx := context.Background()
		record, err := db.GetMasterKeyRecord(ctx)
		if err != nil {
			return fmt.Errorf("reading master key record: %w", err)
		}
		if record == nil {
			return fmt.Errorf("no master key record found — run 'agent-vault server' first")
		}
		if record.DEKPlaintext == nil {
			return fmt.Errorf("instance already has a master password — use 'agent-vault master-password change' instead")
		}

		// Load the DEK and verify the sentinel.
		verRec := buildVerificationRecord(record)
		mk, err := auth.UnlockPasswordless(verRec)
		if err != nil {
			return fmt.Errorf("failed to load encryption key: %w", err)
		}
		defer mk.Wipe()

		// Prompt for the new password.
		newPw, err := auth.PromptNewPassword(
			"New master password: ",
			"Confirm master password: ",
		)
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}
		if len(newPw) == 0 {
			return fmt.Errorf("password cannot be empty")
		}

		// Wrap the DEK under the new KEK.
		salt, dekCT, dekNonce, params, err := auth.WrapDEK(mk.Key(), newPw)
		crypto.WipeBytes(newPw)
		if err != nil {
			return fmt.Errorf("wrapping encryption key: %w", err)
		}

		// Update the record: set wrapped DEK, clear plaintext DEK.
		record.DEKCiphertext = dekCT
		record.DEKNonce = dekNonce
		record.DEKPlaintext = nil
		record.Salt = salt
		record.KDFTime = &params.Time
		record.KDFMemory = &params.Memory
		record.KDFThreads = &params.Threads

		if err := db.UpdateMasterKeyRecord(ctx, record); err != nil {
			return fmt.Errorf("persisting updated record: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Master password set. The server will require this password on startup.\n", successText("✓"))
		return nil
	},
}

var masterPasswordChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "Change the master password",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureServerStopped(); err != nil {
			return err
		}

		db, cleanup, err := openDB()
		if err != nil {
			return err
		}
		defer cleanup()

		ctx := context.Background()
		record, err := db.GetMasterKeyRecord(ctx)
		if err != nil {
			return fmt.Errorf("reading master key record: %w", err)
		}
		if record == nil {
			return fmt.Errorf("no master key record found — run 'agent-vault server' first")
		}
		if record.DEKCiphertext == nil {
			return fmt.Errorf("instance has no master password — use 'agent-vault master-password set' instead")
		}

		// Prompt for the current password and unlock.
		currentPw, err := auth.PromptPassword("Current master password: ")
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}

		verRec := buildVerificationRecord(record)
		mk, err := auth.Unlock(currentPw, verRec)
		crypto.WipeBytes(currentPw)
		if err != nil {
			return fmt.Errorf("wrong password")
		}
		defer mk.Wipe()

		// Prompt for the new password.
		newPw, err := auth.PromptNewPassword(
			"New master password: ",
			"Confirm new master password: ",
		)
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}
		if len(newPw) == 0 {
			return fmt.Errorf("password cannot be empty")
		}

		// Re-wrap the DEK under the new KEK.
		salt, dekCT, dekNonce, params, err := auth.WrapDEK(mk.Key(), newPw)
		crypto.WipeBytes(newPw)
		if err != nil {
			return fmt.Errorf("wrapping encryption key: %w", err)
		}

		// Update the record with the new wrapped DEK.
		record.DEKCiphertext = dekCT
		record.DEKNonce = dekNonce
		record.Salt = salt
		record.KDFTime = &params.Time
		record.KDFMemory = &params.Memory
		record.KDFThreads = &params.Threads

		if err := db.UpdateMasterKeyRecord(ctx, record); err != nil {
			return fmt.Errorf("persisting updated record: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Master password changed. No credentials were re-encrypted.\n", successText("✓"))
		return nil
	},
}

var masterPasswordRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove the master password (switch to passwordless mode)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ensureServerStopped(); err != nil {
			return err
		}

		db, cleanup, err := openDB()
		if err != nil {
			return err
		}
		defer cleanup()

		ctx := context.Background()
		record, err := db.GetMasterKeyRecord(ctx)
		if err != nil {
			return fmt.Errorf("reading master key record: %w", err)
		}
		if record == nil {
			return fmt.Errorf("no master key record found — run 'agent-vault server' first")
		}
		if record.DEKCiphertext == nil {
			return fmt.Errorf("instance already has no master password")
		}

		// Prompt for the current password and unlock.
		currentPw, err := auth.PromptPassword("Current master password: ")
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}

		verRec := buildVerificationRecord(record)
		mk, err := auth.Unlock(currentPw, verRec)
		crypto.WipeBytes(currentPw)
		if err != nil {
			return fmt.Errorf("wrong password")
		}
		defer mk.Wipe()

		// Store the DEK in plaintext, clear the wrapped DEK.
		dekCopy := make([]byte, len(mk.Key()))
		copy(dekCopy, mk.Key())

		record.DEKPlaintext = dekCopy
		record.DEKCiphertext = nil
		record.DEKNonce = nil
		record.Salt = nil
		record.KDFTime = nil
		record.KDFMemory = nil
		record.KDFThreads = nil

		if err := db.UpdateMasterKeyRecord(ctx, record); err != nil {
			return fmt.Errorf("persisting updated record: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s Master password removed. The encryption key is now stored in plaintext.\n", successText("✓"))
		fmt.Fprintln(cmd.OutOrStderr(), "Security now depends on filesystem access controls.")
		return nil
	},
}

// ensureServerStopped checks that no server process is running.
// Master password operations require exclusive access to the database.
func ensureServerStopped() error {
	pid, err := pidfile.Read()
	if err != nil {
		return nil // no PID file means no server running
	}
	if pidfile.IsRunning(pid) {
		return fmt.Errorf("server is running (PID %d) — stop it first with 'agent-vault server stop'", pid)
	}
	return nil
}

// openDB opens the SQLite store at the default path.
func openDB() (*store.SQLiteStore, func(), error) {
	dbPath, err := store.DefaultDBPath()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving db path: %w", err)
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("database not found at %s — run 'agent-vault server' first", dbPath)
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening store: %w", err)
	}
	return db, func() { _ = db.Close() }, nil
}

func init() {
	masterPasswordCmd.AddCommand(masterPasswordSetCmd)
	masterPasswordCmd.AddCommand(masterPasswordChangeCmd)
	masterPasswordCmd.AddCommand(masterPasswordRemoveCmd)
	rootCmd.AddCommand(masterPasswordCmd)
}
