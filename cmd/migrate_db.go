package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

var migrateDBCmd = &cobra.Command{
	Use:   "migrate-db",
	Short: "Copy data from SQLite to PostgreSQL",
	Long: `Copies all data from a local SQLite Agent Vault database to a PostgreSQL
database. The Agent Vault server must be stopped before running this command.

The destination PostgreSQL database should be empty (freshly created with only
the baseline schema). The command will error if existing user data is found.

After migration completes, the CA certificate and encrypted key are also
migrated from disk to the database so the Postgres-backed deployment can
operate in HA mode without shared filesystem access.`,
	RunE: runMigrateDB,
}

func init() {
	migrateDBCmd.Flags().String("to", "", "PostgreSQL connection URL (required, e.g. postgres://user:pass@host/db)")
	migrateDBCmd.Flags().Bool("dry-run", false, "count rows per table without copying anything")
	migrateDBCmd.Flags().String("from", "", "path to source SQLite database (default: ~/.agent-vault/agent-vault.db)")
	migrateDBCmd.Flags().BoolP("yes", "y", false, "skip confirmation prompt (for scripted/CI usage)")
	_ = migrateDBCmd.MarkFlagRequired("to")
	rootCmd.AddCommand(migrateDBCmd)
}

func runMigrateDB(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	toURL, _ := cmd.Flags().GetString("to")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	fromPath, _ := cmd.Flags().GetString("from")

	// 1. Check the server is not running.
	if pid, err := pidfile.Read(); err == nil {
		if pidfile.IsRunning(pid) {
			return fmt.Errorf("agent vault server is running (PID %d); stop it before migrating", pid)
		}
	}

	// 2. Resolve source path.
	if fromPath == "" {
		var err error
		fromPath, err = store.DefaultDBPath()
		if err != nil {
			return fmt.Errorf("resolving default database path: %w", err)
		}
	}
	if _, err := os.Stat(fromPath); err != nil {
		return fmt.Errorf("source database not found: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Source:      %s\n", fromPath)
	fmt.Fprintf(cmd.OutOrStdout(), "Destination: %s\n", store.RedactURL(toURL))
	fmt.Fprintln(cmd.OutOrStdout())

	// 3. Open source SQLite.
	srcStore, err := store.Open(fromPath)
	if err != nil {
		return fmt.Errorf("opening source database: %w", err)
	}
	defer func() { _ = srcStore.Close() }()

	// 4. Dry-run mode: count rows and exit.
	if dryRun {
		counts, err := store.CountSourceTables(srcStore)
		if err != nil {
			return fmt.Errorf("counting source rows: %w", err)
		}
		total := 0
		fmt.Fprintln(cmd.OutOrStdout(), "Table row counts (dry run):")
		for _, tc := range counts {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-30s %d\n", tc.Table, tc.Count)
			total += tc.Count
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\nTotal: %d rows\n", total)
		return nil
	}

	// 5. Open destination Postgres.
	dstStoreIface, err := store.OpenStore(store.StoreConfig{DatabaseURL: toURL})
	if err != nil {
		return fmt.Errorf("opening destination database: %w", err)
	}
	defer func() { _ = dstStoreIface.Close() }()

	dstStore, ok := dstStoreIface.(*store.SQLStore)
	if !ok {
		return fmt.Errorf("destination store is not a SQL store (unexpected type %T)", dstStoreIface)
	}

	// 6. Check destination is empty.
	found, err := store.CountDestinationData(dstStore)
	if err != nil {
		return fmt.Errorf("checking destination database: %w", err)
	}
	if found != "" {
		return fmt.Errorf("destination database already contains data (%s); aborting", found)
	}

	// 7. Count source rows for confirmation.
	counts, err := store.CountSourceTables(srcStore)
	if err != nil {
		return fmt.Errorf("counting source rows: %w", err)
	}
	total := 0
	for _, tc := range counts {
		total += tc.Count
	}

	fmt.Fprintf(cmd.OutOrStdout(), "This will copy %d records from SQLite to PostgreSQL.\n", total)

	autoYes, _ := cmd.Flags().GetBool("yes")
	if !autoYes {
		fmt.Fprintf(cmd.OutOrStdout(), "Continue? [y/N] ")

		reader := bufio.NewReader(os.Stdin)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
			return nil
		}
	}

	// 8. Copy data.
	fmt.Fprintln(cmd.OutOrStdout())
	err = store.MigrateData(ctx, srcStore, dstStore, func(table string, rows int) {
		fmt.Fprintf(cmd.OutOrStdout(), "Copying %-30s %d rows... done\n", table+":", rows)
	})
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	// 9. Migrate CA from disk (if present).
	caDir := filepath.Join(filepath.Dir(fromPath), "ca")
	caMigrated, err := store.MigrateCAFromDisk(ctx, dstStore, caDir)
	if err != nil {
		return fmt.Errorf("migrating CA from disk: %w", err)
	}
	if caMigrated {
		fmt.Fprintln(cmd.OutOrStdout(), "\nCA certificate and key migrated from disk to database.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "\nNo CA files found on disk (this is normal if the CA was already in the database).")
	}

	fmt.Fprintln(cmd.OutOrStdout(), "\nMigration complete.")
	return nil
}
