package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/inspect"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect request logs and explain likely proxy failures",
}

var inspectRequestCmd = &cobra.Command{
	Use:   "request --id <id>",
	Short: "Inspect one safe request-log entry",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetInt64("id")
		if id <= 0 {
			return fmt.Errorf("--id is required")
		}
		vault := resolveVault(cmd)
		log, err := fetchLogByID(cmd, vault, id)
		if err != nil {
			return err
		}
		diagnosis := inspect.Diagnose(*log)

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return printJSON(cmd, struct {
				Log       inspect.RequestLog `json:"log"`
				Diagnosis inspect.Diagnosis  `json:"diagnosis"`
			}{Log: *log, Diagnosis: diagnosis})
		}

		renderRequestInspection(cmd, *log, diagnosis)
		return nil
	},
}

var inspectExplainCmd = &cobra.Command{
	Use:     "explain",
	Aliases: []string{"logs"},
	Short:   "Explain likely failures in recent request logs",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		resp, err := fetchLogs(cmd, vault, 0, 0)
		if err != nil {
			return err
		}
		items := inspect.DiagnoseBatch(resp.Logs)
		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return printJSON(cmd, struct {
				Diagnoses []inspect.DiagnosisForLog `json:"diagnoses"`
			}{Diagnoses: items})
		}
		renderExplain(cmd, items)
		return nil
	},
}

func fetchLogByID(cmd *cobra.Command, vault string, id int64) (*inspect.RequestLog, error) {
	sess, err := ensureSession()
	if err != nil {
		return nil, err
	}

	values := url.Values{}
	values.Set("before", strconv.FormatInt(id+1, 10))
	values.Set("limit", "1")
	path := fmt.Sprintf("/v1/vaults/%s/logs?%s", url.PathEscape(vault), values.Encode())

	var respBody []byte
	err = withReauthRetry(sess, sess.Address, func(s *session.ClientSession) error {
		var ierr error
		respBody, ierr = doAdminRequestWithBody("GET", s.Address+path, s.Token, nil)
		return ierr
	})
	if err != nil {
		return nil, err
	}

	var resp logsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	if len(resp.Logs) == 0 || resp.Logs[0].ID != id {
		return nil, fmt.Errorf("request log %d not found in vault %q", id, vault)
	}
	return &resp.Logs[0], nil
}

func renderRequestInspection(cmd *cobra.Command, log inspect.RequestLog, diagnosis inspect.Diagnosis) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Request %d\n\n", log.ID)
	fmt.Fprintf(out, "Time: %s\n", formatLogTime(log.CreatedAt))
	fmt.Fprintf(out, "Ingress: %s\n", valueOrDash(log.Ingress))
	fmt.Fprintf(out, "Method: %s\n", valueOrDash(log.Method))
	fmt.Fprintf(out, "Host: %s\n", valueOrDash(log.Host))
	fmt.Fprintf(out, "Path: %s\n", valueOrDash(log.Path))
	fmt.Fprintf(out, "Status: %s\n", formatStatus(log))
	fmt.Fprintf(out, "Matched service: %s\n", valueOrDash(log.MatchedService))
	fmt.Fprintf(out, "Credential keys: %s\n", formatCredentialKeys(log.CredentialKeys))
	fmt.Fprintf(out, "Latency: %d ms\n", log.LatencyMs)
	if log.ErrorCode != "" {
		fmt.Fprintf(out, "Error code: %s\n", log.ErrorCode)
	}
	fmt.Fprintln(out)
	renderDiagnosis(out, diagnosis)
}

func renderExplain(cmd *cobra.Command, items []inspect.DiagnosisForLog) {
	out := cmd.OutOrStdout()
	if len(items) == 0 {
		fmt.Fprintln(out, "No suspicious request logs found.")
		return
	}
	for i, item := range items {
		if i > 0 {
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "Request %d (%s %s%s -> %s)\n", item.Log.ID, valueOrDash(item.Log.Method), valueOrDash(item.Log.Host), valueOrDash(item.Log.Path), formatStatus(item.Log))
		renderDiagnosis(out, item.Diagnosis)
	}
}

func renderDiagnosis(out io.Writer, diagnosis inspect.Diagnosis) {
	fmt.Fprintf(out, "Diagnosis:\n%s\n", diagnosis.Summary)
	if len(diagnosis.Details) > 0 {
		fmt.Fprintln(out, "\nDetails:")
		for _, detail := range diagnosis.Details {
			fmt.Fprintf(out, "- %s\n", detail)
		}
	}
	if len(diagnosis.SuggestedNext) > 0 {
		fmt.Fprintln(out, "\nSuggested next checks:")
		for _, next := range diagnosis.SuggestedNext {
			fmt.Fprintf(out, "- %s\n", next)
		}
	}
}

func formatCredentialKeys(keys []string) string {
	if len(keys) == 0 {
		return "-"
	}
	safe := make([]string, 0, len(keys))
	for _, key := range keys {
		safe = append(safe, valueOrDash(key))
	}
	return strings.Join(safe, ", ")
}

func init() {
	inspectRequestCmd.Flags().String("vault", "", "vault name (default resolves from context)")
	inspectRequestCmd.Flags().Int64("id", 0, "request log id")
	inspectRequestCmd.Flags().Bool("json", false, "print JSON")

	inspectExplainCmd.Flags().String("vault", "", "vault name (default resolves from context)")
	inspectExplainCmd.Flags().String("ingress", "", "filter by ingress: explicit or mitm")
	inspectExplainCmd.Flags().String("status", "", "filter by status bucket: 2xx, 3xx, 4xx, 5xx, err")
	inspectExplainCmd.Flags().String("service", "", "filter by matched service host")
	inspectExplainCmd.Flags().Int("limit", 50, "number of recent logs to inspect (max 200)")
	inspectExplainCmd.Flags().Bool("json", false, "print JSON")

	inspectCmd.AddCommand(inspectRequestCmd, inspectExplainCmd)
	rootCmd.AddCommand(inspectCmd)
}
