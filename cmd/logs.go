package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/inspect"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

type logsResponse struct {
	Logs       []inspect.RequestLog `json:"logs"`
	NextCursor *int64               `json:"next_cursor"`
	LatestID   int64                `json:"latest_id"`
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "List safe request logs for a vault",
	Args:  cobra.NoArgs,
	RunE:  runLogs,
}

func runLogs(cmd *cobra.Command, args []string) error {
	vault := resolveVault(cmd)
	jsonOut, _ := cmd.Flags().GetBool("json")
	tail, _ := cmd.Flags().GetBool("tail")
	interval, _ := cmd.Flags().GetDuration("interval")
	if tail && interval <= 0 {
		return fmt.Errorf("--interval must be greater than 0")
	}

	resp, err := fetchLogs(cmd, vault, 0, 0)
	if err != nil {
		return err
	}
	if jsonOut {
		if err := printJSON(cmd, resp); err != nil {
			return err
		}
	} else {
		renderLogsTable(cmd, resp.Logs)
	}

	if !tail {
		return nil
	}
	after := resp.LatestID
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		case <-ticker.C:
			resp, err := fetchLogs(cmd, vault, 0, after)
			if err != nil {
				return err
			}
			after = resp.LatestID
			if len(resp.Logs) == 0 {
				continue
			}
			if jsonOut {
				if err := printJSON(cmd, resp); err != nil {
					return err
				}
				continue
			}
			renderLogsTable(cmd, resp.Logs)
		}
	}
}

func fetchLogs(cmd *cobra.Command, vault string, before, after int64) (*logsResponse, error) {
	sess, err := ensureSession()
	if err != nil {
		return nil, err
	}

	values := url.Values{}
	limit, _ := cmd.Flags().GetInt("limit")
	if limit > 0 {
		values.Set("limit", strconv.Itoa(limit))
	}
	if ingress, _ := cmd.Flags().GetString("ingress"); ingress != "" {
		if err := validateIngress(ingress); err != nil {
			return nil, err
		}
		values.Set("ingress", ingress)
	}
	if status, _ := cmd.Flags().GetString("status"); status != "" {
		if err := validateStatusBucket(status); err != nil {
			return nil, err
		}
		values.Set("status_bucket", status)
	}
	if service, _ := cmd.Flags().GetString("service"); service != "" {
		values.Set("service", service)
	}
	if before > 0 {
		values.Set("before", strconv.FormatInt(before, 10))
	}
	if after > 0 {
		values.Set("after", strconv.FormatInt(after, 10))
	}

	path := fmt.Sprintf("/v1/vaults/%s/logs", url.PathEscape(vault))
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}

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
	return &resp, nil
}

func renderLogsTable(cmd *cobra.Command, logs []inspect.RequestLog) {
	if len(logs) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No request logs found.")
		return
	}
	t := newTable(cmd.OutOrStdout())
	t.AppendHeader(table.Row{"ID", "TIME", "INGRESS", "METHOD", "HOST", "STATUS", "SERVICE", "LATENCY"})
	for _, log := range logs {
		t.AppendRow(table.Row{
			log.ID,
			formatLogTime(log.CreatedAt),
			valueOrDash(log.Ingress),
			valueOrDash(log.Method),
			valueOrDash(log.Host),
			formatStatus(log),
			valueOrDash(log.MatchedService),
			fmt.Sprintf("%d ms", log.LatencyMs),
		})
	}
	t.Render()
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func formatLogTime(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func formatStatus(log inspect.RequestLog) string {
	if log.Status > 0 {
		return strconv.Itoa(log.Status)
	}
	if log.ErrorCode != "" {
		return "err:" + log.ErrorCode
	}
	return "err"
}

func validateStatusBucket(s string) error {
	switch s {
	case "2xx", "3xx", "4xx", "5xx", "err":
		return nil
	default:
		return fmt.Errorf("--status must be one of 2xx, 3xx, 4xx, 5xx, err")
	}
}

func validateIngress(s string) error {
	switch s {
	case "explicit", "mitm":
		return nil
	default:
		return fmt.Errorf("--ingress must be one of explicit, mitm")
	}
}

func valueOrDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return stripControlChars(s)
}

func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

func init() {
	logsCmd.Flags().String("vault", "", "vault name (default resolves from context)")
	logsCmd.Flags().String("ingress", "", "filter by ingress: explicit or mitm")
	logsCmd.Flags().String("status", "", "filter by status bucket: 2xx, 3xx, 4xx, 5xx, err")
	logsCmd.Flags().String("service", "", "filter by matched service host")
	logsCmd.Flags().Int("limit", 50, "number of logs to fetch (max 200)")
	logsCmd.Flags().Bool("tail", false, "poll for new request logs")
	logsCmd.Flags().Duration("interval", 2*time.Second, "poll interval for --tail")
	logsCmd.Flags().Bool("json", false, "print JSON")
	rootCmd.AddCommand(logsCmd)
}
