package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

// loadSession loads the client session or returns an error prompting login.
func loadSession() (*session.ClientSession, error) {
	sess, err := session.Load()
	if err != nil {
		return nil, fmt.Errorf("loading session: %w", err)
	}
	if sess == nil {
		return nil, fmt.Errorf("not logged in, run 'agent-vault login' first")
	}
	return sess, nil
}

// resolveVault returns the target vault using: --vault flag > context file > "default".
func resolveVault(cmd *cobra.Command) string {
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name
	}
	if ctx := session.LoadVaultContext(); ctx != "" {
		return ctx
	}
	return store.DefaultVault
}

// doAdminRequestWithBody makes an authenticated HTTP request to the server and returns the response body.
func doAdminRequestWithBody(method, url, token string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("%s", errResp.Error)
		}
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return respBody, nil
}

// doAdminRequest makes an authenticated HTTP request to the server and checks for errors.
func doAdminRequest(method, url, token string, body []byte) error {
	_, err := doAdminRequestWithBody(method, url, token, body)
	return err
}

// stopServer sends SIGTERM to a running server process and waits for it to exit.
// Returns nil if no server is running.
func stopServer() error {
	pid, err := pidfile.Read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading PID file: %w", err)
	}

	if !pidfile.IsRunning(pid) {
		_ = pidfile.Remove()
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding server process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending SIGTERM to server process %d: %w", pid, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !pidfile.IsRunning(pid) {
			_ = pidfile.Remove()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	return fmt.Errorf("server process %d did not exit within 10 seconds; you may need to kill it manually", pid)
}
