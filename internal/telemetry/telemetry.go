package telemetry

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/posthog/posthog-go"
)

type Telemetry struct {
	client  posthog.Client
	version string
}

type noopLogger struct{}

func (noopLogger) Logf(string, ...interface{})   {}
func (noopLogger) Debugf(string, ...interface{}) {}
func (noopLogger) Warnf(string, ...interface{})  {}
func (noopLogger) Errorf(string, ...interface{}) {}

// New creates a Telemetry client. Returns nil when apiKey is empty
// (dev builds), making all methods safe to call on a nil receiver.
func New(apiKey, version string) *Telemetry {
	if apiKey == "" {
		return nil
	}
	client, _ := posthog.NewWithConfig(apiKey, posthog.Config{
		Logger:   noopLogger{},
		Interval: 30 * time.Second,
	})
	return &Telemetry{client: client, version: version}
}

func (t *Telemetry) CaptureEvent(distinctID, event string, properties map[string]string) {
	if t == nil || t.client == nil {
		return
	}
	props := posthog.NewProperties()
	props.Set("version", t.version)
	for k, v := range properties {
		props.Set(k, v)
	}
	_ = t.client.Enqueue(posthog.Capture{
		DistinctId: distinctID,
		Event:      event,
		Properties: props,
	})
}

func (t *Telemetry) Identify(distinctID string, properties map[string]string) {
	if t == nil || t.client == nil {
		return
	}
	props := posthog.NewProperties()
	for k, v := range properties {
		props.Set(k, v)
	}
	_ = t.client.Enqueue(posthog.Identify{
		DistinctId: distinctID,
		Properties: props,
	})
}

func (t *Telemetry) Alias(distinctID, alias string) {
	if t == nil || t.client == nil || alias == "" {
		return
	}
	_ = t.client.Enqueue(posthog.Alias{
		DistinctId: distinctID,
		Alias:      alias,
	})
}

func (t *Telemetry) Close() {
	if t == nil || t.client == nil {
		return
	}
	_ = t.client.Close()
}

// IsDisabled returns true when the AGENT_VAULT_TELEMETRY env var is
// set to "false" or "0".
func IsDisabled() bool {
	v := strings.ToLower(os.Getenv("AGENT_VAULT_TELEMETRY"))
	return v == "false" || v == "0"
}

var (
	machineIDOnce  sync.Once
	machineIDValue string
)

// MachineID returns a stable anonymous identifier for the current
// machine. Falls back to a hostname-derived hash when /etc/machine-id
// is unavailable (e.g. minimal Docker containers).
func MachineID() string {
	machineIDOnce.Do(func() {
		if mid, err := machineid.ProtectedID("agent-vault"); err == nil && mid != "" {
			machineIDValue = "anonymous_agent_vault_" + mid
			return
		}
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			h := sha256.Sum256([]byte(hostname))
			machineIDValue = fmt.Sprintf("anonymous_agent_vault_%x", h[:8])
			return
		}
	})
	return machineIDValue
}
