package cmd

import "fmt"

// SandboxMode selects how `vault run` isolates the child agent.
type SandboxMode string

const (
	SandboxProcess   SandboxMode = "process"
	SandboxContainer SandboxMode = "container"
)

func (m *SandboxMode) String() string {
	if *m == "" {
		return string(SandboxProcess)
	}
	return string(*m)
}

func (m *SandboxMode) Set(v string) error {
	switch SandboxMode(v) {
	case SandboxProcess, SandboxContainer:
		*m = SandboxMode(v)
		return nil
	default:
		return fmt.Errorf("must be one of: process, container")
	}
}

func (*SandboxMode) Type() string { return "string" }
