package cmd

import "fmt"

// IsolationMode selects how `vault run` runs the child agent.
type IsolationMode string

const (
	IsolationHost      IsolationMode = "host"
	IsolationContainer IsolationMode = "container"
)

func (m *IsolationMode) String() string {
	if *m == "" {
		return string(IsolationHost)
	}
	return string(*m)
}

func (m *IsolationMode) Set(v string) error {
	switch IsolationMode(v) {
	case IsolationHost, IsolationContainer:
		*m = IsolationMode(v)
		return nil
	default:
		return fmt.Errorf("must be one of: %s, %s", IsolationHost, IsolationContainer)
	}
}

func (*IsolationMode) Type() string { return "string" }
