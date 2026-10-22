package macosprovider

import (
	"context"
	"errors"
	"os/exec"
)

var errOutputLimit = errors.New("provider command output limit exceeded")

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, path string, args, env []string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = append([]string(nil), env...)
	command.Dir = "/"
	stdout := &boundedOutput{value: make([]byte, 0, maxCommandOutput), limit: maxCommandOutput}
	stderr := &boundedOutput{value: make([]byte, 0, maxCommandOutput), limit: maxCommandOutput}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	if err != nil {
		out, diagnostic := stdout.value, stderr.value
		if errors.Is(err, errOutputLimit) || stdout.exceeded || stderr.exceeded {
			wipe(out)
			wipe(diagnostic)
			return nil, nil, errOutputLimit
		}
		return out, diagnostic, err
	}
	return stdout.value, stderr.value, nil
}

type boundedOutput struct {
	value    []byte
	limit    int
	exceeded bool
}

func (b *boundedOutput) Write(value []byte) (int, error) {
	if len(value) > b.limit-len(b.value) {
		b.exceeded = true
		return 0, errOutputLimit
	}
	b.value = append(b.value, value...)
	return len(value), nil
}
