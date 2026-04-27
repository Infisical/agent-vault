package cmd

import "fmt"

// ExitCodeError carries a specific process exit code through the Cobra
// RunE return path. Execute() unwraps it and calls os.Exit(Code) so
// wrapped subprocesses (e.g. the isolation container) can propagate their
// real status to the shell without losing deferred cleanups — returning
// the error lets defers inside the command body run before the process
// exits.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("exited with status %d", e.Code)
}
