package cmd

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCodeError_Error(t *testing.T) {
	e := &ExitCodeError{Code: 42}
	if got := e.Error(); got != "exited with status 42" {
		t.Errorf("Error() = %q, want %q", got, "exited with status 42")
	}
}

func TestExitCodeError_ErrorsAs(t *testing.T) {
	inner := &ExitCodeError{Code: 7}
	wrapped := fmt.Errorf("runContainer: %w", inner)
	var got *ExitCodeError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As failed to unwrap ExitCodeError through fmt.Errorf wrap")
	}
	if got.Code != 7 {
		t.Errorf("unwrapped Code = %d, want 7", got.Code)
	}
}
