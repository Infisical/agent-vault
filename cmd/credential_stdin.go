package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const maxCredentialStdinBytes = 64 * 1024

var credentialStdinIsTerminal = func(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func readCredentialStdin(cmd *cobra.Command, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("stdin credential key is required")
	}
	reader := cmd.InOrStdin()
	if credentialStdinIsTerminal(reader) {
		return "", fmt.Errorf("credential stdin must be a pipe or redirected file, not an interactive terminal")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxCredentialStdinBytes+1))
	defer clear(raw)
	if err != nil {
		return "", fmt.Errorf("reading credential from stdin: %w", err)
	}
	if len(raw) > maxCredentialStdinBytes {
		return "", fmt.Errorf("credential from stdin exceeds %d bytes", maxCredentialStdinBytes)
	}
	value := raw
	if bytes.HasSuffix(value, []byte("\n")) {
		value = bytes.TrimSuffix(value, []byte("\n"))
		value = bytes.TrimSuffix(value, []byte("\r"))
	}
	if len(value) == 0 {
		return "", fmt.Errorf("credential from stdin is empty")
	}
	if !utf8.Valid(value) {
		return "", fmt.Errorf("credential from stdin must be valid UTF-8")
	}
	return string(value), nil
}
