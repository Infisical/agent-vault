package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/macosprovider"
)

func main() {
	if os.Getenv("AVSH_TICKET_FD") != "3" {
		fmt.Fprintln(os.Stderr, "provider_error")
		os.Exit(1)
	}
	socket := os.NewFile(3, "avsh-provider")
	if socket == nil {
		fmt.Fprintln(os.Stderr, "provider_error")
		os.Exit(1)
	}
	defer socket.Close()
	if err := macosprovider.New().Serve(context.Background(), socket, socket); err != nil {
		fmt.Fprintln(os.Stderr, "provider_error")
		os.Exit(1)
	}
}
