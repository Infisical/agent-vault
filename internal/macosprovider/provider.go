package macosprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Infisical/agent-vault/internal/acquisition"
)

const (
	ProfileGitHubCom       = "github.com"
	ProfileAgentVaultLocal = "agent-vault-local"
	GitHubCLIPath          = "/opt/homebrew/bin/gh"
	maxCommandOutput       = acquisition.MaxSecretBytes
)

var errProviderRejected = errors.New("provider request rejected")

type commandRunner interface {
	Run(context.Context, string, []string, []string) ([]byte, []byte, error)
}

type keychain interface {
	CopyMatching(context.Context, KeychainItem) ([]byte, error)
}

type profileKind uint8

const (
	profileGitHubCLI profileKind = iota + 1
	profileKeychain
)

// Profile recipes are compiled into the provider. The wire request selects a
// recipe ID only; it cannot provide a command, service, account, access group,
// or environment override.
type profileRecipe struct {
	kind   profileKind
	item   KeychainItem
	source string
}

var profileRecipes = map[string]profileRecipe{
	ProfileGitHubCom: {kind: profileGitHubCLI, source: "github-cli"},
	ProfileAgentVaultLocal: {
		kind:   profileKeychain,
		item:   KeychainItem{Service: "agent-vault", Account: "credential", AllowUserInteraction: true},
		source: "macos-keychain",
	},
}

// Provider implements the client side of the server-created AVSH/1 socket.
// Dependencies are private interfaces so tests can use hermetic fakes.
type Provider struct {
	commands commandRunner
	keychain keychain
	ghPath   string
	home     string
	user     string
	now      func() time.Time
}

func New() *Provider {
	return &Provider{
		commands: execCommandRunner{}, keychain: platformKeychain{}, ghPath: GitHubCLIPath,
		home: os.Getenv("HOME"), user: os.Getenv("USER"), now: time.Now,
	}
}

// Serve handles exactly one request and emits only AVSH/1 protocol messages.
// Diagnostics and underlying command/keychain errors are intentionally
// discarded; callers should report only the stable provider_error code.
func (p *Provider) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	if p == nil || input == nil || output == nil || ctx == nil {
		return errProviderRejected
	}
	request, err := acquisition.ReadProviderRequest(input)
	if err != nil {
		return errProviderRejected
	}
	defer acquisition.DestroyProviderRequest(&request)
	if err := ctx.Err(); err != nil {
		return errProviderRejected
	}
	if !onlyProviderParams(request.Params) || request.Params["mode"] != "native" {
		return errProviderRejected
	}
	profileID := request.Params["profile"]
	recipe, ok := profileRecipes[profileID]
	if !ok {
		return errProviderRejected
	}
	var secretBytes []byte
	switch recipe.kind {
	case profileGitHubCLI:
		if profileID != ProfileGitHubCom || recipe.source != "github-cli" {
			return errProviderRejected
		}
		secretBytes, err = p.acquireGitHub(ctx, profileID)
	case profileKeychain:
		if p.keychain == nil || recipe.item.Service == "" || recipe.item.Account == "" {
			return errProviderRejected
		}
		secretBytes, err = p.keychain.CopyMatching(ctx, recipe.item)
	default:
		return errProviderRejected
	}
	if err != nil || len(secretBytes) == 0 || len(secretBytes) > acquisition.MaxSecretBytes {
		wipe(secretBytes)
		return errProviderRejected
	}
	defer wipe(secretBytes)
	secret, err := acquisition.NewSecretBuffer(secretBytes)
	if err != nil {
		return errProviderRejected
	}
	defer secret.Destroy()
	if p.now == nil {
		return errProviderRejected
	}
	reply := acquisition.Reply{
		Kind: acquisition.MessageReply, Ticket: request.Ticket,
		ContextBindingID: request.ContextBindingID, Secret: secret,
		Meta: acquisition.ReplyMeta{IssuedAtUnix: p.now().Unix(), Source: recipe.source},
	}
	if reply.Meta.IssuedAtUnix <= 0 {
		return errProviderRejected
	}
	if err := acquisition.WriteProviderReply(output, reply); err != nil {
		return errProviderRejected
	}
	return nil
}

func onlyProviderParams(params map[string]string) bool {
	if len(params) != 2 {
		return false
	}
	_, hasProfile := params["profile"]
	_, hasMode := params["mode"]
	return hasProfile && hasMode
}

func (p *Provider) acquireGitHub(ctx context.Context, profileID string) ([]byte, error) {
	if profileID != ProfileGitHubCom || p.commands == nil || p.ghPath != GitHubCLIPath && !filepath.IsAbs(p.ghPath) {
		return nil, errProviderRejected
	}
	env, err := p.sanitizedEnvironment()
	if err != nil {
		return nil, errProviderRejected
	}
	// The host comes only from the compiled profile. Validate the host session
	// before asking gh to emit the token.
	statusOut, statusErrOut, statusErr := p.commands.Run(ctx, p.ghPath,
		[]string{"auth", "status", "--hostname", "github.com"}, env)
	wipe(statusOut)
	wipe(statusErrOut)
	if statusErr != nil || ctx.Err() != nil {
		return nil, errProviderRejected
	}
	tokenOut, tokenErrOut, tokenErr := p.commands.Run(ctx, p.ghPath,
		[]string{"auth", "token", "--hostname", "github.com"}, env)
	wipe(tokenErrOut)
	if tokenErr != nil || ctx.Err() != nil {
		wipe(tokenOut)
		return nil, errProviderRejected
	}
	if err := trimGitHubTokenOutput(&tokenOut); err != nil {
		wipe(tokenOut)
		return nil, errProviderRejected
	}
	return tokenOut, nil
}

func (p *Provider) sanitizedEnvironment() ([]string, error) {
	if !filepath.IsAbs(p.home) || p.home == "/" || strings.ContainsAny(p.home, "\x00\n\r") ||
		p.user == "" || strings.ContainsAny(p.user, "=\x00\n\r") {
		return nil, fmt.Errorf("invalid provider identity")
	}
	env := []string{"GH_NO_UPDATE_NOTIFIER=1", "HOME=" + p.home, "LANG=C", "PATH=/usr/bin:/bin", "USER=" + p.user}
	sort.Strings(env)
	return env, nil
}

func trimGitHubTokenOutput(value *[]byte) error {
	if value == nil || len(*value) == 0 || len(*value) > maxCommandOutput {
		return errProviderRejected
	}
	data := *value
	if data[len(data)-1] == '\n' {
		data[len(data)-1] = 0
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data[len(data)-1] = 0
			data = data[:len(data)-1]
		}
	}
	if len(data) == 0 || len(data) > acquisition.MaxSecretBytes {
		return errProviderRejected
	}
	for _, b := range data {
		if unicode.IsControl(rune(b)) || b == ' ' || b == '\t' {
			return errProviderRejected
		}
	}
	*value = data
	return nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
