//go:build (!darwin && !linux) || !cgo

package acquisition

import (
	"context"

	"github.com/Infisical/agent-vault/internal/store"
)

func runPreparedProvider(
	_ context.Context,
	_ *PreparedExecutable,
	_ store.AcquisitionHandler,
	_ ProviderInvocation,
	_ *Frame,
	_ []byte,
) (*ProviderResult, error) {
	return nil, newProviderError("runner_unsupported", nil)
}
