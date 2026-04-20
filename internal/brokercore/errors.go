package brokercore

import "errors"

var (
	// ErrInvalidSession means the supplied session token is missing, unknown,
	// or expired. Callers should return 401 (/proxy) or 407 (MITM).
	ErrInvalidSession = errors.New("brokercore: invalid or expired session")

	// ErrNoVaultContext means the session carries no vault scope and no hint
	// was provided (e.g. an agent token with zero vault grants).
	ErrNoVaultContext = errors.New("brokercore: session has no vault context")

	// ErrAgentVaultAmbiguous means an instance-level agent token with access
	// to multiple vaults did not specify which vault to use. Callers should
	// tell the user to set vault via the token:vault Basic auth form.
	ErrAgentVaultAmbiguous = errors.New("brokercore: agent has multiple vault grants; vault hint required")

	// ErrVaultHintMismatch means a scoped session was accompanied by a vault
	// hint that does not match the session's bound vault. Never silently
	// retarget a scoped session to a different vault.
	ErrVaultHintMismatch = errors.New("brokercore: vault hint does not match scoped session")

	// ErrVaultNotFound means the requested vault name does not exist.
	ErrVaultNotFound = errors.New("brokercore: vault not found")

	// ErrVaultAccessDenied means the actor exists but has no grant on the
	// requested vault.
	ErrVaultAccessDenied = errors.New("brokercore: actor has no access to vault")

	// ErrServiceNotFound means no configured broker service in the resolved
	// vault matches the target host. Callers surface 403 with a proposal hint.
	ErrServiceNotFound = errors.New("brokercore: no broker service matches target host")

	// ErrCredentialMissing means a credential referenced by the matched
	// service's auth config is not set or could not be decrypted. Callers
	// surface 502 so agents retry only after the credential is provisioned.
	ErrCredentialMissing = errors.New("brokercore: referenced credential missing or undecryptable")

	// ErrServiceDisabled means a configured broker service matched the
	// target host but has been toggled off by an operator. Distinct from
	// ErrServiceNotFound so agents can tell "configured but off" from "not
	// configured". Callers surface 403 with error code "service_disabled".
	ErrServiceDisabled = errors.New("brokercore: broker service is disabled")
)
