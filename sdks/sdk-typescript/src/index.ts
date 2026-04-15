// Clients
export { AgentVault } from "./client.js";
export { VaultClient } from "./vault.js";

// Errors
export { AgentVaultError, ApiError } from "./errors.js";

// Config types
export type { AgentVaultConfig, VaultClientConfig, ClientConfig } from "./types.js";

// Entity types
export type {
  Vault,
  Credential,
  Service,
  ServiceAuth,
  DiscoverResponse,
  DiscoverService,
  Proposal,
  ProposalService,
  ProposalCredentialSlot,
} from "./types.js";

// Session resource types
export type { CreateSessionOptions, Session } from "./resources/sessions.js";
