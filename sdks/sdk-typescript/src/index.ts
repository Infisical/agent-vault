// Clients
export { AgentVault } from "./client.js";
export { VaultClient } from "./vault.js";

// Errors
export { AgentVaultError, ApiError } from "./errors.js";

// Config types
export type { AgentVaultConfig, VaultClientConfig, ClientConfig } from "./types.js";

// Session resource types
export type { CreateSessionOptions, Session } from "./resources/sessions.js";

// Vault types (instance-level operations)
export type { CreateVaultOptions, Vault, DeleteVaultResult } from "./client.js";
