// Clients
export { AgentVault } from "./client.js";
export { VaultClient } from "./vault.js";

// Errors
export { AgentVaultError, ApiError, ProxyForbiddenError } from "./errors.js";
export type { ProposalHint } from "./errors.js";

// Config types
export type { AgentVaultConfig, VaultClientConfig, ClientConfig } from "./types.js";

// Session resource types
export type { CreateSessionOptions, Session, ContainerConfig } from "./resources/sessions.js";
export { buildProxyEnv } from "./resources/sessions.js";

// Vault types (instance-level operations)
export type { CreateVaultOptions, Vault, DeleteVaultResult } from "./client.js";

// Credential resource types
export type {
  ListCredentialsOptions,
  Credential,
  ListCredentialsResult,
  SetCredentialsResult,
  DeleteCredentialsResult,
} from "./resources/credentials.js";

// Proxy resource types
export type {
  ProxyRequestOptions,
  ProxyResponse,
} from "./resources/proxy.js";

// Service resource types
export type {
  BearerAuth,
  BasicAuth,
  ApiKeyAuth,
  CustomAuth,
  ServiceAuth,
  Service,
  ListServicesResult,
  SetServicesResult,
  ReplaceAllServicesResult,
  ClearServicesResult,
  RemoveServiceResult,
  CredentialUsageEntry,
  CredentialUsageResult,
} from "./resources/services.js";
