import type { HttpClient } from "../http.js";
import type {
  CredentialsList,
  CredentialsSet,
  CredentialsDeleted,
} from "../types.js";

/**
 * Options for listing credentials.
 *
 * The `key` filter is only accepted when `reveal` is `true` — the server
 * ignores it otherwise. The union type enforces this at compile time.
 */
export type ListCredentialsOptions =
  | { reveal?: false; key?: never }
  | { reveal: true; key?: string };

/**
 * A credential entry with its decrypted value.
 */
export interface Credential {
  /** Credential key (SCREAMING_SNAKE_CASE). */
  key: string;
  /** Decrypted credential value. */
  value: string;
}

/**
 * Result of listing credentials.
 */
export interface ListCredentialsResult {
  /** All credential key names in the vault. */
  keys: string[];
  /** Decrypted credentials (only present when reveal was requested). */
  credentials?: Credential[];
}

/**
 * Result of setting credentials.
 */
export interface SetCredentialsResult {
  /** Keys that were set. */
  set: string[];
}

/**
 * Result of deleting credentials.
 */
export interface DeleteCredentialsResult {
  /** Keys that were deleted. */
  deleted: string[];
}

/**
 * Resource for managing vault credentials (secrets).
 * Maps to `GET/POST/DELETE /v1/credentials`.
 */
export class CredentialsResource {
  constructor(
    private readonly httpClient: HttpClient,
    private readonly vaultName: string | undefined,
  ) {}

  /**
   * List credential keys, optionally revealing their decrypted values.
   *
   * Without `reveal`, returns only key names (requires proxy+ role).
   * With `reveal: true`, returns decrypted values (requires member+ role).
   * With `reveal: true` and `key`, returns a single credential.
   *
   * @throws {ApiError} 403 if the caller lacks sufficient permissions.
   * @throws {ApiError} 404 if the vault or credential is not found.
   */
  async list(options?: ListCredentialsOptions): Promise<ListCredentialsResult> {
    const query: Record<string, string> = {};
    if (this.vaultName) {
      query.vault = this.vaultName;
    }
    if (options?.reveal) {
      query.reveal = "true";
    }
    if (options?.key) {
      query.key = options.key;
    }

    const res = await this.httpClient.get<CredentialsList>("/v1/credentials", {
      query,
    });

    return {
      keys: res.keys,
      credentials: res.credentials?.map((c) => ({
        key: c.key,
        value: c.value ?? "",
      })),
    };
  }

  /**
   * Set one or more credentials in the vault.
   *
   * Keys must be SCREAMING_SNAKE_CASE (`^[A-Z][A-Z0-9_]*$`).
   * Existing credentials with the same key are overwritten.
   * Requires member+ role.
   *
   * @param credentials - Map of credential key to plaintext value.
   * @throws {ApiError} 400 if any key fails validation or credentials map is empty.
   * @throws {ApiError} 403 if the caller lacks sufficient permissions.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async set(
    credentials: Record<string, string>,
  ): Promise<SetCredentialsResult> {
    const body: Record<string, unknown> = { credentials };
    if (this.vaultName) {
      body.vault = this.vaultName;
    }

    const res = await this.httpClient.post<CredentialsSet>(
      "/v1/credentials",
      body,
    );

    return { set: res.set };
  }

  /**
   * Delete one or more credentials from the vault.
   *
   * Keys must be SCREAMING_SNAKE_CASE (`^[A-Z][A-Z0-9_]*$`).
   * Requires member+ role.
   *
   * @param keys - Credential keys to delete.
   * @throws {ApiError} 400 if any key fails validation or keys array is empty.
   * @throws {ApiError} 403 if the caller lacks sufficient permissions.
   * @throws {ApiError} 404 if the vault is not found.
   */
  async delete(keys: string[]): Promise<DeleteCredentialsResult> {
    const body: Record<string, unknown> = { keys };
    if (this.vaultName) {
      body.vault = this.vaultName;
    }

    const res = await this.httpClient.del<CredentialsDeleted>(
      "/v1/credentials",
      body,
    );

    return { deleted: res.deleted };
  }
}
