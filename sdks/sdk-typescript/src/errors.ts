/**
 * Base error class for all Agent Vault SDK errors.
 * Thrown for client-side issues (missing config, network failures, timeouts).
 */
export class AgentVaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentVaultError";
  }
}

/**
 * Error returned by the Agent Vault API.
 * Wraps HTTP error responses with status code, error code, and message.
 */
export class ApiError extends AgentVaultError {
  readonly status: number;
  readonly code: string;
  readonly headers: Headers;

  constructor({
    status,
    code,
    message,
    headers,
  }: {
    status: number;
    code: string;
    message: string;
    headers: Headers;
  }) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.headers = headers;
  }

  /**
   * Parse an API error from an HTTP response.
   *
   * Handles both server error formats:
   * - Standard: `{"error": "message"}`
   * - Proxy:    `{"error": "code", "message": "detail"}`
   */
  static async fromResponse(response: Response): Promise<ApiError> {
    let code = "unknown";
    let message = response.statusText;
    let proposalHint: ProposalHint | undefined;

    try {
      const body = await response.json();
      if (typeof body === "object" && body !== null) {
        const record = body as Record<string, unknown>;
        const errorField = record.error;
        const messageField = record.message;

        if (typeof errorField === "string") {
          code = errorField;
          message =
            typeof messageField === "string" ? messageField : errorField;
        }

        if (record.proposal_hint && typeof record.proposal_hint === "object") {
          const hint = record.proposal_hint as Record<string, unknown>;
          proposalHint = {
            host: hint.host as string,
            endpoint: hint.endpoint as string,
            supportedAuthTypes: hint.supported_auth_types as string[],
          };
        }
      }
    } catch {
      // Response body wasn't JSON — fall back to statusText
    }

    if (proposalHint) {
      return new ProxyForbiddenError({
        status: response.status,
        code,
        message,
        headers: response.headers,
        proposalHint,
      });
    }

    return new ApiError({
      status: response.status,
      code,
      message,
      headers: response.headers,
    });
  }
}

/** Structured hint returned by the broker when a proxy request is denied. */
export interface ProposalHint {
  host: string;
  endpoint: string;
  supportedAuthTypes: string[];
}

/**
 * Thrown when a proxy request is denied because no broker service matches the target host.
 * Contains a `proposalHint` with the information needed to create a proposal.
 */
export class ProxyForbiddenError extends ApiError {
  readonly proposalHint: ProposalHint;

  constructor({
    status,
    code,
    message,
    headers,
    proposalHint,
  }: {
    status: number;
    code: string;
    message: string;
    headers: Headers;
    proposalHint: ProposalHint;
  }) {
    super({ status, code, message, headers });
    this.name = "ProxyForbiddenError";
    this.proposalHint = proposalHint;
  }
}
