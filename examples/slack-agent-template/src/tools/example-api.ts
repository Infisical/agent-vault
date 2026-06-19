import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

const DEFAULT_MAX_BODY_CHARS = 4000;
const USER_AGENT = process.env.EXAMPLE_API_USER_AGENT?.trim() || "agent-vault-slack-template";

export function normalizeExampleApiPath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed.startsWith("/")) {
    throw new Error("Path must start with '/'.");
  }
  if (trimmed.includes("://") || trimmed.includes("..")) {
    throw new Error("Path must be a relative API path without schemes or traversal.");
  }
  return trimmed;
}

export function buildExampleApiUrl(path: string, baseUrl = process.env.EXAMPLE_API_BASE_URL): URL {
  const trimmedBaseUrl = baseUrl?.trim();
  if (!trimmedBaseUrl) {
    throw new Error("EXAMPLE_API_BASE_URL is not set.");
  }

  const base = new URL(trimmedBaseUrl);
  const normalizedPath = normalizeExampleApiPath(path);
  const requested = new URL(`https://example.invalid${normalizedPath}`);
  const basePath = base.pathname.replace(/\/+$/, "");

  base.pathname = `${basePath}${requested.pathname}`;
  base.search = requested.search;
  base.hash = "";
  return base;
}

function truncateBody(body: string, maxChars = DEFAULT_MAX_BODY_CHARS): string {
  return body.length <= maxChars ? body : `${body.slice(0, maxChars - 3)}...`;
}

async function responseBodyText(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") ?? "";
  const raw = await response.text();
  if (!raw) return "";

  if (contentType.includes("application/json")) {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }

  return raw;
}

export const exampleApiGet = tool(
  "example_api_get",
  "Example read-only HTTP GET tool. Configure EXAMPLE_API_BASE_URL, then replace or adapt this for your agent's API.",
  {
    path: z
      .string()
      .min(1)
      .max(200)
      .default("/")
      .describe("Relative API path to fetch from EXAMPLE_API_BASE_URL. Must start with '/'."),
  },
  async ({ path }) => {
    let url: URL;
    try {
      url = buildExampleApiUrl(path);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: "text" as const,
            text: `${message} Set EXAMPLE_API_BASE_URL or replace this example tool with an agent-specific tool.`,
          },
        ],
      };
    }

    const response = await fetch(url, {
      method: "GET",
      redirect: "error",
      headers: {
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
    });

    const body = truncateBody(await responseBodyText(response));
    return {
      content: [
        {
          type: "text" as const,
          text: [
            `GET ${url}`,
            `Status: ${response.status} ${response.statusText}`,
            body ? `Body:\n${body}` : "Body: <empty>",
          ].join("\n"),
        },
      ],
    };
  },
);
