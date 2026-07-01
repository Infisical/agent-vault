import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

// TODO: replace this placeholder with a real tool. Tools typically call an
// external API — when run behind agent-vault, credentials are injected into
// outgoing HTTPS requests transparently via the HTTPS_PROXY env var.
export const echo = tool(
  "echo",
  "Echo back the provided message. Placeholder tool — replace with your own.",
  {
    message: z.string().describe("The message to echo back"),
  },
  async (args) => ({
    content: [{ type: "text" as const, text: `Echo: ${args.message}` }],
  }),
);
