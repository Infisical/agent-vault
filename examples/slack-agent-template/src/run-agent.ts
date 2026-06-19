import { query } from "@anthropic-ai/claude-agent-sdk";
import { mcpServers } from "./agent.js";
import { agentConfig } from "./config.js";
import { AGENT_SYSTEM_PROMPT } from "./personality.js";

// Allow every tool on every registered service server (mcp__<service>__*).
const allowedTools = Object.keys(mcpServers).map((name) => `mcp__${name}__*`);

// TODO: customize per-tool progress labels by switching on `toolName`.
// Example:
//   case "mcp__agent_tools__example_api_get": return ":mag: Checking the API...";
function toolProgressLabel(toolName: string, _input: Record<string, unknown>): string | null {
  if (toolName.endsWith("__example_api_get")) {
    return ":mag: Checking the API...";
  }
  return ":hourglass_flowing_sand: Working...";
}

export async function runAgent(
  prompt: string,
  onProgress?: (message: string) => void,
): Promise<string> {
  let result = "";

  for await (const event of query({
    prompt,
    options: {
      model: agentConfig.model,
      // Workaround for anthropics/claude-agent-sdk-typescript#296. Set in Dockerfile.
      pathToClaudeCodeExecutable: process.env.CLAUDE_CODE_EXECUTABLE,
      systemPrompt: AGENT_SYSTEM_PROMPT,
      mcpServers,
      allowedTools,
      tools: [],
      permissionMode: "bypassPermissions",
      persistSession: false,
    },
  })) {
    if (event.type === "assistant" && onProgress) {
      for (const block of event.message.content) {
        if (block.type === "tool_use") {
          const label = toolProgressLabel(block.name, block.input as Record<string, unknown>);
          if (label) onProgress(label);
        }
      }
    }

    if (event.type === "result" && event.subtype === "success") {
      result = event.result;
    }
  }

  return result;
}
