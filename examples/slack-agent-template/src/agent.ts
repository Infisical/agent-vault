import { createSdkMcpServer } from "@anthropic-ai/claude-agent-sdk";
import { agentConfig } from "./config.js";
import { echo } from "./tools/echo.js";
import { exampleApiGet } from "./tools/example-api.js";

// Tools are exposed as mcp__<server-name>__<tool-name>. run-agent.ts registers
// every server in this registry and derives allowedTools from its keys.
export const templateServer = createSdkMcpServer({
  name: agentConfig.mcpServerName,
  version: "1.0.0",
  tools: [echo, exampleApiGet],
});

export const mcpServers = {
  [agentConfig.mcpServerName]: templateServer,
};
