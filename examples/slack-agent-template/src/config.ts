const fallback = (value: string | undefined, defaultValue: string) => {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : defaultValue;
};

const normalizeServerName = (value: string) => {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "_")
    .replace(/^[_-]+|[_-]+$/g, "");

  return normalized || "agent_tools";
};

export const agentConfig = {
  name: fallback(process.env.AGENT_NAME, "Vaulted Slack Agent"),
  description: fallback(
    process.env.AGENT_DESCRIPTION,
    "A custom Slack agent that routes outbound API calls through Agent Vault.",
  ),
  mission: fallback(
    process.env.AGENT_MISSION,
    "Help the team turn Slack requests into useful answers and actions using only the tools wired into this template.",
  ),
  audience: fallback(process.env.AGENT_AUDIENCE, "the Slack workspace where this agent is installed"),
  tone: fallback(process.env.AGENT_TONE, "practical, concise, and direct"),
  extraInstructions: fallback(process.env.AGENT_EXTRA_INSTRUCTIONS, ""),
  model: fallback(process.env.AGENT_MODEL, "claude-sonnet-4-6"),
  mcpServerName: normalizeServerName(fallback(process.env.AGENT_MCP_SERVER_NAME, "agent_tools")),
};
