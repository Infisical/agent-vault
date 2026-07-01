import "dotenv/config";
import { runAgent } from "./run-agent.js";

const prompt = process.argv[2] || "Say hello and tell me what tools you have available.";

console.log(`\nPrompt: ${prompt}\n`);
try {
  const response = await runAgent(prompt);
  console.log(response);
} catch (error) {
  console.error("Agent error:", error);
  process.exit(1);
}
