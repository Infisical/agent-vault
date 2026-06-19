import "dotenv/config";
import http from "node:http";
import { App } from "@slack/bolt";
import { WebClient } from "@slack/web-api";
import { HttpsProxyAgent } from "https-proxy-agent";
import { allowlistConfigured, isAllowedEmail } from "./access.js";
import { agentConfig } from "./config.js";
import { runAgent } from "./run-agent.js";
import { chunkText } from "./slack-format.js";
import { MAX_THREAD_CONTEXT_MESSAGES, formatThreadTranscript } from "./slack-transcript.js";

// @slack/web-api hard-codes `proxy: false` on its axios client, ignoring
// HTTPS_PROXY env vars. Pass an explicit agent so the agent-vault MITM proxy
// can intercept and substitute placeholder tokens. The same agent is reused for
// the one-off identity probe below.
const proxyUrl = process.env.HTTPS_PROXY;
const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : undefined;

// Behind Agent Vault, the real token lives only in the broker; the env holds a
// placeholder that the proxy swaps into the Authorization header. A token must
// never ride in the request body: @slack/web-api copies a per-call `token`
// argument into the form body, which the proxy cannot rewrite.
const identity = await new WebClient(process.env.SLACK_BOT_TOKEN, { agent }).auth.test();
const botUserId = identity.user_id;

// Supplying botId/botUserId and disabling token verification stops Bolt from
// making its own token-bearing auth.test calls at startup and per event.
const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  appToken: process.env.SLACK_APP_TOKEN,
  socketMode: true,
  tokenVerificationEnabled: false,
  botId: identity.bot_id,
  botUserId,
  clientOptions: { agent },
});

const stripBotMention = (text: string) =>
  botUserId ? text.replaceAll(`<@${botUserId}>`, "").trim() : text.trim();

if (allowlistConfigured()) {
  console.log("Slack email allowlist is enabled via AGENT_ALLOWLIST");
}

// Resolving a Slack user id to email costs an API call, so cache it per process.
const emailCache = new Map<string, string | undefined>();

async function resolveEmail(
  client: InstanceType<typeof App>["client"],
  userId: string | undefined,
): Promise<string | undefined> {
  if (!allowlistConfigured()) return undefined;
  if (!userId) return undefined;
  if (emailCache.has(userId)) return emailCache.get(userId);

  try {
    // No per-call `token` arg: behind Agent Vault that would land in the
    // request body, which the proxy cannot rewrite. The client-level token rides
    // in the header.
    const info = await client.users.info({ user: userId });
    const email = info.user?.profile?.email;
    emailCache.set(userId, email);
    return email;
  } catch (err) {
    const code = (err as { data?: { error?: string } })?.data?.error;
    console.error(`Failed to resolve user email${code ? ` (${code})` : ""}:`, err);
    return undefined;
  }
}

async function isAuthorized(
  client: InstanceType<typeof App>["client"],
  userId: string | undefined,
  channel: string,
  threadTs: string,
): Promise<boolean> {
  if (!allowlistConfigured()) return true;

  const email = await resolveEmail(client, userId);
  if (isAllowedEmail(email)) return true;

  await client.chat
    .postMessage({
      channel,
      thread_ts: threadTs,
      text: `Sorry, ${agentConfig.name} is only available to approved users right now.`,
    })
    .catch(() => {});
  return false;
}

async function handleMessage(
  text: string,
  channel: string,
  threadTs: string,
  isThreadReply: boolean,
  client: InstanceType<typeof App>["client"],
) {
  const userMessage = stripBotMention(text);

  if (!userMessage) {
    await client.chat.postMessage({
      channel,
      thread_ts: threadTs,
      text: `Hey, I am ${agentConfig.name}. How can I help?`,
    });
    return;
  }

  // First-in-thread messages have no history to fetch, so skip the API call.
  // For replies, fetch history in parallel with posting the thinking placeholder.
  const historyPromise = isThreadReply
    ? client.conversations
        .replies({ channel, ts: threadTs, limit: MAX_THREAD_CONTEXT_MESSAGES })
        .catch((err) => {
          // Surface Slack error codes like missing_scope and not_in_channel.
          const code = (err as { data?: { error?: string } })?.data?.error;
          console.error(`Failed to fetch thread history${code ? ` (${code})` : ""}:`, err);
          return undefined;
        })
    : Promise.resolve(undefined);

  const thinkingPromise = client.chat.postMessage({
    channel,
    thread_ts: threadTs,
    text: "Thinking...",
  });

  const [history, thinking] = await Promise.all([historyPromise, thinkingPromise]);

  const thinkingTs = thinking.ts;
  if (!thinkingTs) {
    console.error("Failed to post thinking message");
    return;
  }

  const transcript = formatThreadTranscript(history?.messages ?? [], {
    agentName: agentConfig.name,
    botUserId,
  });

  // Always append userMessage explicitly: conversations.replies returns the
  // oldest N messages, so on a long thread the triggering message itself can
  // fall outside the window. Slight redundancy in the common case is fine.
  const prompt = transcript
    ? `Conversation in this Slack thread so far:\n\n${transcript}\n\nRespond to this latest message: ${userMessage}`
    : userMessage;

  try {
    let lastProgress = "";
    const response = await runAgent(prompt, (progress) => {
      if (progress === lastProgress) return;
      lastProgress = progress;
      client.chat.update({ channel, ts: thinkingTs, text: progress }).catch(() => {});
    });

    const answer = response || "I couldn't find an answer. Try rephrasing your question.";
    const chunks = chunkText(answer);
    await client.chat.update({ channel, ts: thinkingTs, text: chunks[0] });
    for (const chunk of chunks.slice(1)) {
      await client.chat.postMessage({ channel, thread_ts: threadTs, text: chunk });
    }
  } catch (error) {
    console.error("Agent error:", error);
    try {
      await client.chat.update({
        channel,
        ts: thinkingTs,
        text: ":warning: Sorry, I ran into an error. Please try again.",
      });
    } catch (updateError) {
      console.error("Failed to update error message:", updateError);
    }
  }
}

// Handle @mentions in channels
app.event("app_mention", async ({ event, client }) => {
  const threadTs = event.thread_ts ?? event.ts;
  if (!(await isAuthorized(client, event.user, event.channel, threadTs))) return;
  await handleMessage(event.text, event.channel, threadTs, event.thread_ts !== undefined, client);
});

// Handle direct messages
app.event("message", async ({ event, client }) => {
  if (event.channel_type !== "im") return;
  if (event.subtype) return;
  const eventThreadTs = (event as { thread_ts?: string }).thread_ts;
  const threadTs = eventThreadTs ?? event.ts;
  const userId = (event as { user?: string }).user;
  if (!(await isAuthorized(client, userId, event.channel, threadTs))) return;
  await handleMessage(event.text ?? "", event.channel, threadTs, eventThreadTs !== undefined, client);
});

const port = Number(process.env.PORT) || 3000;
http
  .createServer((req, res) => {
    const pathname = (req.url ?? "/").split("?", 1)[0].replace(/\/+$/, "") || "/";
    if (pathname === "/" || pathname === "/health") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
      return;
    }
    res.writeHead(404);
    res.end();
  })
  .listen(port, () => {
    console.log(`HTTP server listening on :${port}`);
  });

await app.start();
console.log(`${agentConfig.name} is running in Socket Mode`);
