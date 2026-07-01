export const MAX_THREAD_CONTEXT_MESSAGES = 50;
export const MAX_THREAD_CONTEXT_CHARS = 12000;
export const MAX_THREAD_MESSAGE_CHARS = 1200;

export type SlackTranscriptMessage = {
  text?: string;
  user?: string;
  bot_id?: string;
};

type TranscriptOptions = {
  agentName: string;
  botUserId?: string;
  maxMessages?: number;
  maxChars?: number;
  maxMessageChars?: number;
};

function stripBotMention(text: string, botUserId?: string) {
  return botUserId ? text.replaceAll(`<@${botUserId}>`, "").trim() : text.trim();
}

function truncate(value: string, maxChars: number) {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, Math.max(0, maxChars - 3))}...`;
}

export function formatThreadTranscript(
  messages: SlackTranscriptMessage[],
  {
    agentName,
    botUserId,
    maxMessages = MAX_THREAD_CONTEXT_MESSAGES,
    maxChars = MAX_THREAD_CONTEXT_CHARS,
    maxMessageChars = MAX_THREAD_MESSAGE_CHARS,
  }: TranscriptOptions,
): string {
  const textMessages = messages.filter((message) => Boolean(message.text));
  const consideredMessages = textMessages.slice(-maxMessages);
  const lines = consideredMessages
    .map((message) => {
      const cleanText = stripBotMention(message.text ?? "", botUserId);
      if (!cleanText) return "";

      const isBot = (botUserId && message.user === botUserId) || Boolean(message.bot_id);
      const speaker = isBot ? agentName : `<@${message.user ?? "unknown"}>`;
      return `${speaker}: ${truncate(cleanText, maxMessageChars)}`;
    })
    .filter(Boolean);

  const keptLines: string[] = [];
  let usedChars = 0;

  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i]!;
    const additionalChars = line.length + (keptLines.length ? 1 : 0);
    if (keptLines.length && usedChars + additionalChars > maxChars) break;
    if (!keptLines.length && line.length > maxChars) {
      keptLines.unshift(truncate(line, maxChars));
      usedChars = maxChars;
      break;
    }
    keptLines.unshift(line);
    usedChars += additionalChars;
  }

  const omittedByMessageCount = textMessages.length > consideredMessages.length;
  const omittedByCharCount = keptLines.length < lines.length;
  const transcript = keptLines.join("\n");

  if (!transcript) return "";
  if (!omittedByMessageCount && !omittedByCharCount) return transcript;
  return `[Earlier thread context omitted for length.]\n${transcript}`;
}
