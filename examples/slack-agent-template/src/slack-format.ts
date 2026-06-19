// Pure Slack text-formatting helpers. Kept free of side effects so they can be
// unit-tested without standing up the Bolt app.

// Slack rejects messages over 40,000 chars with msg_too_long, and visually
// collapses very long ones. Chunk well under that, breaking on line boundaries
// so a long answer splits between paragraphs rather than mid-line.
export const SLACK_MAX_CHARS = 3900;

/**
 * Split text into chunks no longer than `max`, breaking on line boundaries.
 * A single line longer than `max` is hard-split. Always returns at least one
 * chunk, with the empty string for empty input.
 */
export function chunkText(text: string, max = SLACK_MAX_CHARS): string[] {
  const chunks: string[] = [];
  let current = "";

  for (const line of text.split("\n")) {
    if (line.length > max) {
      if (current) {
        chunks.push(current);
        current = "";
      }
      for (let i = 0; i < line.length; i += max) chunks.push(line.slice(i, i + max));
      continue;
    }

    if (current && current.length + line.length + 1 > max) {
      chunks.push(current);
      current = line;
    } else {
      current = current ? `${current}\n${line}` : line;
    }
  }

  if (current) chunks.push(current);
  return chunks.length > 0 ? chunks : [""];
}
