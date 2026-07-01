import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { formatThreadTranscript } from "./slack-transcript.js";

describe("formatThreadTranscript", () => {
  test("formats user and bot messages and strips bot mentions", () => {
    const transcript = formatThreadTranscript(
      [
        { user: "U1", text: "<@BOT> hello" },
        { user: "BOT", text: "hi there" },
      ],
      { agentName: "Agent", botUserId: "BOT" },
    );

    assert.equal(transcript, "<@U1>: hello\nAgent: hi there");
  });

  test("keeps only the most recent messages when message count is capped", () => {
    const transcript = formatThreadTranscript(
      Array.from({ length: 5 }, (_, index) => ({
        user: `U${index}`,
        text: `message ${index}`,
      })),
      { agentName: "Agent", maxMessages: 2 },
    );

    assert.match(transcript, /^\[Earlier thread context omitted for length\.\]/);
    assert.ok(!transcript.includes("message 2"));
    assert.ok(transcript.includes("message 3"));
    assert.ok(transcript.includes("message 4"));
  });

  test("keeps most recent lines within a character cap", () => {
    const transcript = formatThreadTranscript(
      [
        { user: "U1", text: "older message" },
        { user: "U2", text: "middle message" },
        { user: "U3", text: "newer message" },
      ],
      { agentName: "Agent", maxChars: 45 },
    );

    assert.match(transcript, /^\[Earlier thread context omitted for length\.\]/);
    assert.ok(!transcript.includes("older message"));
    assert.ok(transcript.includes("newer message"));
  });

  test("truncates a single oversized message", () => {
    const transcript = formatThreadTranscript(
      [{ user: "U1", text: "x".repeat(100) }],
      { agentName: "Agent", maxChars: 30, maxMessageChars: 100 },
    );

    assert.ok(transcript.length <= 30);
    assert.ok(transcript.endsWith("..."));
  });
});
