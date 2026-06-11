import { describe, expect, it } from "vitest";
import { basePathFromBaseHref, joinBasePath } from "./basePath";

describe("basePathFromBaseHref", () => {
  it("returns empty string for the root base", () => {
    expect(basePathFromBaseHref("/")).toBe("");
  });

  it("strips the trailing slash from a prefix base", () => {
    expect(basePathFromBaseHref("/vault/")).toBe("/vault");
  });

  it("handles nested prefixes", () => {
    expect(basePathFromBaseHref("/tools/agent-vault/")).toBe(
      "/tools/agent-vault",
    );
  });

  it("handles absolute base hrefs", () => {
    expect(basePathFromBaseHref("https://example.com/vault/")).toBe("/vault");
    expect(basePathFromBaseHref("https://example.com/")).toBe("");
  });

  it("returns empty string when the base tag is missing", () => {
    expect(basePathFromBaseHref(null)).toBe("");
    expect(basePathFromBaseHref(undefined)).toBe("");
    expect(basePathFromBaseHref("")).toBe("");
  });
});

describe("joinBasePath", () => {
  it("prefixes root-relative API URLs", () => {
    expect(joinBasePath("/vault", "/v1/status")).toBe("/vault/v1/status");
  });

  it("leaves URLs untouched at the root", () => {
    expect(joinBasePath("", "/v1/status")).toBe("/v1/status");
  });

  it("leaves absolute URLs untouched", () => {
    expect(joinBasePath("/vault", "https://example.com/x")).toBe(
      "https://example.com/x",
    );
  });
});
