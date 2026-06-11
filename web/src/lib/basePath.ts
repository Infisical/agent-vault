/**
 * The URL path prefix the app is served under (e.g. "/vault"), or "" when
 * mounted at the domain root.
 *
 * The Go server rewrites the <base href="/" /> tag in index.html to
 * <base href="{prefix}/" /> when started with --ui-base-path. Reading it
 * back here means one built bundle works for any prefix with no build-time
 * configuration.
 */

/** Parses a <base href> value into a path prefix without a trailing slash. */
export function basePathFromBaseHref(href: string | null | undefined): string {
  if (!href) return "";
  let path: string;
  try {
    path = new URL(href, "http://placeholder").pathname;
  } catch {
    return "";
  }
  const trimmed = path.replace(/\/+$/, "");
  return trimmed === "/" ? "" : trimmed;
}

/** Joins the base path onto a root-relative URL ("/v1/..." → "{prefix}/v1/..."). */
export function joinBasePath(base: string, url: string): string {
  return base && url.startsWith("/") ? base + url : url;
}

export const basePath: string =
  typeof document === "undefined"
    ? ""
    : basePathFromBaseHref(
        document.querySelector("base")?.getAttribute("href"),
      );
