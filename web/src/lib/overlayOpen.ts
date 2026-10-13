// Fired when a Sheet or Modal opens so the mobile nav drawer can close
// (and clear inert) before the overlay becomes interactive.
export const OVERLAY_OPEN_EVENT = "agent-vault:overlay-open";

export function notifyOverlayOpen(): void {
  window.dispatchEvent(new Event(OVERLAY_OPEN_EVENT));
}
