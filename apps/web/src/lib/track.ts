// First-party usage counting (no cookies, no third parties). The API counts visitors with a
// hash that changes daily; browsers asking not to be tracked are skipped here and there.

export type TrackEvent = "page.view" | "report.fix_opened" | "cta.signup_clicked";

export function trackingAllowed(nav: Navigator | null = globalThis.navigator ?? null): boolean {
  if (!nav) return false;
  const n = nav as Navigator & { globalPrivacyControl?: boolean };
  return !(n.globalPrivacyControl === true || n.doNotTrack === "1");
}

export function track(name: TrackEvent, extra: { check_id?: string } = {}): void {
  if (!trackingAllowed()) return;
  void fetch("/api/v1/events", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, path: location.pathname, ...extra }),
    keepalive: true, // survives navigating away (link clicks)
  }).catch(() => undefined);
}
