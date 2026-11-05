// Types and calls for the CorpSEC API (apps/api), reached through the /api rewrite.

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "pass";
export type Stage = "connection" | "encryption" | "website" | "software" | "email";
export type ScanStatus = "queued" | "running" | "completed" | "partial" | "failed";

export interface Explanation {
  check_id: string;
  title: string;
  summary: string;
  analogy: string | null;
  why_it_matters: string[];
  fix_steps: string[];
  fix_for: string;
  effort: string;
  who_can_fix: string;
  technical: string;
}

export interface Attribution {
  notice: string;
  license: string;
  license_url: string;
}

export interface Finding {
  id: string;
  check_id: string;
  check_version: string;
  host: string;
  dedupe_key: string;
  severity: Severity;
  confidence: "confirmed" | "likely" | "possible";
  status: "open" | "fixed" | "dismissed";
  evidence: { kind: string; observed?: unknown; [key: string]: unknown };
  context: Record<string, string>;
  references: string[];
  first_seen: string;
  fixed_at: string | null;
  dismissed_reason: string | null;
  explanation: Explanation | null;
  /** Points this problem takes off the score; null when it doesn't count. */
  points?: number | null;
}

export interface StageGrade {
  score: number;
  letter: string;
  counted: number;
  /** Points this area's problems take off the overall score. */
  lost?: number;
}

export interface Scan {
  id: string;
  /** Set for scans of a monitored site (owner-only). */
  site_id: string | null;
  /** Exposed-file locations and contents are hidden until the viewer proves ownership. */
  redacted: boolean;
  /** Whether this viewer may re-check or hide findings (false for shared read-only links). */
  can_act: boolean;
  target: string;
  host: string;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  score: number | null;
  grade: string | null;
  grade_caps: string[];
  stage_grades: Partial<Record<Stage, StageGrade>>;
  fix_first: string[];
  /** The overall score is 100 minus this. */
  points_lost?: number;
  error: string | null;
  check_runs: { check_id: string; stage: Stage; status: string }[];
  findings: Finding[];
}

export interface ProgressEvent {
  type: "progress" | "done";
  check_id?: string;
  stage?: Stage;
  completed?: number;
  total?: number;
  /** Number of checks per stage, so the UI can tell when a stage is finished. */
  stage_totals?: Partial<Record<Stage, number>>;
}

export type DismissReason = "accepted_risk" | "false_positive" | "not_applicable";

export interface ActionResult {
  result: "fixed" | "still_present" | "inconclusive";
  grade: string | null;
  score: number | null;
}

export interface Me {
  id: string;
  email: string;
  weekly_digest: boolean;
  is_admin: boolean;
}

export type FeedbackReason = "false_positive" | "wrong_advice" | "unclear" | "other";

export interface MetricValue {
  value: number | null;
  target?: number;
  [detail: string]: number | string | null | undefined;
}

export interface AdminOverview {
  days: number;
  generated_at: string;
  metrics: {
    activation: MetricValue;
    action: MetricValue;
    false_positive: MetricValue;
    safety: { optouts: number; note: string };
  };
  scans: {
    per_day: ({ day: string } & Record<string, number | string>)[];
    started_by_kind: Record<string, number>;
    avg_seconds: number | null;
    p95_seconds: number | null;
    failing_checks: { check_id: string; count: number }[];
    common_problems: { check_id: string; count: number }[];
  };
  funnel: { step: string; visitors: number }[];
  live: { queued: number; oldest_queued_seconds: number; running: number; intel_age_hours: number | null };
  feedback_by_check: { check_id: string; open: number }[];
}

export interface FeedbackItem {
  id: number;
  check_id: string;
  check_version: string;
  reason: FeedbackReason;
  note: string | null;
  created_at: string;
  evidence: Record<string, unknown>;
  resolved: boolean;
}

export type OAuthProvider = "google" | "microsoft";

export type Platform =
  | "wordpress" | "joomla" | "drupal" | "shopify" | "wix" | "squarespace" | "webflow" | "custom" | "unknown";

export interface ScanSummary {
  id: string;
  status: ScanStatus;
  grade: string | null;
  score: number | null;
  finished_at: string | null;
}

export interface VerifyInstructions {
  txt_name: string;
  txt_value: string;
  file_url: string;
  file_content: string;
  meta_tag: string;
}

export interface Site {
  id: string;
  domain: string;
  platform: Platform | null;
  verified: boolean;
  verification_method: "dns" | "file" | "meta" | null;
  monitoring_enabled: boolean;
  monitoring_paused_reason: string | null;
  next_scan_at: string | null;
  latest: ScanSummary | null;
  previous_grade: string | null;
  instructions: VerifyInstructions | null;
}

export interface SiteDetail extends Site {
  history: ScanSummary[];
  alerts: { kind: string; created_at: string; payload: Record<string, unknown> }[];
}

export type VerifyMethod = "dns" | "file" | "meta";

export interface TrendPoint {
  scan_id: string;
  finished_at: string;
  score: number | null;
  grade: string | null;
  /** Stage -> letter. */
  stages: Partial<Record<Stage, string>>;
  open_problems: number;
}

export interface Trends {
  points: TrendPoint[];
  fixed_count: number;
  median_days_to_fix: number | null;
  open_now: number;
}

export interface Benchmark {
  score: number | null;
  platform: Platform | null;
  sample: number;
  /** Share of compared sites with a lower score; null when there aren't enough. */
  better_than: number | null;
}

export interface ProblemLine {
  check_id: string;
  title: string;
  severity: Severity;
  item: string;
}

export interface MonthlyReport {
  domain: string;
  month: string;
  scans: number;
  start_grade: string | null;
  end_grade: string | null;
  start_score: number | null;
  end_score: number | null;
  fixed: ProblemLine[];
  new: ProblemLine[];
  open_at_end: ProblemLine[];
  alerts: { kind: string; at: string }[];
}

export interface Portfolio {
  sites: {
    id: string;
    domain: string;
    grade: string | null;
    score: number | null;
    open_by_severity: Partial<Record<Severity, number>>;
    last_checked: string | null;
  }[];
  average_score: number | null;
  open_serious: number;
  fix_first: {
    site_id: string;
    domain: string;
    scan_id: string;
    finding_id: string;
    check_id: string;
    title: string;
    severity: Severity;
    effort: string;
  }[];
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

const BASE = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      ...init,
      headers: { "content-type": "application/json", ...init?.headers },
    });
  } catch {
    throw new ApiError("We couldn't reach CorpSEC. Check your internet connection.", 0);
  }
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    // RFC 9457 problem details; the title is written for users.
    const body = await res.json().catch(() => null);
    throw new ApiError(body?.title ?? "Something went wrong. Please try again.", res.status);
  }
  return res.json() as Promise<T>;
}

export const api = {
  startScan: (target: string) =>
    request<{ id: string; status: ScanStatus }>("/scans", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),
  getScan: (id: string, share?: string | null) =>
    request<Scan>(`/scans/${encodeURIComponent(id)}${share ? `?share=${encodeURIComponent(share)}` : ""}`),
  shareScan: (id: string, email: string, note: string) =>
    request<{ status: string }>(`/scans/${encodeURIComponent(id)}/share`, {
      method: "POST",
      body: JSON.stringify({ email, note: note || null }),
    }),
  optoutInfo: (domain: string) =>
    request<{ domain: string; txt_name: string; txt_value: string; opted_out: boolean }>(
      `/optout/${encodeURIComponent(domain)}`,
    ),
  optout: (domain: string) =>
    request<{ domain: string; opted_out: boolean }>("/optout", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
  eventsUrl: (id: string) => `${BASE}/scans/${encodeURIComponent(id)}/events`,
  recheck: (findingId: string) =>
    request<ActionResult>(`/findings/${encodeURIComponent(findingId)}/recheck`, {
      method: "POST",
    }),
  dismiss: (findingId: string, reason: DismissReason) =>
    request<ActionResult>(`/findings/${encodeURIComponent(findingId)}/dismiss`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  feedback: (findingId: string, reason: FeedbackReason, note: string) =>
    request<{ status: string }>(`/findings/${encodeURIComponent(findingId)}/feedback`, {
      method: "POST",
      body: JSON.stringify({ reason, note: note || null }),
    }),
  restore: (findingId: string) =>
    request<ActionResult>(`/findings/${encodeURIComponent(findingId)}/restore`, {
      method: "POST",
    }),

  // accounts
  me: () => request<Me>("/me"),
  requestLink: (email: string, next?: string) =>
    request<{ status: string }>("/auth/magic-link", {
      method: "POST",
      body: JSON.stringify({ email, next }),
    }),
  verifyLink: (token: string) =>
    request<Me>("/auth/verify", { method: "POST", body: JSON.stringify({ token }) }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  updateMe: (patch: { weekly_digest?: boolean }) =>
    request<Me>("/me", { method: "PATCH", body: JSON.stringify(patch) }),
  /** A plain link: the browser downloads the JSON file with the session cookie. */
  exportUrl: `${BASE}/me/export`,
  deleteAccount: (confirmEmail: string) =>
    request<void>("/me", { method: "DELETE", body: JSON.stringify({ confirm_email: confirmEmail }) }),
  /** Sign-in providers the server has credentials for; buttons for the others stay hidden. */
  providers: () => request<{ providers: OAuthProvider[] }>("/auth/providers"),
  /** A full-page navigation, not a fetch: the API redirects to the provider and back. */
  oauthStartUrl: (provider: OAuthProvider, next?: string) =>
    `${BASE}/auth/oauth/${provider}/start` + (next ? `?next=${encodeURIComponent(next)}` : ""),

  // operator dashboard (admins only; others get 404)
  adminOverview: (days: number) => request<AdminOverview>(`/admin/overview?days=${days}`),
  adminFeedback: () => request<FeedbackItem[]>("/admin/feedback"),
  resolveFeedback: (id: number) =>
    request<FeedbackItem>(`/admin/feedback/${id}/resolve`, { method: "POST" }),

  // sites
  sites: () => request<Site[]>("/sites"),
  site: (id: string) => request<SiteDetail>(`/sites/${encodeURIComponent(id)}`),
  addSite: (domain: string, platform: Platform | null) =>
    request<Site>("/sites", { method: "POST", body: JSON.stringify({ domain, platform }) }),
  updateSite: (id: string, patch: { platform?: Platform; monitoring_enabled?: boolean }) =>
    request<Site>(`/sites/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  deleteSite: (id: string) =>
    request<void>(`/sites/${encodeURIComponent(id)}`, { method: "DELETE" }),
  verifySite: (id: string, method: VerifyMethod) =>
    request<{ verified: boolean; message: string }>(`/sites/${encodeURIComponent(id)}/verify`, {
      method: "POST",
      body: JSON.stringify({ method }),
    }),
  trends: (id: string) => request<Trends>(`/sites/${encodeURIComponent(id)}/trends`),
  benchmark: (id: string) => request<Benchmark>(`/sites/${encodeURIComponent(id)}/benchmark`),
  monthly: (id: string, month: string) =>
    request<MonthlyReport>(`/sites/${encodeURIComponent(id)}/monthly?month=${encodeURIComponent(month)}`),
  portfolio: () => request<Portfolio>("/portfolio"),
  scanSite: (id: string) =>
    request<ScanSummary>(`/sites/${encodeURIComponent(id)}/scans`, { method: "POST" }),
};
