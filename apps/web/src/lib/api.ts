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
}

export interface StageGrade {
  score: number;
  letter: string;
  counted: number;
}

export interface Scan {
  id: string;
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
  getScan: (id: string) => request<Scan>(`/scans/${encodeURIComponent(id)}`),
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
  restore: (findingId: string) =>
    request<ActionResult>(`/findings/${encodeURIComponent(findingId)}/restore`, {
      method: "POST",
    }),
};
