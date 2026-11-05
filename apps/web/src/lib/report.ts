// Pure helpers that shape a scan for the results page. Unit-tested in report.test.ts.
import type { Finding, Scan, Severity, Stage } from "./api";

/** Same text the API puts in redacted evidence (corpsec_api.redaction.HIDDEN). */
export const REDACTED_MARK = "Hidden until you verify that you own this site.";

export const STAGES: Stage[] = ["connection", "encryption", "website", "software", "email"];
export const PROBLEM_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
export const GROUP_ORDER = ["critical", "high", "medium", "low", "info", "fixed", "dismissed", "pass"];

export function isFinished(scan: Pick<Scan, "status">): boolean {
  return scan.status === "completed" || scan.status === "partial" || scan.status === "failed";
}

export function isProblem(f: Finding): boolean {
  return f.status === "open" && PROBLEM_SEVERITIES.includes(f.severity);
}

/** Group key a finding is shown under. Fixed and hidden ones get their own groups. */
export function groupOf(f: Finding): string {
  if (f.status === "fixed") return "fixed";
  if (f.status === "dismissed") return "dismissed";
  return f.severity;
}

/**
 * One card per check and group: TLS 1.0 and TLS 1.1 accepted are one problem with two
 * places it was found, not two problems with the same title.
 */
export type FindingSet = { key: string; findings: Finding[] };

function bundle(findings: Finding[]): FindingSet[] {
  const sets = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `${f.check_id}:${groupOf(f)}`;
    sets.set(key, [...(sets.get(key) ?? []), f]);
  }
  return [...sets].map(([key, fs]) => ({ key, findings: fs }));
}

/** Finding sets by group, in display order, skipping empty groups and internal checks. */
export function groupFindings(findings: Finding[], exclude: Set<string> = new Set()): [string, FindingSet[]][] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.explanation) continue; // internal checks have no explanation
    const key = groupOf(f);
    if (exclude.has(`${f.check_id}:${key}`)) continue;
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  return GROUP_ORDER.filter((k) => groups.has(k)).map((k) => [k, bundle(groups.get(k)!)]);
}

/** The API's fix-first list as finding sets (one per check), still-open problems only. */
export function fixFirst(scan: Scan): FindingSet[] {
  const byId = new Map(scan.findings.map((f) => [f.id, f]));
  const sets: FindingSet[] = [];
  for (const id of scan.fix_first) {
    const f = byId.get(id);
    if (!f || !isProblem(f)) continue;
    const key = `${f.check_id}:${groupOf(f)}`;
    sets.push({ key, findings: scan.findings.filter((x) => `${x.check_id}:${groupOf(x)}` === key) });
  }
  return sets;
}

/** Human label for where a finding applies: "TLSv1.0", "/.env", "contact-form-7". */
export function itemLabel(f: Finding): string {
  return f.dedupe_key.replace(/^wordpress-(plugin|theme):/, "");
}

const LETTERS: [number, string][] = [[90, "A"], [80, "B"], [65, "C"], [50, "D"]];
export function letterForScore(score: number): string {
  return LETTERS.find(([min]) => score >= min)?.[1] ?? "F";
}

/** Show a cap note only if the cap actually lowered the grade. */
export function capApplied(scan: Pick<Scan, "score" | "grade">): boolean {
  if (scan.score === null || !scan.grade) return false;
  const order = ["A+", "A", "B", "C", "D", "F"];
  return order.indexOf(scan.grade) > order.indexOf(letterForScore(scan.score));
}

/** "A+" -> "a", used for colour tokens. Letter is always shown as text too. */
export function gradeTone(letter: string | null): string {
  return (letter ?? "f").replace("+", "").toLowerCase();
}

export type StageState = "waiting" | "running" | "done";

/** Stage progress from the check ids finished so far and each check's stage. */
export function stageStates(
  finished: Map<string, Stage>,
  total: number,
  expectedPerStage: Partial<Record<Stage, number>>,
): Record<Stage, StageState> {
  const counts: Partial<Record<Stage, number>> = {};
  for (const stage of finished.values()) counts[stage] = (counts[stage] ?? 0) + 1;
  const all = finished.size >= total && total > 0;
  const out = {} as Record<Stage, StageState>;
  for (const s of STAGES) {
    const n = counts[s] ?? 0;
    const expected = expectedPerStage[s];
    if (all || (expected !== undefined && n >= expected)) out[s] = "done";
    else out[s] = n > 0 ? "running" : "waiting";
  }
  return out;
}

/** Wordfence/MITRE licences require their notices wherever the data is shown. */
export function attributions(f: Finding): { holders: [string, { notice: string; license: string; license_url: string }][]; records: string[] } {
  const observed = f.evidence.observed as
    | { attributions?: Record<string, { notice: string; license: string; license_url: string }>; vulnerabilities?: { url?: string | null }[] }
    | undefined;
  if (!observed || typeof observed !== "object") return { holders: [], records: [] };
  const holders = Object.entries(observed.attributions ?? {});
  const records = (observed.vulnerabilities ?? []).map((v) => v.url).filter((u): u is string => !!u);
  return { holders, records };
}

/** "6", "7.5": points without a trailing ".0". */
export function formatPoints(points: number): string {
  return Number.isInteger(points) ? String(points) : points.toFixed(1);
}

/** The score range that gives a letter, for "60 is a D (50–64)". */
export function letterRange(letter: string): string {
  const ranges: Record<string, string> = { "A+": "95–100", A: "90–100", B: "80–89", C: "65–79", D: "50–64", F: "0–49" };
  return ranges[letter] ?? "";
}
