import type { Stage, TrendPoint } from "./api";

export const STAGES: Stage[] = ["connection", "encryption", "website", "software", "email"];

/** Score lines where the letter grade changes (spec §9.2), drawn as quiet reference lines. */
export const GRADE_LINES: [number, string][] = [[90, "A"], [80, "B"], [65, "C"], [50, "D"]];

export interface PlotPoint {
  x: number;
  y: number;
  point: TrendPoint;
}

/** Positions on a width × height plot: time on x (evenly spaced scans), score 0–100 on y. */
export function plotPoints(points: TrendPoint[], width: number, height: number, pad = 8): PlotPoint[] {
  const scored = points.filter((p) => p.score !== null);
  const step = scored.length > 1 ? (width - 2 * pad) / (scored.length - 1) : 0;
  return scored.map((point, i) => ({
    x: scored.length > 1 ? pad + i * step : width / 2,
    y: pad + (1 - (point.score as number) / 100) * (height - 2 * pad),
    point,
  }));
}

/** "Safer than 72% of WordPress sites" style sentence parts; null when there's no comparison. */
export function benchmarkPercent(betterThan: number | null): number | null {
  return betterThan === null ? null : Math.round(betterThan * 100);
}

/** Current calendar month as YYYY-MM: the report so far (the newest month with data). */
export function thisMonth(today: Date = new Date()): string {
  return today.toISOString().slice(0, 7);
}

/** Previous calendar month as YYYY-MM. */
export function lastMonth(today: Date = new Date()): string {
  const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth() - 1, 1));
  return d.toISOString().slice(0, 7);
}

export function monthName(month: string): string {
  const [y, m] = month.split("-").map(Number);
  return new Intl.DateTimeFormat(undefined, { month: "long", year: "numeric", timeZone: "UTC" }).format(
    new Date(Date.UTC(y, m - 1, 1)),
  );
}
