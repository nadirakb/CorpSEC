import type { MetricValue } from "./api";

export type MetricStatus = "met" | "missed" | "no_data";

/** For the false-alarm rate lower is better; for the others higher is better. */
export function metricStatus(m: MetricValue, lowerIsBetter = false): MetricStatus {
  if (m.value === null || m.target === undefined) return "no_data";
  return (lowerIsBetter ? m.value <= m.target : m.value >= m.target) ? "met" : "missed";
}

export function percent(value: number | null, digits = 0): string {
  return value === null ? "–" : `${(value * 100).toFixed(digits)}%`;
}

export function duration(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  return `${Math.round(seconds / 3600)} h`;
}

/** Total scans per day, filling days without scans so the bars keep a steady time axis. */
export function dailyTotals(
  perDay: ({ day: string } & Record<string, number | string>)[],
  days: number,
  today: Date = new Date(),
): { day: string; total: number; byStatus: Record<string, number> }[] {
  const byDay = new Map(perDay.map((d) => [d.day, d]));
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i));
    const key = d.toISOString().slice(0, 10);
    const row = byDay.get(key);
    const byStatus: Record<string, number> = {};
    if (row) for (const [k, v] of Object.entries(row)) if (k !== "day") byStatus[k] = Number(v);
    out.push({ day: key, total: Object.values(byStatus).reduce((a, b) => a + b, 0), byStatus });
  }
  return out;
}
