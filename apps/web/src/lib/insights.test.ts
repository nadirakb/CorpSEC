import { describe, expect, it } from "vitest";

import type { TrendPoint } from "./api";
import { benchmarkPercent, lastMonth, plotPoints } from "./insights";

const p = (score: number | null): TrendPoint => ({
  scan_id: "s", finished_at: "2026-11-01T00:00:00Z", score, grade: null, stages: {}, open_problems: 0,
});

describe("insights helpers", () => {
  it("places scores on the plot, skipping unscored scans", () => {
    const pts = plotPoints([p(100), p(null), p(0)], 116, 116, 8);
    expect(pts.map((x) => [x.x, x.y])).toEqual([[8, 8], [108, 108]]);
    expect(plotPoints([p(50)], 100, 100, 0)[0]).toMatchObject({ x: 50, y: 50 });
  });

  it("formats comparisons and months", () => {
    expect(benchmarkPercent(0.724)).toBe(72);
    expect(benchmarkPercent(null)).toBeNull();
    expect(lastMonth(new Date("2026-01-15T00:00:00Z"))).toBe("2025-12");
  });
});
