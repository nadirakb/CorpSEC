import { describe, expect, it } from "vitest";

import { dailyTotals, duration, metricStatus, percent } from "./admin";

describe("admin helpers", () => {
  it("judges metrics against their targets", () => {
    expect(metricStatus({ value: 0.3, target: 0.25 })).toBe("met");
    expect(metricStatus({ value: 0.1, target: 0.25 })).toBe("missed");
    expect(metricStatus({ value: 0.01, target: 0.02 }, true)).toBe("met");
    expect(metricStatus({ value: null, target: 0.02 }, true)).toBe("no_data");
  });

  it("formats", () => {
    expect(percent(0.256)).toBe("26%");
    expect(percent(null)).toBe("–");
    expect(duration(42)).toBe("42 s");
    expect(duration(600)).toBe("10 min");
    expect(duration(7200)).toBe("2 h");
  });

  it("fills missing days", () => {
    const rows = dailyTotals([{ day: "2026-11-03", completed: 2, failed: 1 }], 3, new Date("2026-11-04T10:00:00Z"));
    expect(rows.map((r) => [r.day, r.total])).toEqual([
      ["2026-11-02", 0],
      ["2026-11-03", 3],
      ["2026-11-04", 0],
    ]);
    expect(rows[1].byStatus).toEqual({ completed: 2, failed: 1 });
  });
});
