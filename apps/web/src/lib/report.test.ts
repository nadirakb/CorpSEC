import { describe, expect, it } from "vitest";

import type { Finding, Scan } from "./api";
import { attributions, capApplied, fixFirst, formatPoints, gradeTone, groupFindings, itemLabel, letterRange, stageStates } from "./report";

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id,
    check_id: "HDR-001",
    check_version: "1.0.0",
    host: "example.com",
    dedupe_key: "",
    severity: "medium",
    confidence: "confirmed",
    status: "open",
    evidence: { kind: "http" },
    context: {},
    references: [],
    first_seen: "2026-10-29T10:00:00Z",
    fixed_at: null,
    dismissed_reason: null,
    explanation: {
      check_id: "HDR-001", title: "t", summary: "s", analogy: null, why_it_matters: [],
      fix_steps: [], fix_for: "default", effort: "", who_can_fix: "", technical: "",
    },
    ...over,
  };
}

describe("groupFindings", () => {
  it("orders groups and separates fixed, hidden and internal findings", () => {
    const groups = groupFindings([
      finding("a", { severity: "pass" }),
      finding("b", { severity: "critical" }),
      finding("c", { severity: "high", status: "fixed" }),
      finding("d", { severity: "low", status: "dismissed" }),
      finding("e", { severity: "info", explanation: null }),
      finding("f", { severity: "critical" }),
    ]);
    expect(groups.map(([k, sets]) => [k, sets.map((s) => s.findings.map((f) => f.id))])).toEqual([
      ["critical", [["b", "f"]]], // same check -> one card
      ["fixed", [["c"]]],
      ["dismissed", [["d"]]],
      ["pass", [["a"]]],
    ]);
  });

  it("skips sets already shown in fix-first", () => {
    const groups = groupFindings([finding("a", { severity: "high" })], new Set(["HDR-001:high"]));
    expect(groups).toEqual([]);
  });
});

describe("capApplied", () => {
  it("is true only when the cap lowered the letter", () => {
    expect(capApplied({ score: 85, grade: "C" })).toBe(true);
    expect(capApplied({ score: 50, grade: "D" })).toBe(false);
    expect(capApplied({ score: 60, grade: "F" })).toBe(true);
  });
});

describe("fixFirst", () => {
  it("keeps the API order and drops findings that are no longer open", () => {
    const scan = {
      fix_first: ["x", "y", "z"],
      findings: [
        finding("y"),
        finding("x", { status: "fixed" }),
        finding("z", { severity: "high", check_id: "TLS-003" }),
        finding("z2", { severity: "high", check_id: "TLS-003" }),
      ],
    } as unknown as Scan;
    expect(fixFirst(scan).map((s) => s.findings.map((f) => f.id))).toEqual([["y"], ["z", "z2"]]);
  });
});

describe("gradeTone", () => {
  it("maps letters to tone tokens", () => {
    expect(gradeTone("A+")).toBe("a");
    expect(gradeTone("C")).toBe("c");
    expect(gradeTone(null)).toBe("f");
  });
});

describe("stageStates", () => {
  it("derives waiting/running/done", () => {
    const done = new Map([
      ["CONN-001", "connection"],
      ["CONN-002", "connection"],
      ["TLS-001", "encryption"],
    ] as const);
    const states = stageStates(new Map(done), 10, { connection: 2, encryption: 8 });
    expect(states.connection).toBe("done");
    expect(states.encryption).toBe("running");
    expect(states.email).toBe("waiting");
  });
});

describe("attributions", () => {
  it("collects licence holders and record links from vulnerability evidence", () => {
    const f = finding("v", {
      evidence: {
        kind: "fingerprint",
        observed: {
          vulnerabilities: [{ url: "https://www.wordfence.com/threat-intel/x" }, { url: null }],
          attributions: { defiant: { notice: "© Defiant", license: "…", license_url: "https://l" } },
        },
      },
    });
    const a = attributions(f);
    expect(a.records).toEqual(["https://www.wordfence.com/threat-intel/x"]);
    expect(a.holders.map(([k]) => k)).toEqual(["defiant"]);
  });
});

describe("itemLabel", () => {
  it("drops the WordPress add-on prefix", () => {
    expect(itemLabel(finding("a", { dedupe_key: "wordpress-plugin:contact-form-7" }))).toBe("contact-form-7");
    expect(itemLabel(finding("b", { dedupe_key: "wordpress-theme:astra" }))).toBe("astra");
    expect(itemLabel(finding("c", { dedupe_key: "TLSv1.0" }))).toBe("TLSv1.0");
  });
});

describe("grade explanation helpers", () => {
  it("formats points and letter ranges", () => {
    expect(formatPoints(6)).toBe("6");
    expect(formatPoints(7.5)).toBe("7.5");
    expect(letterRange("D")).toBe("50–64");
    expect(letterRange("F")).toBe("0–49");
  });
});
