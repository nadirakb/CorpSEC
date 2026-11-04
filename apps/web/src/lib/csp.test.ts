import { describe, expect, it } from "vitest";

import { csp } from "./csp";

describe("csp", () => {
  it("allows only nonce-stamped scripts in production", () => {
    const policy = csp("abc123", false);
    expect(policy).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(policy).not.toContain("unsafe-eval");
    expect(policy).not.toMatch(/script-src[^;]*unsafe-inline/);
    expect(policy).toContain("frame-ancestors 'none'");
  });

  it("adds eval only for development", () => {
    expect(csp("x", true)).toContain("'unsafe-eval'");
  });
});
