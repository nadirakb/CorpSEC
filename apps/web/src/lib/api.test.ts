import { describe, expect, it } from "vitest";

import { api } from "./api";

describe("oauthStartUrl", () => {
  it("goes through the /api rewrite", () => {
    expect(api.oauthStartUrl("google")).toBe("/api/v1/auth/oauth/google/start");
  });

  it("carries where to go next", () => {
    expect(api.oauthStartUrl("microsoft", "/sites/s 1")).toBe(
      "/api/v1/auth/oauth/microsoft/start?next=%2Fsites%2Fs%201",
    );
  });
});
