import { describe, expect, it } from "vitest";

import { trackingAllowed } from "./track";

describe("trackingAllowed", () => {
  it("respects Global Privacy Control and Do Not Track", () => {
    expect(trackingAllowed({ doNotTrack: null } as Navigator)).toBe(true);
    expect(trackingAllowed({ doNotTrack: "1" } as Navigator)).toBe(false);
    expect(trackingAllowed({ globalPrivacyControl: true } as unknown as Navigator)).toBe(false);
    expect(trackingAllowed(null)).toBe(false);
  });
});
