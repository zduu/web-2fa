import { describe, expect, it } from "vitest";

import {
  getAvatarInitial,
  hashAvatarHue,
  normalizeAvatarSize,
} from "../src/ui/avatar.js";

describe("avatar helpers", () => {
  it("keeps avatar sizes finite and within the supported range", () => {
    expect(normalizeAvatarSize(44)).toBe(44);
    expect(normalizeAvatarSize("44.9")).toBe(44);
    expect(normalizeAvatarSize(8)).toBe(16);
    expect(normalizeAvatarSize(200)).toBe(96);
    expect(normalizeAvatarSize("bad")).toBe(44);
    expect(normalizeAvatarSize(Infinity)).toBe(44);
  });

  it("builds stable display initials from issuer or account text", () => {
    expect(getAvatarInitial(" github ", "me@example.com")).toBe("G");
    expect(getAvatarInitial("", " me@example.com ")).toBe("M");
    expect(getAvatarInitial(" 钉钉 ", "")).toBe("钉");
    expect(getAvatarInitial("", "")).toBe("?");
  });

  it("hashes avatar hues deterministically inside the hue range", () => {
    const hue = hashAvatarHue("GitHub");

    expect(hashAvatarHue("GitHub")).toBe(hue);
    expect(hue).toBeGreaterThanOrEqual(0);
    expect(hue).toBeLessThan(360);
  });
});
