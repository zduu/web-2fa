import { describe, expect, it } from "vitest";

import { normalizeRingSecondsLeft, normalizeRingSize } from "../src/ui/ring.js";

describe("normalizeRingSize", () => {
  it("keeps ring SVG dimensions finite and inside the supported range", () => {
    expect(normalizeRingSize(40)).toBe(40);
    expect(normalizeRingSize("40.9")).toBe(40);
    expect(normalizeRingSize(8)).toBe(16);
    expect(normalizeRingSize(200)).toBe(96);
    expect(normalizeRingSize("bad")).toBe(40);
    expect(normalizeRingSize(Infinity)).toBe(40);
  });
});

describe("normalizeRingSecondsLeft", () => {
  it("keeps ring progress seconds finite and inside the current period", () => {
    expect(normalizeRingSecondsLeft(12, 30)).toBe(12);
    expect(normalizeRingSecondsLeft("12.9", 30)).toBe(12);
    expect(normalizeRingSecondsLeft(-1, 30)).toBe(0);
    expect(normalizeRingSecondsLeft(99, 30)).toBe(30);
    expect(normalizeRingSecondsLeft("bad", 30)).toBe(30);
    expect(normalizeRingSecondsLeft(Infinity, 30)).toBe(30);
    expect(normalizeRingSecondsLeft(20, "3")).toBe(5);
  });
});
