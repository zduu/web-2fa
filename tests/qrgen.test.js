import { describe, expect, it } from "vitest";

import { normalizeQrSvgOptions, renderQrSvg } from "../src/core/qrgen.js";

describe("renderQrSvg", () => {
  it("renders an SVG QR code for share links", () => {
    const svg = renderQrSvg("https://example.com/shared.html?sid=demo#k=test");
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain('viewBox="0 0 ');
    expect(svg).toContain("<path ");
  });

  it("normalizes unsafe SVG rendering options before calling the encoder", () => {
    expect(normalizeQrSvgOptions({
      ecc: " h ",
      border: "99",
      pixelSize: "0",
      whiteColor: "\" onload=\"alert(1)",
      blackColor: "#123abc",
      boostEcc: false,
    })).toEqual({
      ecc: "H",
      border: 16,
      pixelSize: 1,
      whiteColor: "#ffffff",
      blackColor: "#123abc",
      boostEcc: false,
    });
  });

  it("renders with safe fallback options for malformed inputs", () => {
    const svg = renderQrSvg("demo", {
      ecc: "bad",
      border: "bad",
      pixelSize: Infinity,
      blackColor: "\"><script>",
    });

    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain('fill="#111827"');
    expect(svg).not.toContain("<script>");
  });
});
