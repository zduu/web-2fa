import { describe, expect, it } from "vitest";

import { renderQrSvg } from "../src/core/qrgen.js";

describe("renderQrSvg", () => {
  it("renders an SVG QR code for share links", () => {
    const svg = renderQrSvg("https://example.com/shared.html?sid=demo#k=test");
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain('viewBox="0 0 ');
    expect(svg).toContain("<path ");
  });
});
