import { describe, expect, it, beforeEach, afterEach } from "vitest";

import { isQrDecodeSupported, isLiveScanSupported } from "../src/core/qrdecode.js";

describe("qrdecode capability detection", () => {
  let originalWindow;
  let originalBarcodeDetector;

  beforeEach(() => {
    originalWindow = globalThis.window;
    originalBarcodeDetector = globalThis.window?.BarcodeDetector;
  });

  afterEach(() => {
    if (originalWindow === undefined) {
      delete globalThis.window;
    } else {
      globalThis.window = originalWindow;
      if (originalBarcodeDetector === undefined) delete globalThis.window.BarcodeDetector;
      else globalThis.window.BarcodeDetector = originalBarcodeDetector;
    }
  });

  it("always reports QR decoding as supported because of bundled jsQR fallback", () => {
    // 即使浏览器没有 BarcodeDetector，我们也有 jsQR 作为回退
    globalThis.window = {};
    expect(isQrDecodeSupported()).toBe(true);
  });

  it("reports live (camera) scan supported only when BarcodeDetector exists", () => {
    globalThis.window = {};
    expect(isLiveScanSupported()).toBe(false);
    globalThis.window = { BarcodeDetector: class {} };
    expect(isLiveScanSupported()).toBe(true);
  });
});
