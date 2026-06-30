import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";

import { decodeQrFromFile, decodeQrFromSource, isQrDecodeSupported, isLiveScanSupported } from "../src/core/qrdecode.js";

describe("qrdecode capability detection", () => {
  let originalWindow;
  let originalBarcodeDetector;
  let originalDocument;
  let originalOffscreenCanvas;
  let originalURL;
  let originalImage;
  let originalCreateImageBitmap;

  beforeEach(() => {
    originalWindow = globalThis.window;
    originalBarcodeDetector = globalThis.window?.BarcodeDetector;
    originalDocument = globalThis.document;
    originalOffscreenCanvas = globalThis.OffscreenCanvas;
    originalURL = globalThis.URL;
    originalImage = globalThis.Image;
    originalCreateImageBitmap = globalThis.createImageBitmap;
  });

  afterEach(() => {
    if (originalWindow === undefined) {
      delete globalThis.window;
    } else {
      globalThis.window = originalWindow;
      if (originalBarcodeDetector === undefined) delete globalThis.window.BarcodeDetector;
      else globalThis.window.BarcodeDetector = originalBarcodeDetector;
    }
    if (originalDocument === undefined) delete globalThis.document;
    else globalThis.document = originalDocument;
    if (originalOffscreenCanvas === undefined) delete globalThis.OffscreenCanvas;
    else globalThis.OffscreenCanvas = originalOffscreenCanvas;
    if (originalURL === undefined) delete globalThis.URL;
    else globalThis.URL = originalURL;
    if (originalImage === undefined) delete globalThis.Image;
    else globalThis.Image = originalImage;
    if (originalCreateImageBitmap === undefined) delete globalThis.createImageBitmap;
    else globalThis.createImageBitmap = originalCreateImageBitmap;
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

  it("returns null instead of throwing when no canvas API is available", async () => {
    globalThis.window = {};
    delete globalThis.document;
    delete globalThis.OffscreenCanvas;

    await expect(decodeQrFromSource({ width: 10, height: 10 })).resolves.toBe(null);
  });

  it("returns null when fallback canvas drawing fails", async () => {
    globalThis.window = {};
    delete globalThis.OffscreenCanvas;
    globalThis.document = {
      createElement: () => ({
        getContext: () => ({
          drawImage: () => {
            throw new Error("draw-failed");
          },
          getImageData: () => ({ data: new Uint8ClampedArray(4) }),
        }),
      }),
    };

    await expect(decodeQrFromSource({ width: 1, height: 1 })).resolves.toBe(null);
  });

  it("returns null when fallback canvas image data read fails", async () => {
    globalThis.window = {};
    delete globalThis.OffscreenCanvas;
    globalThis.document = {
      createElement: () => ({
        getContext: () => ({
          drawImage: () => {},
          getImageData: () => {
            throw new Error("read-failed");
          },
        }),
      }),
    };

    await expect(decodeQrFromSource({ width: 1, height: 1 })).resolves.toBe(null);
  });

  it("returns null when file decode has no object URL image fallback", async () => {
    delete globalThis.createImageBitmap;
    delete globalThis.URL;
    delete globalThis.Image;

    await expect(decodeQrFromFile(new Blob(["not an image"]))).resolves.toBe(null);
  });

  it("revokes object URLs when image fallback loading fails", async () => {
    delete globalThis.createImageBitmap;
    const revokeObjectURL = vi.fn();
    globalThis.URL = {
      createObjectURL: vi.fn(() => "blob:qr"),
      revokeObjectURL,
    };
    globalThis.Image = class {
      set src(_value) {
        queueMicrotask(() => this.onerror?.(new Error("image-load-failed")));
      }
    };

    await expect(decodeQrFromFile(new Blob(["not an image"]))).resolves.toBe(null);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:qr");
  });
});
