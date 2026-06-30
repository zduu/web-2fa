import { afterEach, describe, expect, it, vi } from "vitest";

import { attachScanner, watchScannerDetach } from "../src/ui/scanner.js";

const originalWindow = globalThis.window;

afterEach(() => {
  if (originalWindow === undefined) delete globalThis.window;
  else Object.defineProperty(globalThis, "window", { configurable: true, value: originalWindow });
  vi.restoreAllMocks();
});

describe("attachScanner", () => {
  it("returns false for invalid scanner roots", () => {
    expect(attachScanner(null, vi.fn(), vi.fn())).toBe(false);
    expect(attachScanner({}, vi.fn(), vi.fn())).toBe(false);
  });

  it("tolerates missing optional scanner controls when live scanning is unsupported", () => {
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {},
    });
    const root = {
      querySelector: vi.fn(() => null),
    };

    expect(() => attachScanner(root, vi.fn(), vi.fn())).not.toThrow();
    expect(attachScanner(root, vi.fn(), vi.fn())).toBe(true);
  });
});

describe("watchScannerDetach", () => {
  it("returns false when no document body is available", () => {
    expect(watchScannerDetach({}, vi.fn(), { doc: null })).toBe(false);
    expect(watchScannerDetach({}, vi.fn(), { doc: { body: {} } })).toBe(false);
  });

  it("uses requestAnimationFrame polling when ResizeObserver is available", () => {
    const root = {};
    const cleanup = vi.fn();
    const contains = vi.fn()
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(false);
    const callbacks = [];
    const raf = vi.fn((callback) => {
      callbacks.push(callback);
      return callbacks.length;
    });

    expect(watchScannerDetach(root, cleanup, {
      doc: { body: { contains } },
      win: { ResizeObserver: class {} },
      raf,
    })).toBe(true);

    expect(cleanup).not.toHaveBeenCalled();
    callbacks.shift()();
    expect(cleanup).not.toHaveBeenCalled();
    callbacks.shift()();
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(raf).toHaveBeenCalledTimes(2);
  });

  it("falls back to MutationObserver when frame polling is unavailable", () => {
    const root = {};
    const cleanup = vi.fn();
    const disconnect = vi.fn();
    let observerCallback;
    const observe = vi.fn();
    class MutationObserverCtor {
      constructor(callback) {
        observerCallback = callback;
      }

      observe(...args) {
        observe(...args);
      }

      disconnect() {
        disconnect();
      }
    }
    const contains = vi.fn()
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(false);

    expect(watchScannerDetach(root, cleanup, {
      doc: { body: { contains, appendChild: vi.fn() } },
      win: {},
      MutationObserverCtor,
    })).toBe(true);
    expect(observe).toHaveBeenCalledTimes(1);

    observerCallback();
    expect(cleanup).not.toHaveBeenCalled();
    observerCallback();
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(disconnect).toHaveBeenCalledTimes(1);
  });

  it("returns false when MutationObserver setup fails", () => {
    expect(watchScannerDetach({}, vi.fn(), {
      doc: { body: { contains: vi.fn(() => true), appendChild: vi.fn() } },
      win: {},
      MutationObserverCtor: class {
        observe() {
          throw new Error("observe blocked");
        }
      },
    })).toBe(false);
  });
});
