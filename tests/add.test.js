import { describe, expect, it, vi } from "vitest";

import { watchAddPreviewDetach } from "../src/ui/add.js";

describe("watchAddPreviewDetach", () => {
  it("returns false without a usable document body", () => {
    expect(watchAddPreviewDetach({}, vi.fn(), { doc: null })).toBe(false);
    expect(watchAddPreviewDetach({}, vi.fn(), { doc: { body: {} } })).toBe(false);
  });

  it("runs cleanup immediately when the root is already detached", () => {
    const cleanup = vi.fn();
    const root = {};

    expect(watchAddPreviewDetach(root, cleanup, {
      doc: { body: { contains: vi.fn(() => false) } },
    })).toBe(true);
    expect(cleanup).toHaveBeenCalledTimes(1);
  });

  it("observes the document body and cleans up after detach", () => {
    const cleanup = vi.fn();
    const disconnect = vi.fn();
    const observe = vi.fn();
    let observerCallback;
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
    const root = {};
    const contains = vi.fn()
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(false);
    const body = { contains };

    expect(watchAddPreviewDetach(root, cleanup, {
      doc: { body },
      MutationObserverCtor,
    })).toBe(true);
    expect(observe).toHaveBeenCalledWith(body, { childList: true, subtree: true });

    observerCallback();
    expect(cleanup).not.toHaveBeenCalled();
    observerCallback();
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(disconnect).toHaveBeenCalledTimes(1);
  });

  it("returns false when MutationObserver setup fails", () => {
    expect(watchAddPreviewDetach({}, vi.fn(), {
      doc: { body: { contains: vi.fn(() => true) } },
      MutationObserverCtor: class {
        observe() {
          throw new Error("observe blocked");
        }
      },
    })).toBe(false);
  });
});
