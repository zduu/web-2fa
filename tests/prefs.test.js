import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyDensity,
  getDensity,
  LS_DENSITY,
  normalizeDensity,
  setDensity,
} from "../src/ui/prefs.js";

function installLocalStorage(storage) {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: storage,
  });
}

function createLocalStorage() {
  const store = new Map();
  return {
    getItem: (key) => store.has(key) ? store.get(key) : null,
    setItem: (key, value) => { store.set(key, String(value)); },
    removeItem: (key) => { store.delete(key); },
    clear: () => { store.clear(); },
  };
}

function installDocument(toggle = vi.fn()) {
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      body: {
        classList: { toggle },
      },
    },
  });
  return toggle;
}

beforeEach(() => {
  installLocalStorage(createLocalStorage());
  installDocument();
});

afterEach(() => {
  delete globalThis.localStorage;
  delete globalThis.document;
  vi.restoreAllMocks();
});

describe("density preferences", () => {
  it("normalizes density values", () => {
    expect(normalizeDensity("compact")).toBe("compact");
    expect(normalizeDensity(" COMPACT ")).toBe("compact");
    expect(normalizeDensity("comfortable")).toBe("comfortable");
    expect(normalizeDensity("bad")).toBe("comfortable");
  });

  it("persists density and applies the body class", () => {
    const toggle = installDocument();

    expect(setDensity("compact")).toBe("compact");
    expect(localStorage.getItem(LS_DENSITY)).toBe("compact");
    expect(toggle).toHaveBeenCalledWith("compact", true);
    expect(getDensity()).toBe("compact");

    expect(setDensity("bad")).toBe("comfortable");
    expect(localStorage.getItem(LS_DENSITY)).toBe("comfortable");
    expect(toggle).toHaveBeenLastCalledWith("compact", false);
  });

  it("uses safe defaults when localStorage or document is unavailable", () => {
    installLocalStorage({
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
    });
    delete globalThis.document;

    expect(getDensity()).toBe("comfortable");
    expect(() => setDensity("compact")).not.toThrow();
    expect(setDensity("compact")).toBe("compact");
    expect(applyDensity("compact")).toBe("compact");
  });
});
