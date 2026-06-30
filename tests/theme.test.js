import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyTheme,
  dispatchThemeChanged,
  getThemePreference,
  initTheme,
  LS_THEME,
  normalizeThemePreference,
  resolveTheme,
  setThemePreference,
} from "../src/ui/theme.js";

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

function installDocument({ meta = null } = {}) {
  const root = { dataset: {}, style: {} };
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      documentElement: root,
      querySelector: vi.fn(() => meta),
    },
  });
  return root;
}

function installWindow(windowValue = {}) {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: windowValue,
  });
}

beforeEach(() => {
  installLocalStorage(createLocalStorage());
  installDocument();
  installWindow();
});

afterEach(() => {
  delete globalThis.localStorage;
  delete globalThis.document;
  delete globalThis.window;
  delete globalThis.CustomEvent;
  vi.restoreAllMocks();
});

describe("theme preferences", () => {
  it("normalizes theme preference values and stored preference", () => {
    expect(normalizeThemePreference("dark")).toBe("dark");
    expect(normalizeThemePreference("light")).toBe("light");
    expect(normalizeThemePreference("auto")).toBe("auto");
    expect(normalizeThemePreference(" AUTO ")).toBe("auto");
    expect(normalizeThemePreference(" LIGHT ")).toBe("light");
    expect(normalizeThemePreference("bad")).toBe("dark");

    localStorage.setItem(LS_THEME, "bad");
    expect(getThemePreference()).toBe("dark");
    localStorage.setItem(LS_THEME, "auto");
    expect(getThemePreference()).toBe("auto");
  });

  it("resolves auto theme from matchMedia with safe fallback", () => {
    installWindow({ matchMedia: vi.fn(() => ({ matches: false })) });
    expect(resolveTheme("auto")).toBe("light");

    installWindow({ matchMedia: vi.fn(() => { throw new Error("blocked"); }) });
    expect(resolveTheme("auto")).toBe("dark");
    expect(resolveTheme("bad")).toBe("dark");
  });

  it("applies normalized theme state to document and theme-color meta", () => {
    const meta = { setAttribute: vi.fn() };
    const root = installDocument({ meta });

    expect(applyTheme("light")).toEqual({ preference: "light", resolved: "light" });
    expect(root.dataset).toEqual({ theme: "light", themeResolved: "light" });
    expect(root.style.colorScheme).toBe("light");
    expect(meta.setAttribute).toHaveBeenCalledWith("content", "#f4f7fb");

    expect(applyTheme("bad")).toEqual({ preference: "dark", resolved: "dark" });
    expect(root.dataset.theme).toBe("dark");
  });

  it("uses safe defaults when storage or document is unavailable", () => {
    installLocalStorage({
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
    });
    delete globalThis.document;

    expect(getThemePreference()).toBe("dark");
    expect(applyTheme("auto")).toEqual({ preference: "auto", resolved: "dark" });
    expect(() => setThemePreference("light")).not.toThrow();
    expect(setThemePreference("light")).toEqual({ preference: "light", resolved: "light" });
  });

  it("dispatches theme change events with CustomEvent details", () => {
    const dispatchEvent = vi.fn();
    installWindow({ dispatchEvent });
    Object.defineProperty(globalThis, "CustomEvent", {
      configurable: true,
      value: class CustomEventMock extends Event {
        constructor(type, options = {}) {
          super(type);
          this.detail = options.detail;
        }
      },
    });

    expect(dispatchThemeChanged({ preference: "dark", resolved: "dark" })).toBe(true);
    expect(dispatchEvent).toHaveBeenCalledTimes(1);
    expect(dispatchEvent.mock.calls[0][0]).toBeInstanceOf(globalThis.CustomEvent);
    expect(dispatchEvent.mock.calls[0][0].detail).toEqual({ preference: "dark", resolved: "dark" });
  });

  it("falls back to Event when CustomEvent is unavailable", () => {
    const dispatchEvent = vi.fn();
    installWindow({ dispatchEvent });
    delete globalThis.CustomEvent;

    expect(dispatchThemeChanged({ preference: "light", resolved: "light" })).toBe(true);
    expect(dispatchEvent.mock.calls[0][0]).toBeInstanceOf(Event);
    expect(dispatchEvent.mock.calls[0][0].type).toBe("theme-changed");
  });

  it("initializes auto theme listener with legacy matchMedia APIs", () => {
    const addListener = vi.fn();
    installWindow({
      matchMedia: vi.fn(() => ({ matches: true, addListener })),
    });

    localStorage.setItem(LS_THEME, "auto");
    expect(initTheme()).toEqual({ preference: "auto", resolved: "dark" });
    expect(addListener).toHaveBeenCalledTimes(1);
  });
});
