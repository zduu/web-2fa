import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  bindIdleWatcherEvents,
  getIdleVisibilityState,
  getHiddenMinutes,
  getIdleMinutes,
  LS_HIDDEN_LOCK,
  LS_IDLE_LOCK,
  normalizeLockMinutes,
  setHiddenMinutes,
  setIdleMinutes,
  startIdleWatcher,
  stopIdleWatcher,
} from "../src/core/idle.js";
import {
  clearUnlockFails,
  getUnlockBlockMs,
  normalizeFailCount,
  normalizeSessionTimestamp,
  recordUnlockFail,
} from "../src/core/password-strength.js";

function installStorage(name) {
  const store = new Map();
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value: {
      getItem: (key) => store.has(key) ? store.get(key) : null,
      setItem: (key, value) => { store.set(key, String(value)); },
      removeItem: (key) => { store.delete(key); },
      clear: () => { store.clear(); },
    },
  });
}

function installBlockedStorage(name) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value: {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
      removeItem: () => { throw new Error("blocked"); },
    },
  });
}

const originalDocumentDescriptor = Object.getOwnPropertyDescriptor(globalThis, "document");
const originalWindowDescriptor = Object.getOwnPropertyDescriptor(globalThis, "window");

function restoreGlobalProperty(name, descriptor) {
  if (descriptor) Object.defineProperty(globalThis, name, descriptor);
  else delete globalThis[name];
}

beforeEach(() => {
  installStorage("localStorage");
  installStorage("sessionStorage");
});

afterEach(() => {
  vi.useRealTimers();
  stopIdleWatcher();
  delete globalThis.localStorage;
  delete globalThis.sessionStorage;
  restoreGlobalProperty("document", originalDocumentDescriptor);
  restoreGlobalProperty("window", originalWindowDescriptor);
});

describe("local security settings", () => {
  it("normalizes idle and hidden lock minutes", () => {
    expect(normalizeLockMinutes("15.9", 10)).toBe(15);
    expect(normalizeLockMinutes("1e999", 10)).toBe(10);
    expect(normalizeLockMinutes("-1", 10)).toBe(10);
    expect(normalizeLockMinutes("2000", 10)).toBe(1440);

    localStorage.setItem(LS_IDLE_LOCK, "1e999");
    localStorage.setItem(LS_HIDDEN_LOCK, "-1");
    expect(getIdleMinutes()).toBe(10);
    expect(getHiddenMinutes()).toBe(5);

    setIdleMinutes("2000");
    setHiddenMinutes("7.9");
    expect(localStorage.getItem(LS_IDLE_LOCK)).toBe("1440");
    expect(localStorage.getItem(LS_HIDDEN_LOCK)).toBe("7");
  });

  it("normalizes unlock failure backoff session values", () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);

    expect(normalizeFailCount("2.9")).toBe(2);
    expect(normalizeFailCount("1e999")).toBe(0);
    expect(normalizeSessionTimestamp("1001000.9")).toBe(1_001_000);
    expect(normalizeSessionTimestamp("1e999")).toBe(0);

    sessionStorage.setItem("authenticator.v1.unlockFails", "1e999");
    expect(recordUnlockFail()).toBe(0);
    expect(sessionStorage.getItem("authenticator.v1.unlockFails")).toBe("1");

    sessionStorage.setItem("authenticator.v1.unlockBlockUntil", "1002000.9");
    expect(getUnlockBlockMs()).toBe(2000);

    sessionStorage.setItem("authenticator.v1.unlockBlockUntil", "1e999");
    expect(getUnlockBlockMs()).toBe(0);
  });

  it("uses safe defaults when local lock storage is unavailable", () => {
    installBlockedStorage("localStorage");

    expect(getIdleMinutes()).toBe(10);
    expect(getHiddenMinutes()).toBe(5);
    expect(() => setIdleMinutes(15)).not.toThrow();
    expect(() => setHiddenMinutes(20)).not.toThrow();
  });

  it("does not throw when idle watcher starts outside a browser document", () => {
    delete globalThis.document;
    delete globalThis.window;

    expect(() => startIdleWatcher(() => {})).not.toThrow();
  });

  it("reads idle visibility state safely", () => {
    expect(getIdleVisibilityState({ visibilityState: "hidden" })).toBe("hidden");
    expect(getIdleVisibilityState({ visibilityState: "visible" })).toBe("visible");
    expect(getIdleVisibilityState(null)).toBe("");
    expect(getIdleVisibilityState(Object.defineProperty({}, "visibilityState", {
      get() {
        throw new Error("blocked");
      },
    }))).toBe("");
  });

  it("binds idle watcher activity and visibility handlers through safe targets", () => {
    const listeners = {};
    const doc = {
      visibilityState: "hidden",
      addEventListener: vi.fn((name, listener) => {
        listeners[name] = listener;
      }),
    };
    const win = {
      addEventListener: vi.fn((name, listener) => {
        listeners[name] = listener;
      }),
    };
    const onActivity = vi.fn();
    const onHidden = vi.fn();
    const onVisible = vi.fn();

    expect(bindIdleWatcherEvents({ doc, win, onActivity, onHidden, onVisible })).toBe(true);
    expect(win.addEventListener).toHaveBeenCalledWith("mousemove", onActivity, { passive: true });
    expect(win.addEventListener).toHaveBeenCalledWith("wheel", onActivity, { passive: true });
    expect(doc.addEventListener).toHaveBeenCalledWith("visibilitychange", expect.any(Function));

    listeners.mousemove();
    listeners.visibilitychange();
    doc.visibilityState = "visible";
    listeners.visibilitychange();

    expect(onActivity).toHaveBeenCalledTimes(1);
    expect(onHidden).toHaveBeenCalledTimes(1);
    expect(onVisible).toHaveBeenCalledTimes(1);
  });

  it("tolerates blocked idle watcher listener targets", () => {
    expect(bindIdleWatcherEvents({ doc: null, win: null })).toBe(false);
    expect(bindIdleWatcherEvents({
      doc: { addEventListener: () => { throw new Error("blocked"); } },
      win: { addEventListener: () => { throw new Error("blocked"); } },
    })).toBe(false);
  });

  it("does not throw when unlock backoff session storage is unavailable", () => {
    installBlockedStorage("sessionStorage");

    expect(getUnlockBlockMs()).toBe(0);
    expect(recordUnlockFail()).toBe(0);
    expect(() => clearUnlockFails()).not.toThrow();
  });
});
