import { afterEach, describe, expect, it, vi } from "vitest";

import {
  bindHomeTickerEvents,
  dispatchHomeEvent,
  formatItemName,
  formatProjectName,
  getCardActions,
  setCardActions,
} from "../src/ui/home.js";

const originalWindow = globalThis.window;
const originalCustomEvent = globalThis.CustomEvent;
const originalEvent = globalThis.Event;

afterEach(() => {
  if (originalWindow === undefined) delete globalThis.window;
  else Object.defineProperty(globalThis, "window", { configurable: true, value: originalWindow });
  if (originalCustomEvent === undefined) delete globalThis.CustomEvent;
  else Object.defineProperty(globalThis, "CustomEvent", { configurable: true, value: originalCustomEvent });
  if (originalEvent === undefined) delete globalThis.Event;
  else Object.defineProperty(globalThis, "Event", { configurable: true, value: originalEvent });
  setCardActions({});
  vi.restoreAllMocks();
});

describe("formatItemName", () => {
  it("formats trimmed issuer and account display names", () => {
    expect(formatItemName({
      issuer: " GitHub ",
      account: " me@example.com ",
    })).toBe("GitHub · me@example.com");
    expect(formatItemName({ issuer: " GitHub " })).toBe("GitHub");
    expect(formatItemName({ account: " me@example.com " })).toBe("me@example.com");
    expect(formatItemName({ issuer: " ", account: "" })).toBe("未命名账户");
  });
});

describe("formatProjectName", () => {
  it("formats project names with trimmed fallback", () => {
    expect(formatProjectName(" Work ")).toBe("Work");
    expect(formatProjectName(" ")).toBe("未命名");
  });
});

describe("dispatchHomeEvent", () => {
  it("dispatches CustomEvent details when available", () => {
    const dispatchEvent = vi.fn();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { dispatchEvent },
    });

    expect(dispatchHomeEvent("data-changed", { source: "test" })).toBe(true);
    expect(dispatchEvent).toHaveBeenCalledTimes(1);
    expect(dispatchEvent.mock.calls[0][0]).toBeInstanceOf(CustomEvent);
    expect(dispatchEvent.mock.calls[0][0].detail).toEqual({ source: "test" });
  });

  it("falls back to Event when CustomEvent is unavailable", () => {
    const dispatchEvent = vi.fn();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { dispatchEvent },
    });
    delete globalThis.CustomEvent;

    expect(dispatchHomeEvent("data-changed", { ignored: true })).toBe(true);
    expect(dispatchEvent.mock.calls[0][0]).toBeInstanceOf(Event);
    expect(dispatchEvent.mock.calls[0][0].type).toBe("data-changed");
  });

  it("returns false when no event target is available", () => {
    delete globalThis.window;

    expect(dispatchHomeEvent("data-changed")).toBe(false);
  });
});

describe("bindHomeTickerEvents", () => {
  it("binds visible and focus refresh handlers when targets support events", () => {
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
    const onVisible = vi.fn();
    const onFocus = vi.fn();

    expect(bindHomeTickerEvents({ doc, win, onVisible, onFocus })).toBe(true);
    expect(doc.addEventListener).toHaveBeenCalledWith("visibilitychange", expect.any(Function));
    expect(win.addEventListener).toHaveBeenCalledWith("focus", expect.any(Function));

    listeners.visibilitychange();
    expect(onVisible).not.toHaveBeenCalled();
    doc.visibilityState = "visible";
    listeners.visibilitychange();
    listeners.focus();

    expect(onVisible).toHaveBeenCalledTimes(1);
    expect(onFocus).toHaveBeenCalledTimes(1);
  });

  it("returns false when listener targets are missing or throw during setup", () => {
    expect(bindHomeTickerEvents({ doc: null, win: null })).toBe(false);
    expect(bindHomeTickerEvents({
      doc: { addEventListener: () => { throw new Error("boom"); } },
      win: { addEventListener: () => { throw new Error("boom"); } },
    })).toBe(false);
  });
});

describe("card actions", () => {
  it("stores actions on window when available", () => {
    const onEdit = vi.fn();
    const win = {};
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: win,
    });

    expect(setCardActions({ onEdit })).toBe(true);
    expect(win.__cardActions.onEdit).toBe(onEdit);
    expect(getCardActions().onEdit).toBe(onEdit);
  });

  it("falls back to module state when window is unavailable", () => {
    const onDelete = vi.fn();
    delete globalThis.window;

    expect(setCardActions({ onDelete })).toBe(false);
    expect(getCardActions().onDelete).toBe(onDelete);
  });
});
