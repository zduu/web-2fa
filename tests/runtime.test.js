import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  apiUrl,
  canUseCloudApis,
  clearCloudBaseUrls,
  getApiBaseUrl,
  getAppMode,
  getCloudBaseUrls,
  getPublicBaseUrl,
  isAndroidApp,
  setCloudBaseUrls,
} from "../src/core/runtime.js";

const LS_API_BASE_URL = "authenticator.v1.cloudApiBaseUrl";
const LS_PUBLIC_BASE_URL = "authenticator.v1.cloudPublicBaseUrl";

function installLocalStorage() {
  const store = new Map();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key) => store.has(key) ? store.get(key) : null,
      setItem: (key, value) => { store.set(key, String(value)); },
      removeItem: (key) => { store.delete(key); },
      clear: () => { store.clear(); },
    },
  });
}

function setRuntimeConfig(config) {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __APP_RUNTIME__: config },
  });
}

function setLocationOrigin(origin) {
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { origin },
  });
}

beforeEach(() => {
  installLocalStorage();
  setRuntimeConfig({});
  setLocationOrigin("https://app.example.com/");
});

afterEach(() => {
  delete globalThis.localStorage;
  delete globalThis.window;
  delete globalThis.location;
});

describe("runtime URL helpers", () => {
  it("uses web defaults and normalizes configured API URL paths", () => {
    expect(getAppMode()).toBe("web");
    expect(getPublicBaseUrl()).toBe("https://app.example.com");
    expect(apiUrl("api/health")).toBe("/api/health");
    expect(canUseCloudApis()).toBe(true);

    setRuntimeConfig({
      apiBaseUrl: " https://api.example.com/base/// ",
      publicBaseUrl: " https://public.example.com/app/ ",
    });

    expect(getApiBaseUrl()).toBe("https://api.example.com/base");
    expect(getPublicBaseUrl()).toBe("https://public.example.com/app");
    expect(apiUrl("api/share/list")).toBe("https://api.example.com/base/api/share/list");
    expect(apiUrl("https://other.example.com/api?x=1#hash")).toBe("https://other.example.com/api?x=1#hash");
  });

  it("falls back to web defaults when runtime config cannot be read", () => {
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {},
    });
    Object.defineProperty(globalThis.window, "__APP_RUNTIME__", {
      configurable: true,
      get() {
        throw new Error("blocked");
      },
    });

    expect(getAppMode()).toBe("web");
    expect(getApiBaseUrl()).toBe("");
    expect(getPublicBaseUrl()).toBe("https://app.example.com");
    expect(canUseCloudApis()).toBe(true);
  });

  it("requires an Android API URL before accepting a public URL override", () => {
    setRuntimeConfig({ mode: "android-app" });

    expect(isAndroidApp()).toBe(true);
    expect(canUseCloudApis()).toBe(false);
    expect(() => setCloudBaseUrls({ publicBaseUrl: "https://public.example.com" })).toThrow("请先填写云端 API 地址");
    expect(localStorage.getItem(LS_PUBLIC_BASE_URL)).toBeNull();
  });

  it("normalizes runtime app mode casing and whitespace", () => {
    setRuntimeConfig({ mode: " Android-App " });
    expect(getAppMode()).toBe("android-app");
    expect(isAndroidApp()).toBe(true);

    setRuntimeConfig({ mode: " LOCAL-APP " });
    expect(getAppMode()).toBe("local-app");
    expect(canUseCloudApis()).toBe(false);
  });

  it("normalizes Android cloud URL overrides and reports effective public URL", () => {
    setRuntimeConfig({
      mode: "android-app",
      apiBaseUrl: "https://default.example.com/api/",
      publicBaseUrl: "https://default.example.com/app/",
    });

    const saved = setCloudBaseUrls({
      apiBaseUrl: " https://api.example.com/v1/?token=x#hash ",
      publicBaseUrl: " https://public.example.com/app///?x=1#hash ",
    });

    expect(saved).toEqual({
      apiBaseUrl: "https://api.example.com/v1",
      publicBaseUrl: "https://public.example.com/app",
    });
    expect(localStorage.getItem(LS_API_BASE_URL)).toBe("https://api.example.com/v1");
    expect(localStorage.getItem(LS_PUBLIC_BASE_URL)).toBe("https://public.example.com/app");
    expect(getCloudBaseUrls()).toMatchObject(saved);

    const apiOnly = setCloudBaseUrls({
      apiBaseUrl: "https://api-only.example.com/base/",
      publicBaseUrl: "   ",
    });

    expect(apiOnly).toEqual({
      apiBaseUrl: "https://api-only.example.com/base",
      publicBaseUrl: "https://api-only.example.com/base",
    });
    expect(localStorage.getItem(LS_PUBLIC_BASE_URL)).toBeNull();
    expect(getPublicBaseUrl()).toBe("https://api-only.example.com/base");
    expect(getCloudBaseUrls().publicBaseUrl).toBe("https://api-only.example.com/base");
  });

  it("clears Android cloud URL overrides without changing packaged defaults", () => {
    setRuntimeConfig({
      mode: "android-app",
      apiBaseUrl: "https://default.example.com/api/",
      publicBaseUrl: "https://default.example.com/app/",
    });

    setCloudBaseUrls({ apiBaseUrl: "https://api.example.com" });
    clearCloudBaseUrls();

    expect(localStorage.getItem(LS_API_BASE_URL)).toBeNull();
    expect(localStorage.getItem(LS_PUBLIC_BASE_URL)).toBeNull();
    expect(getCloudBaseUrls()).toEqual({
      apiBaseUrl: "https://default.example.com/api",
      publicBaseUrl: "https://default.example.com/app",
      defaultApiBaseUrl: "https://default.example.com/api",
      defaultPublicBaseUrl: "https://default.example.com/app",
    });
  });
});
