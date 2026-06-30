import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildDrawerCloudShareCopyText,
  downloadDrawerTextFile,
  formatCloudProjectDataStatus,
  formatDrawerDeletedAtLabel,
  formatDrawerItemTitle,
  formatDrawerLastSyncLabel,
  formatDrawerProjectName,
  formatDrawerProjectTitle,
  formatDrawerShareAccessCount,
  formatDrawerSyncErrorToast,
  formatDrawerTimestamp,
  getDrawerLastSyncTimestamp,
  getDrawerProjectAutoInterval,
  getDrawerTimestamp,
  getSelectableCloudProjectIds,
  getSelectedCloudProjectIds,
  getSelectedCloudProjects,
  isSelectableCloudProject,
  readDrawerJsonResponse,
} from "../src/ui/drawer.js";

const originalDocument = globalThis.document;
const originalURL = globalThis.URL;

function setRuntimeConfig(config) {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __APP_RUNTIME__: config },
  });
}

afterEach(() => {
  delete globalThis.window;
  if (originalDocument === undefined) delete globalThis.document;
  else Object.defineProperty(globalThis, "document", { configurable: true, value: originalDocument });
  if (originalURL === undefined) delete globalThis.URL;
  else Object.defineProperty(globalThis, "URL", { configurable: true, value: originalURL });
});

describe("drawer display formatters", () => {
  it("formats cloud preview item titles with trimmed fields", () => {
    expect(formatDrawerItemTitle({
      issuer: " GitHub ",
      account: " me@example.com ",
    })).toBe("GitHub · me@example.com");
    expect(formatDrawerItemTitle({ issuer: " GitHub " })).toBe("GitHub");
    expect(formatDrawerItemTitle({ account: " me@example.com " })).toBe("me@example.com");
    expect(formatDrawerItemTitle({ issuer: " ", account: "" })).toBe("未命名账户");
  });

  it("formats cloud preview project names with a fallback", () => {
    expect(formatDrawerProjectName(" Work ")).toBe("Work");
    expect(formatDrawerProjectName(" ")).toBe("-");
  });

  it("formats editable project titles with trimmed name and id fallback", () => {
    expect(formatDrawerProjectTitle({ name: " Work ", id: "project-1" })).toBe("Work");
    expect(formatDrawerProjectTitle({ name: " ", id: " project-1 " })).toBe("project-1");
    expect(formatDrawerProjectTitle({ name: " ", id: " " })).toBe("未命名");
  });

  it("formats cloud project data status", () => {
    expect(formatCloudProjectDataStatus({ valid: false, hasData: false })).toBe("格式异常");
    expect(formatCloudProjectDataStatus({ valid: "false", hasData: true })).toBe("格式异常");
    expect(formatCloudProjectDataStatus({ valid: true, hasData: true })).toBe("有数据");
    expect(formatCloudProjectDataStatus({ valid: true, hasData: "true" })).toBe("有数据");
    expect(formatCloudProjectDataStatus({ valid: true, hasData: "false" })).toBe("空");
    expect(formatCloudProjectDataStatus({ valid: true, hasData: false })).toBe("空");
  });

  it("normalizes project auto interval values for drawer controls", () => {
    expect(getDrawerProjectAutoInterval({ autoInterval: 30_000 })).toBe(30_000);
    expect(getDrawerProjectAutoInterval({ autoInterval: "10000" })).toBe(10_000);
    expect(getDrawerProjectAutoInterval({ autoInterval: "bad" })).toBe(60_000);
    expect(getDrawerProjectAutoInterval({ autoInterval: -1 })).toBe(60_000);
  });

  it("formats last sync labels with invalid timestamps treated as unsynced", () => {
    expect(getDrawerLastSyncTimestamp({ lastSyncedAt: "bad" })).toBe(0);
    expect(getDrawerLastSyncTimestamp({ lastSyncedAt: -1 })).toBe(0);
    expect(formatDrawerLastSyncLabel({ lastSyncedAt: "bad" })).toBe("未同步");
    expect(formatDrawerLastSyncLabel({ lastSyncedAt: "bad" }, { localApp: true })).toBe("本地项目");
    expect(formatDrawerLastSyncLabel({ lastSyncedAt: 1 })).toMatch(/^上次同步：/);
  });

  it("formats drawer timestamps only when values are safe", () => {
    expect(getDrawerTimestamp("42.9")).toBe(42);
    expect(getDrawerTimestamp("bad")).toBe(0);
    expect(getDrawerTimestamp(Number.MAX_SAFE_INTEGER + 1)).toBe(0);
    expect(formatDrawerTimestamp("bad")).toBe("");
    expect(formatDrawerTimestamp(42)).not.toBe("");
    expect(formatDrawerTimestamp(42)).not.toMatch(/Invalid/i);
    expect(formatDrawerDeletedAtLabel("bad")).toBe("时间未知");
    expect(formatDrawerDeletedAtLabel(42)).toMatch(/^删除于 /);
  });

  it("formats share access counts from safe non-negative integers", () => {
    expect(formatDrawerShareAccessCount(3)).toBe("访问 3 次");
    expect(formatDrawerShareAccessCount("4.9")).toBe("访问 4 次");
    expect(formatDrawerShareAccessCount(-1)).toBe("访问 0 次");
    expect(formatDrawerShareAccessCount(Infinity)).toBe("访问 0 次");
    expect(formatDrawerShareAccessCount(Number.MAX_SAFE_INTEGER + 1)).toBe("访问 0 次");
  });

  it("builds cloud share copy links from the configured public base URL", () => {
    setRuntimeConfig({
      mode: "android-app",
      apiBaseUrl: "https://api.example.com/",
      publicBaseUrl: "https://public.example.com/app/",
    });

    expect(buildDrawerCloudShareCopyText({
      sid: " sid/a ",
      k: " share-key/value ",
    })).toEqual({
      type: "link",
      text: "https://public.example.com/app/shared.html?sid=sid%2Fa#k=share-key%2Fvalue",
    });

    expect(buildDrawerCloudShareCopyText({
      sid: "sid-safe",
      k: " safe-key ",
      showSecret: false,
    })).toEqual({
      type: "link",
      text: "https://public.example.com/app/shared.html?sid=sid-safe#ck=safe-key",
    });

    expect(buildDrawerCloudShareCopyText({
      sid: "sid-a",
      requiresPassword: true,
      protectedBundle: {
        wk: " wrapped/key ",
        iv: " iv ",
        s: " salt ",
        iter: "200000",
      },
    })).toEqual({
      type: "protected-link",
      text: "https://public.example.com/app/shared.html?sid=sid-a#wk=wrapped%2Fkey&iv=iv&s=salt&iter=200000",
    });

    expect(buildDrawerCloudShareCopyText({
      sid: "sid-protected-safe",
      requiresPassword: true,
      showSecret: false,
      protectedBundle: {
        wk: "wrapped",
        iv: "iv",
        s: "salt",
      },
    })).toEqual({
      type: "protected-link",
      text: "https://public.example.com/app/shared.html?sid=sid-protected-safe#wk=wrapped&iv=iv&s=salt&cm=1",
    });
  });

  it("falls back to copying the share sid when cloud share key material is unavailable", () => {
    expect(buildDrawerCloudShareCopyText({ sid: " sid-a ", requiresPassword: true })).toEqual({
      type: "protected-sid",
      text: "sid-a",
    });
    expect(buildDrawerCloudShareCopyText({ sid: " sid-b " })).toEqual({
      type: "sid",
      text: "sid-b",
    });
  });

  it("downloads drawer text through the shared blob helper", async () => {
    const anchor = {
      href: "",
      download: "",
      click: vi.fn(),
    };
    const createObjectURL = vi.fn(() => "blob:drawer-text");
    const revokeObjectURL = vi.fn();

    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: {
        createElement: vi.fn(() => anchor),
      },
    });
    Object.defineProperty(globalThis, "URL", {
      configurable: true,
      value: { createObjectURL, revokeObjectURL },
    });

    expect(downloadDrawerTextFile("demo.txt", "drawer text")).toBe(true);
    expect(anchor.href).toBe("blob:drawer-text");
    expect(anchor.download).toBe("demo.txt");
    expect(anchor.click).toHaveBeenCalledTimes(1);
    expect(await createObjectURL.mock.calls[0][0].text()).toBe("drawer text");
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:drawer-text");
  });

  it("selects only valid cloud projects for bulk operations", () => {
    const projects = [
      { syncId: " good ", metadata: { valid: true } },
      { syncId: "bad", metadata: { valid: false } },
      { syncId: "bad-string", metadata: { valid: "false" } },
      { syncId: "", metadata: { valid: true } },
    ];

    expect(isSelectableCloudProject(projects[0])).toBe(true);
    expect(isSelectableCloudProject(projects[1])).toBe(false);
    expect(isSelectableCloudProject(projects[2])).toBe(false);
    expect(getSelectableCloudProjectIds(projects)).toEqual(["good"]);
    expect(getSelectedCloudProjectIds(projects, new Set())).toEqual(["good"]);
    expect(getSelectedCloudProjectIds(projects, new Set(["bad"]))).toEqual([]);
    expect(getSelectedCloudProjectIds(projects, new Set(), { requireExplicitSelection: true })).toEqual([]);
    expect(getSelectedCloudProjects(projects, new Set()).map((project) => project.syncId)).toEqual([" good "]);
  });

  it("reads drawer JSON responses and surfaces server error states", async () => {
    await expect(readDrawerJsonResponse(new Response(JSON.stringify({ success: true, items: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }))).resolves.toEqual({ success: true, items: [] });

    await expect(readDrawerJsonResponse(new Response(JSON.stringify({ success: false, error: "Unauthorized" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }))).rejects.toThrow("Unauthorized");

    await expect(readDrawerJsonResponse(new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Note": "kv-missing" },
    }))).rejects.toThrow("AUTH_KV");

    await expect(readDrawerJsonResponse(new Response("nope", { status: 503 })))
      .rejects.toThrow("HTTP 503");
  });

  it("classifies drawer sync errors for user-facing toasts", () => {
    expect(formatDrawerSyncErrorToast({ code: "empty", message: "ignored" })).toEqual({
      message: "云端暂无数据",
      type: "warn",
    });
    expect(formatDrawerSyncErrorToast({ code: "deleted", message: "云端项目已删除，可在回收站恢复" })).toEqual({
      message: "云端项目已删除，可在回收站恢复",
      type: "warn",
    });
    expect(formatDrawerSyncErrorToast({ message: "拉取失败：500" })).toEqual({
      message: "拉取失败：500",
      type: "err",
    });
    expect(formatDrawerSyncErrorToast(null)).toEqual({
      message: "同步失败",
      type: "err",
    });
  });
});
