import { afterEach, describe, expect, it, vi } from "vitest";

import {
  deriveSyncKey,
  syncEncrypt,
} from "../src/core/crypto.js";
import {
  bindAutoSyncVisibilityEvents,
  dispatchSyncEvent,
  deleteCloudProject,
  getSyncEndpoint,
  isDocumentVisible,
  itemKey,
  mergeItems,
  normalizeSyncRouteId,
  pullCurrent,
  pushCurrent,
  pushProject,
  startAutoSync,
  stopAutoSync,
} from "../src/sync/sync.js";
import { normalizeProjectItemOrder } from "../src/sync/projects.js";
import {
  buildDecryptedExportRecord,
  buildDecryptedExportFiles,
  decryptCloudAll,
  getDecryptableCloudProjects,
  isDecryptableCloudProject,
  listAllCloudProjects,
  normalizeCloudConcurrency,
  normalizeCloudSecrets,
} from "../src/sync/cloud.js";
import { state } from "../src/core/storage.js";
import { parseOtpAuth } from "../src/core/totp.js";

const originalCustomEventDescriptor = Object.getOwnPropertyDescriptor(globalThis, "CustomEvent");
const originalDocumentDescriptor = Object.getOwnPropertyDescriptor(globalThis, "document");
const originalWindowDescriptor = Object.getOwnPropertyDescriptor(globalThis, "window");

function restoreGlobalProperty(name, descriptor) {
  if (descriptor) {
    Object.defineProperty(globalThis, name, descriptor);
  } else {
    delete globalThis[name];
  }
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  state.items = [];
  state.syncProjects = [];
  state.currentProjectId = null;
  state.globalToken = "";
  stopAutoSync();
  restoreGlobalProperty("CustomEvent", originalCustomEventDescriptor);
  restoreGlobalProperty("document", originalDocumentDescriptor);
  restoreGlobalProperty("window", originalWindowDescriptor);
});

describe("sync route ids", () => {
  it("normalizes Sync IDs before building API endpoints", () => {
    expect(normalizeSyncRouteId(" project/id ")).toBe("project/id");
    expect(getSyncEndpoint(" project/id ")).toBe("/api/sync/project%2Fid");
  });

  it("rejects Sync IDs that would collide with KV namespaces or contain controls", () => {
    expect(normalizeSyncRouteId("sync:demo")).toBe("");
    expect(normalizeSyncRouteId("share:demo")).toBe("");
    expect(normalizeSyncRouteId("demo\nid")).toBe("");

    try {
      getSyncEndpoint("sync:demo");
      throw new Error("expected getSyncEndpoint to throw");
    } catch (error) {
      expect(error.code).toBe("invalid-sync-id");
    }
  });

  it("fails current project push before fetch when Sync ID is invalid", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK"));
    state.currentProjectId = "p1";
    state.syncProjects = [{ id: "p1", syncId: "sync:demo", secret: "secret", itemsData: [] }];

    await expect(pushCurrent()).rejects.toMatchObject({ code: "invalid-sync-id" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces soft-deleted cloud projects during pull", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Gone", {
      status: 410,
      headers: { "X-Note": "soft-deleted" },
    }));
    state.currentProjectId = "p1";
    state.syncProjects = [{ id: "p1", syncId: "demo", secret: "secret", itemsData: [] }];

    await expect(pullCurrent()).rejects.toMatchObject({
      code: "deleted",
      status: 410,
      message: "云端项目已删除，可在回收站恢复",
    });
  });

  it("surfaces sync KV missing notes during push, pull, and delete", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Not configured", {
      status: 503,
      headers: { "X-Note": "kv-missing" },
    }));
    state.currentProjectId = "p1";
    state.syncProjects = [{ id: "p1", syncId: "demo", secret: "secret", itemsData: [] }];
    state.globalToken = "admin-token";

    await expect(pushCurrent()).rejects.toMatchObject({
      code: "http",
      status: 503,
      note: "kv-missing",
      message: "服务端未绑定 AUTH_KV",
    });
    await expect(pullCurrent()).rejects.toMatchObject({
      code: "http",
      status: 503,
      note: "kv-missing",
      message: "服务端未绑定 AUTH_KV",
    });
    await expect(deleteCloudProject("demo")).rejects.toMatchObject({
      code: "http",
      status: 503,
      note: "kv-missing",
      message: "服务端未绑定 AUTH_KV",
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("surfaces sync errors from project pushes", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Server Error", {
      status: 200,
      headers: { "X-Note": "error" },
    }));
    const proj = { id: "p1", syncId: "demo", secret: "secret", itemsData: [] };

    await expect(pushProject(proj)).rejects.toMatchObject({
      code: "http",
      status: 200,
      note: "error",
      message: "推送失败：服务端错误",
    });
    expect(proj.lastSyncedAt).toBeUndefined();
  });

  it("surfaces GitHub backup warnings without failing successful pushes", async () => {
    const dispatchEvent = vi.fn();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { dispatchEvent },
    });
    Object.defineProperty(globalThis, "CustomEvent", {
      configurable: true,
      value: class CustomEventMock extends Event {
        constructor(type, options = {}) {
          super(type);
          this.detail = options.detail;
        }
      },
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", {
      status: 200,
      headers: { "X-Note": "github-backup-failed" },
    }));
    state.currentProjectId = "p1";
    state.syncProjects = [{ id: "p1", syncId: "demo", secret: "secret", itemsData: [] }];

    await expect(pushCurrent()).resolves.toBeUndefined();

    expect(state.syncProjects[0].lastSyncedAt).toEqual(expect.any(Number));
    expect(dispatchEvent).toHaveBeenCalledTimes(1);
    expect(dispatchEvent.mock.calls[0][0].type).toBe("sync-warning");
    expect(dispatchEvent.mock.calls[0][0].detail).toMatchObject({
      note: "github-backup-failed",
      message: "GitHub 备份失败",
    });
  });

  it("does not treat 200 sync responses with error notes as successful pushes", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Server Error", {
      status: 200,
      headers: { "X-Note": "error" },
    }));
    state.currentProjectId = "p1";
    state.syncProjects = [{ id: "p1", syncId: "demo", secret: "secret", itemsData: [] }];

    await expect(pushCurrent()).rejects.toMatchObject({
      code: "http",
      status: 200,
      note: "error",
      message: "推送失败：服务端错误",
    });
    expect(state.syncProjects[0].lastSyncedAt).toBeUndefined();
  });

  it("keeps soft-delete success notes accepted for cloud deletes", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", {
      status: 200,
      headers: { "X-Note": "soft-delete" },
    }));
    state.globalToken = "admin-token";

    await expect(deleteCloudProject("demo")).resolves.toBeUndefined();
  });
});

describe("auto sync scheduler", () => {
  it("does not throw when started outside a browser document", () => {
    delete globalThis.document;
    delete globalThis.window;

    expect(() => startAutoSync()).not.toThrow();
  });

  it("checks document visibility without leaking global document failures", () => {
    expect(isDocumentVisible({ visibilityState: "visible" })).toBe(true);
    expect(isDocumentVisible({ visibilityState: "hidden" })).toBe(false);
    expect(isDocumentVisible(null)).toBe(false);
    expect(isDocumentVisible(Object.defineProperty({}, "visibilityState", {
      get() {
        throw new Error("blocked");
      },
    }))).toBe(false);
  });

  it("binds visibility and online events through captured targets", () => {
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
    const onHidden = vi.fn();
    const onOnline = vi.fn();

    expect(bindAutoSyncVisibilityEvents({ doc, win, onVisible, onHidden, onOnline })).toBe(true);
    expect(doc.addEventListener).toHaveBeenCalledWith("visibilitychange", expect.any(Function));
    expect(win.addEventListener).toHaveBeenCalledWith("online", expect.any(Function));

    listeners.visibilitychange();
    expect(onHidden).toHaveBeenCalledTimes(1);
    doc.visibilityState = "visible";
    listeners.visibilitychange();
    listeners.online();

    expect(onVisible).toHaveBeenCalledTimes(1);
    expect(onOnline).toHaveBeenCalledTimes(1);
  });

  it("tolerates missing or blocked auto-sync listener targets", () => {
    expect(bindAutoSyncVisibilityEvents({ doc: null, win: null })).toBe(false);
    expect(bindAutoSyncVisibilityEvents({
      doc: { addEventListener: () => { throw new Error("blocked"); } },
      win: { addEventListener: () => { throw new Error("blocked"); } },
    })).toBe(false);
  });

  it("dispatches sync events with CustomEvent details when available", () => {
    const originalWindow = globalThis.window;
    const originalCustomEvent = globalThis.CustomEvent;
    const dispatchEvent = vi.fn();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { dispatchEvent },
    });
    Object.defineProperty(globalThis, "CustomEvent", {
      configurable: true,
      value: class CustomEventMock extends Event {
        constructor(type, options = {}) {
          super(type);
          this.detail = options.detail;
        }
      },
    });

    expect(dispatchSyncEvent("sync-failed", { attempt: 1 })).toBe(true);
    expect(dispatchEvent).toHaveBeenCalledTimes(1);
    expect(dispatchEvent.mock.calls[0][0]).toBeInstanceOf(globalThis.CustomEvent);
    expect(dispatchEvent.mock.calls[0][0].detail).toEqual({ attempt: 1 });

    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
    if (originalCustomEvent === undefined) delete globalThis.CustomEvent;
    else globalThis.CustomEvent = originalCustomEvent;
  });

  it("falls back to Event for sync events when CustomEvent is unavailable", () => {
    const originalWindow = globalThis.window;
    const dispatchEvent = vi.fn();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { dispatchEvent },
    });
    delete globalThis.CustomEvent;

    expect(dispatchSyncEvent("sync-recovered", { ignored: true })).toBe(true);
    expect(dispatchEvent.mock.calls[0][0]).toBeInstanceOf(Event);
    expect(dispatchEvent.mock.calls[0][0].type).toBe("sync-recovered");

    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
  });

  it("returns false for sync events without a window event target", () => {
    const originalWindow = globalThis.window;
    delete globalThis.window;

    expect(dispatchSyncEvent("sync-give-up")).toBe(false);

    if (originalWindow === undefined) delete globalThis.window;
    else globalThis.window = originalWindow;
  });
});

describe("mergeItems", () => {
  it("builds stable item keys from unnormalized OTP values", () => {
    expect(itemKey({
      type: "TOTP",
      secret: " jbsw-y3dp==== ",
      issuer: " GitHub ",
      account: " me@example.com ",
    })).toBe(itemKey({
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    }));

    expect(itemKey({
      type: "HOTP",
      secret: " jbsw-y3dp==== ",
      issuer: "GitHub",
      account: "counter@example.com",
    })).toBe(itemKey({
      type: "hotp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "counter@example.com",
    }));
  });

  it("keeps the latest version while merging share metadata", () => {
    const result = mergeItems(
      [
        {
          type: "totp",
          secret: "jbswy3dp",
          issuer: "GitHub",
          account: "me@example.com",
          algorithm: "SHA1",
          digits: 6,
          period: 30,
          updatedAt: 10,
          shares: [{ sid: " sid-a " }],
        },
        {
          type: "totp",
          secret: "MFRGGZDFMZTWQ2LK",
          issuer: "Google",
          account: "me@example.com",
          updatedAt: 50,
          shares: [{ sid: "sid-x" }],
        },
      ],
      [
        {
          type: "totp",
          secret: "JBSWY3DP",
          issuer: "GitHub",
          account: "me@example.com",
          algorithm: "sha256",
          digits: 8,
          period: 45,
          updatedAt: 20,
          shares: [{ sid: "sid-a", k: "share-key" }, { sid: " sid-b " }, { sid: " " }],
        },
        {
          type: "totp",
          secret: "MFRGGZDFMZTWQ2LK",
          issuer: "Google",
          account: "me@example.com",
          updatedAt: 40,
          shares: [{ sid: "sid-y" }],
        },
      ],
    );

    expect(result).toHaveLength(2);
    expect(result).toContainEqual(expect.objectContaining({
      issuer: "GitHub",
      algorithm: "SHA256",
      digits: 8,
      period: 45,
      updatedAt: 20,
      shares: [
        { sid: "sid-a", k: "share-key" },
        { sid: "sid-b" },
      ],
    }));
    expect(result).toContainEqual(expect.objectContaining({
      issuer: "Google",
      updatedAt: 50,
      shares: [
        { sid: "sid-x" },
        { sid: "sid-y" },
      ],
    }));
  });

  it("merges unnormalized semantically identical OTP items", () => {
    const result = mergeItems(
      [{
        type: "totp",
        secret: " jbsw y3dp==== ",
        issuer: " GitHub ",
        account: " me@example.com ",
        updatedAt: 10,
      }],
      [{
        type: "totp",
        secret: "JBSWY3DP",
        issuer: "GitHub",
        account: "me@example.com",
        updatedAt: 20,
      }],
    );

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      secret: "JBSWY3DP",
      updatedAt: 20,
    });
  });

  it("ignores invalid updatedAt values when choosing the latest merged item", () => {
    const result = mergeItems(
      [{
        type: "totp",
        secret: "JBSWY3DP",
        issuer: "GitHub",
        account: "me@example.com",
        password: "local",
        updatedAt: 20,
      }],
      [{
        type: "totp",
        secret: "JBSWY3DP",
        issuer: "GitHub",
        account: "me@example.com",
        password: "remote",
        updatedAt: "1e999",
      }],
    );

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      password: "local",
      updatedAt: 20,
    });
  });
});

describe("normalizeProjectItemOrder", () => {
  it("keeps explicit order, removes stale ids, and appends new items lexicographically", () => {
    const result = normalizeProjectItemOrder(
      ["b", "ghost", "a"],
      [
        { id: "a", issuer: "GitHub", account: "me@example.com" },
        { id: "b", issuer: "Google", account: "me@example.com" },
        { id: "c", issuer: " AWS ", account: " ops@example.com " },
        { id: "d", issuer: "Zoom", account: "team@example.com", deleted: true },
      ],
    );

    expect(result).toEqual(["b", "a", "c"]);
  });

  it("sorts appended items by trimmed issuer and account fields", () => {
    expect(normalizeProjectItemOrder([], [
      { id: "b", issuer: "  Beta", account: " z@example.com " },
      { id: "a", issuer: " Alpha ", account: " a@example.com " },
    ])).toEqual(["a", "b"]);
  });
});

describe("buildDecryptedExportRecord", () => {
  it("handles missing cloud item fields without throwing", () => {
    expect(buildDecryptedExportRecord(null)).toMatchObject({
      type: "totp",
      issuer: "",
      account: "",
      password: "",
      secret: "",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      project: "unknown",
    });
  });

  it("normalizes OTP fields for cloud JSON and CSV export", () => {
    const record = buildDecryptedExportRecord({
      type: "hotp",
      issuer: " GitHub ",
      account: " me@example.com ",
      password: 123,
      secret: " jbsw y3dp==== ",
      algorithm: "SHA-512",
      digits: "99",
      period: "2",
      counter: "-4",
      _projectName: " ops/project ",
    });

    expect(record).toMatchObject({
      type: "hotp",
      issuer: "GitHub",
      account: "me@example.com",
      password: "",
      secret: "JBSWY3DP",
      algorithm: "SHA512",
      digits: 10,
      period: 5,
      counter: 0,
      project: "ops/project",
    });
    expect(record.otpauth).toContain("otpauth://hotp/");
    expect(record.otpauth).toContain("secret=JBSWY3DP");
    expect(record.otpauth).toContain("algorithm=SHA512");
    expect(record.otpauth).toContain("digits=10");
    expect(record.otpauth).toContain("counter=0");
    expect(parseOtpAuth(record.otpauth)).toMatchObject({
      issuer: "GitHub",
      account: "me@example.com",
      secret: "JBSWY3DP",
      algorithm: "SHA512",
      digits: 10,
      counter: 0,
    });
  });
});

describe("buildDecryptedExportFiles", () => {
  it("returns no files for unsupported formats or empty filtered results", () => {
    const items = [{ issuer: "GitHub", secret: "JBSWY3DP", _projectName: "Work" }];

    expect(buildDecryptedExportFiles({ items, format: "pdf", ts: 1000 })).toEqual([]);
    expect(buildDecryptedExportFiles({ items, selected: new Set(["Other"]), ts: 1000 })).toEqual([]);
    expect(buildDecryptedExportFiles({ items: [{ ...items[0], deleted: true }], ts: 1000 })).toEqual([]);
  });

  it("normalizes export format and unsafe filename timestamps", () => {
    vi.useFakeTimers();
    vi.setSystemTime(2000);
    const items = [{ issuer: "GitHub", secret: "JBSWY3DP", _projectName: "Work" }];

    expect(buildDecryptedExportFiles({ items, format: " CSV ", ts: "1e999" }).map((file) => file.filename))
      .toEqual(["cloud-decrypted-all-2000.csv"]);
    expect(buildDecryptedExportFiles({ items, format: " JSON ", ts: "1000.9" }).map((file) => file.filename))
      .toEqual(["cloud-decrypted-all-1000.json"]);
  });

  it("builds split JSON export files with normalized project names", async () => {
    const files = buildDecryptedExportFiles({
      items: [
        { issuer: " GitHub ", account: " me@example.com ", secret: " jbsw y3dp ", _projectName: " Work " },
        { issuer: "Google", secret: "JBSWY3DP", _projectName: " " },
      ],
      format: "json",
      split: true,
      ts: 1000,
    });

    expect(files.map((file) => file.filename)).toEqual([
      "cloud-decrypted-Work-1000.json",
      "cloud-decrypted-unknown-1000.json",
    ]);
    await expect(files[0].blob.text()).resolves.toContain("\"issuer\": \"GitHub\"");
  });

  it("builds normalized otpauth text export files", async () => {
    const files = buildDecryptedExportFiles({
      items: [
        {
          type: "hotp",
          issuer: " GitHub ",
          account: " me@example.com ",
          secret: " jbsw-y3dp==== ",
          algorithm: "SHA-512",
          digits: "99",
          counter: "-2",
          _projectName: " Work ",
        },
      ],
      format: "otpauth",
      ts: 1000,
    });

    expect(files.map((file) => file.filename)).toEqual(["cloud-decrypted-otpauth-all-1000.txt"]);
    const text = await files[0].blob.text();
    expect(text.endsWith("\n")).toBe(true);
    expect(text.trim().split("\n")).toHaveLength(1);
    expect(parseOtpAuth(text.trim())).toMatchObject({
      type: "hotp",
      issuer: "GitHub",
      account: "me@example.com",
      secret: "JBSWY3DP",
      algorithm: "SHA512",
      digits: 10,
      counter: 0,
    });
  });

  it("builds CSV exports with normalized fields and escaped cell content", async () => {
    const item = {
      issuer: " Ops \"A\",\nTeam ",
      account: " user, \"root\" ",
      password: "pa\"ss,\nword",
      secret: " jbsw-y3dp==== ",
      algorithm: "sha-256",
      digits: "8",
      period: "45",
      _projectName: " Work, \"A\" ",
    };
    const record = buildDecryptedExportRecord(item);
    const files = buildDecryptedExportFiles({
      items: [
        item,
        { issuer: "Other", secret: "JBSWY3DP", _projectName: "Other" },
      ],
      format: "csv",
      split: true,
      selected: new Set([" Work, \"A\" "]),
      ts: 1000,
    });

    expect(files.map((file) => file.filename)).toEqual(["cloud-decrypted-Work_A_-1000.csv"]);
    await expect(files[0].blob.text()).resolves.toBe([
      "type,issuer,account,password,secret,algorithm,digits,period,counter,project,otpauth",
      [
        record.type,
        "\"Ops \"\"A\"\",\nTeam\"",
        "\"user, \"\"root\"\"\"",
        "\"pa\"\"ss,\nword\"",
        record.secret,
        record.algorithm,
        String(record.digits),
        String(record.period),
        "",
        "\"Work, \"\"A\"\"\"",
        record.otpauth,
      ].join(","),
      "",
    ].join("\n"));
  });

  it("neutralizes spreadsheet formula prefixes in CSV exports", async () => {
    const [file] = buildDecryptedExportFiles({
      items: [{ issuer: "=HYPERLINK(\"https://example.com\")", account: "+cmd", secret: "JBSWY3DP" }],
      format: "csv",
      ts: 1000,
    });
    const csv = await file.blob.text();
    expect(csv).toContain("\"'=HYPERLINK(\"\"https://example.com\"\")\"");
    expect(csv).toContain("'+cmd");
  });
});

describe("cloud project decryptability", () => {
  it("surfaces cloud project listing JSON errors before generic HTTP errors", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      success: false,
      error: "AUTH_KV missing",
    }), { status: 503, headers: { "Content-Type": "application/json" } }));

    await expect(listAllCloudProjects()).rejects.toThrow("AUTH_KV missing");
  });

  it("keeps generic HTTP errors for non-JSON cloud project listing failures", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Server Error", { status: 503 }));

    await expect(listAllCloudProjects()).rejects.toThrow("HTTP 503");
  });

  it("does not accept cloud project listing responses with error notes", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      success: true,
      projects: [],
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Note": "kv-missing" },
    }));

    await expect(listAllCloudProjects()).rejects.toThrow("AUTH_KV");
  });

  it("normalizes cloud decrypt concurrency and secret lists", () => {
    expect(normalizeCloudConcurrency("bad")).toBe(5);
    expect(normalizeCloudConcurrency("0")).toBe(1);
    expect(normalizeCloudConcurrency("3.9")).toBe(3);
    expect(normalizeCloudConcurrency("99")).toBe(10);
    expect(normalizeCloudConcurrency("bad", 2)).toBe(2);

    expect(normalizeCloudSecrets([" secret-a ", "", null, 123])).toEqual(["secret-a", "123"]);
    expect(normalizeCloudSecrets("secret-a")).toEqual([]);
  });

  it("filters malformed cloud projects before bulk decrypt attempts", () => {
    const projects = [
      { syncId: " good ", metadata: { valid: true } },
      { syncId: "bad", metadata: { valid: false } },
      { syncId: "bad-string", metadata: { valid: "false" } },
      { syncId: "", metadata: { valid: true } },
      { syncId: "sync:nested", metadata: { valid: true } },
      { syncId: "demo\nid", metadata: { valid: true } },
      { syncId: "legacy" },
    ];

    expect(isDecryptableCloudProject(projects[0])).toBe(true);
    expect(isDecryptableCloudProject(projects[1])).toBe(false);
    expect(isDecryptableCloudProject(projects[2])).toBe(false);
    expect(isDecryptableCloudProject(projects[3])).toBe(false);
    expect(isDecryptableCloudProject(projects[4])).toBe(false);
    expect(isDecryptableCloudProject(projects[5])).toBe(false);
    expect(getDecryptableCloudProjects(projects).map((project) => project.syncId)).toEqual([" good ", "legacy"]);
  });

  it("counts skipped malformed cloud projects as failed decrypt attempts", async () => {
    await expect(decryptCloudAll({
      projects: [
        { syncId: "bad", metadata: { valid: false } },
        { syncId: "bad-string", metadata: { valid: "0" } },
        { syncId: " " },
        { syncId: "sync:nested", metadata: { valid: true } },
      ],
      secrets: ["secret"],
    })).resolves.toEqual({ items: [], failed: 4 });
  });

  it("counts every project as failed when no usable decrypt secret is provided", async () => {
    await expect(decryptCloudAll({
      projects: [
        { syncId: "good", metadata: { valid: true } },
        { syncId: "bad", metadata: { valid: false } },
      ],
      secrets: [" ", null],
      concurrency: "bad",
    })).resolves.toEqual({ items: [], failed: 2 });
  });

  it("does not count successfully decrypted empty cloud projects as failures", async () => {
    state.globalToken = "admin-token";
    const key = await deriveSyncKey("secret", "empty");
    const payload = await syncEncrypt({ items: [] }, key);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));

    await expect(decryptCloudAll({
      projects: [{ syncId: "empty", metadata: { valid: true } }],
      secrets: ["secret"],
    })).resolves.toEqual({ items: [], failed: 0 });
  });
});
