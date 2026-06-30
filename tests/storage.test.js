import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { KDF_ITERATIONS_DEFAULT, normalizeKdfIterations } from "../src/core/crypto.js";
import {
  ensureItemDefaults,
  load,
  loadGlobalToken,
  loadSyncProjects,
  lockLocalData,
  LS_KEY,
  LS_META,
  LS_CURRENT_PROJECT,
  LS_SYNC_PROJECTS,
  mergeShareRefs,
  normalizeSyncAutoInterval,
  normalizeSyncProject,
  normalizeStoredTimestamp,
  saveSyncProjects,
  saveGlobalToken,
  setMasterPassword,
  state,
  tryUnlock,
} from "../src/core/storage.js";
import { createProject, updateProject } from "../src/sync/projects.js";

function installLocalStorage() {
  const store = new Map();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key) => store.has(key) ? store.get(key) : null,
      setItem: (key, value) => { store.set(key, String(value)); },
      removeItem: (key) => { store.delete(key); },
      clear: () => { store.clear(); },
      key: (index) => Array.from(store.keys())[index] || null,
      get length() { return store.size; },
    },
  });
}

function installBlockedLocalStorage() {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
      removeItem: () => { throw new Error("blocked"); },
    },
  });
}

function resetState() {
  state.items = [];
  state.unlocked = true;
  state.encMeta = null;
  state.key = null;
  state.dekRaw = null;
  state.syncProjects = [];
  state.currentProjectId = null;
  state.globalToken = "";
  state.adminUnlocked = false;
  state.cloudProjects = [];
  state.cloudAggregatedItems = [];
  state.cloudSelectedProjects = new Set();
}

beforeEach(() => {
  installLocalStorage();
  resetState();
});

afterEach(() => {
  resetState();
  delete globalThis.localStorage;
});

describe("ensureItemDefaults", () => {
  it("normalizes stored items and share references", () => {
    expect(ensureItemDefaults({
      type: "HOTP",
      issuer: " GitHub ",
      account: " me@example.com ",
      secret: " abcd ef12==== ",
      algorithm: "sha256",
      digits: "8",
      counter: "12",
      pinned: 1,
      deleted: 0,
      note: null,
      shares: [" sid-a ", { sid: " sid-b ", k: "key-b" }, { sid: " " }, { sid: "sid-c" }, { nope: true }],
    })).toEqual({
      type: "hotp",
      issuer: "GitHub",
      account: "me@example.com",
      secret: "ABCDEF12",
      algorithm: "SHA256",
      digits: 8,
      period: 30,
      counter: 12,
      password: "",
      updatedAt: expect.any(Number),
      deleted: false,
      pinned: true,
      note: "",
      shares: [
        { sid: "sid-a" },
        { sid: "sid-b", k: "key-b" },
        { sid: "sid-c", k: undefined },
      ],
    });
  });

  it("fills missing defaults for totp items", () => {
    expect(ensureItemDefaults({ secret: "jbsw y3dp" })).toMatchObject({
      type: "totp",
      issuer: "",
      account: "",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      counter: 0,
      pinned: false,
      deleted: false,
      shares: [],
    });
  });

  it("clamps invalid OTP parameters from stored items", () => {
    expect(ensureItemDefaults({
      type: "steam",
      secret: "jbsw y3dp",
      algorithm: "md5",
      digits: "-1",
      period: "2",
      counter: "-9",
    })).toMatchObject({
      type: "totp",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 4,
      period: 5,
      counter: 0,
    });
  });

  it("normalizes stored boolean-like item fields explicitly", () => {
    expect(ensureItemDefaults({
      secret: "JBSWY3DP",
      pinned: "false",
      deleted: "0",
    })).toMatchObject({
      pinned: false,
      deleted: false,
    });
    expect(ensureItemDefaults({
      secret: "JBSWY3DP",
      pinned: "yes",
      deleted: "true",
    })).toMatchObject({
      pinned: true,
      deleted: true,
    });
  });

  it("normalizes invalid stored timestamps", () => {
    expect(normalizeStoredTimestamp("42.9", 1000)).toBe(42);
    expect(normalizeStoredTimestamp("1e999", 1000)).toBe(1000);
    expect(normalizeStoredTimestamp("-1", 1000)).toBe(1000);
    expect(ensureItemDefaults({ secret: "JBSWY3DP", updatedAt: "1e999" })).toMatchObject({
      updatedAt: expect.any(Number),
    });
  });
});

describe("mergeShareRefs", () => {
  it("normalizes share ids and fills missing recovery keys", () => {
    expect(mergeShareRefs(
      [" sid-a ", { sid: "sid-b" }, { sid: " " }],
      [{ sid: "sid-a", k: "key-a" }, { sid: " sid-b ", k: "key-b" }, { nope: true }],
    )).toEqual([
      { sid: "sid-a", k: "key-a" },
      { sid: "sid-b", k: "key-b" },
    ]);
  });
});

describe("encrypted sync project storage", () => {
  it("uses safe defaults when localStorage reads are blocked during startup", async () => {
    installBlockedLocalStorage();
    state.items = [{ id: "stale", secret: "OLDSECRET" }];
    state.unlocked = false;

    expect(() => load()).not.toThrow();
    expect(state.items).toEqual([]);
    expect(state.unlocked).toBe(true);
    await expect(tryUnlock("password")).resolves.toBe(true);
    expect(() => loadSyncProjects()).not.toThrow();
    expect(state.syncProjects).toEqual([]);
    expect(loadGlobalToken()).toBe("");
    expect(() => saveGlobalToken("admin-token")).not.toThrow();
    expect(() => lockLocalData()).not.toThrow();
  });

  it("returns false instead of throwing for malformed encrypted metadata", async () => {
    localStorage.setItem(LS_META, "{bad json");
    localStorage.setItem(LS_KEY, JSON.stringify({ v: 2, iv: "iv", ct: "ct" }));

    await expect(tryUnlock("password")).resolves.toBe(false);
  });

  it("normalizes sync project numeric configuration", () => {
    expect(normalizeSyncAutoInterval("30000.9")).toBe(30000);
    expect(normalizeSyncAutoInterval("4999")).toBe(60000);
    expect(normalizeSyncAutoInterval("1e999")).toBe(60000);

    expect(normalizeSyncProject({
      id: " p1 ",
      name: " Work ",
      syncId: " sync-id ",
      secret: " sync-secret ",
      auto: 1,
      autoInterval: "30000.9",
      lastSyncedAt: "1e999",
      itemsData: [{ secret: " jbsw y3dp " }],
      itemOrder: "bad",
    })).toMatchObject({
      id: "p1",
      name: "Work",
      syncId: "sync-id",
      secret: "sync-secret",
      auto: true,
      autoInterval: 30000,
      lastSyncedAt: 0,
      itemsData: [{ secret: "JBSWY3DP" }],
      itemOrder: [],
    });

    expect(normalizeSyncProject({ auto: "false" })).toMatchObject({ auto: false });
    expect(normalizeSyncProject({ auto: "yes" })).toMatchObject({ auto: true });
  });

  it("normalizes current project selection when loading stored projects", () => {
    state.items = [{ id: "stale", secret: "OLDSECRET" }];
    localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify({
      currentProjectId: " missing-project ",
      projects: [{
        id: " p1 ",
        name: " Work ",
        syncId: " sync-id ",
        secret: " sync-secret ",
        itemsData: [{ id: "i1", secret: "JBSWY3DP", issuer: " GitHub " }],
      }, {
        id: "p2",
        name: "Other",
        itemsData: [{ id: "i2", secret: "JBSWY3DP" }],
      }],
    }));

    loadSyncProjects();

    expect(state.currentProjectId).toBe("p1");
    expect(state.syncProjects.map((project) => project.id)).toEqual(["p1", "p2"]);
    expect(state.items).toHaveLength(1);
    expect(state.items[0]).toMatchObject({
      id: "i1",
      issuer: "GitHub",
    });

    localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify({
      currentProjectId: " p2 ",
      projects: state.syncProjects,
    }));
    loadSyncProjects();
    expect(state.currentProjectId).toBe("p2");
    expect(state.items[0]).toMatchObject({ id: "i2" });
  });

  it("clears current selection but preserves local items when loading an empty project list", () => {
    state.items = [{ id: "local", secret: "OLDSECRET" }];
    localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify({
      currentProjectId: "_all_",
      projects: [],
    }));

    loadSyncProjects();

    expect(state.currentProjectId).toBeNull();
    expect(state.items).toEqual([{ id: "local", secret: "OLDSECRET" }]);
  });

  it("normalizes project configuration on create and update", () => {
    const project = createProject({
      name: " Work ",
      syncId: " sync-id ",
      secret: " sync-secret ",
      auto: 1,
      autoInterval: "1e999",
    });

    expect(project).toMatchObject({
      name: "Work",
      syncId: "sync-id",
      secret: "sync-secret",
      auto: true,
      autoInterval: 60000,
      lastSyncedAt: 0,
    });

    expect(updateProject(project.id, {
      autoInterval: "30000.9",
      lastSyncedAt: "1e999",
    })).toMatchObject({
      autoInterval: 30000,
      lastSyncedAt: 0,
    });
  });

  it("normalizes stored KDF iteration counts before unlock", async () => {
    expect(normalizeKdfIterations("600000.9")).toBe(600000);
    expect(normalizeKdfIterations("999")).toBe(KDF_ITERATIONS_DEFAULT);
    expect(normalizeKdfIterations("10000001")).toBe(KDF_ITERATIONS_DEFAULT);
    expect(normalizeKdfIterations("1e999")).toBe(KDF_ITERATIONS_DEFAULT);

    state.items = [{ id: "i1", secret: "JBSWY3DP", issuer: "GitHub", account: "me@example.com" }];
    await setMasterPassword("correct horse battery staple");
    const meta = JSON.parse(localStorage.getItem(LS_META));
    meta.iter = "600000.9";
    localStorage.setItem(LS_META, JSON.stringify(meta));

    lockLocalData();

    await expect(tryUnlock("correct horse battery staple")).resolves.toBe(true);
    expect(state.items[0]).toMatchObject({
      id: "i1",
      secret: "JBSWY3DP",
    });
  });

  it("normalizes aggregate project display names when loading all-project view", () => {
    localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify([{
      id: "p1",
      name: " Work ",
      itemsData: [{ id: "i1", secret: "JBSWY3DP" }],
    }, {
      id: "p2",
      name: " ",
      itemsData: [{ id: "i2", secret: "JBSWY3DP" }],
    }]));
    localStorage.setItem(LS_CURRENT_PROJECT, "_all_");

    loadSyncProjects();

    expect(state.currentProjectId).toBe("_all_");
    expect(state.items.map((it) => it._projectName)).toEqual(["Work", "未命名"]);
  });

  it("encrypts sync projects when a master password is enabled", async () => {
    state.items = [{ id: "i1", secret: "JBSWY3DP", issuer: "GitHub", account: "me@example.com" }];
    state.syncProjects = [{
      id: "p1",
      name: "Personal",
      syncId: "sync-id",
      secret: "sync-secret",
      itemsData: [{ id: "i1", secret: "JBSWY3DP", issuer: "GitHub", account: "me@example.com" }],
      itemOrder: ["i1"],
    }];
    state.currentProjectId = "p1";

    await setMasterPassword("correct horse battery staple");

    const raw = localStorage.getItem(LS_SYNC_PROJECTS);
    expect(JSON.parse(raw).v).toBe(2);
    expect(raw).not.toContain("sync-secret");
    expect(raw).not.toContain("JBSWY3DP");
    expect(localStorage.getItem(LS_CURRENT_PROJECT)).toBeNull();

    lockLocalData();
    loadSyncProjects();
    expect(state.syncProjects).toEqual([]);
    expect(state.currentProjectId).toBeNull();

    await expect(tryUnlock("correct horse battery staple")).resolves.toBe(true);
    expect(state.currentProjectId).toBe("p1");
    expect(state.syncProjects[0]).toMatchObject({
      syncId: "sync-id",
      secret: "sync-secret",
    });
    expect(state.items[0]).toMatchObject({
      id: "i1",
      secret: "JBSWY3DP",
    });
  });

  it("migrates legacy plaintext sync projects after unlock", async () => {
    state.items = [{ id: "legacy", secret: "JBSWY3DP" }];
    await setMasterPassword("migrate-this");

    localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify([{
      id: "legacy-project",
      name: "Legacy",
      syncId: "legacy-sync",
      secret: "legacy-secret",
      itemsData: [{ id: "legacy", secret: "JBSWY3DP" }],
    }]));
    localStorage.setItem(LS_CURRENT_PROJECT, "legacy-project");

    lockLocalData();
    await expect(tryUnlock("migrate-this")).resolves.toBe(true);
    await saveSyncProjects();

    const raw = localStorage.getItem(LS_SYNC_PROJECTS);
    expect(state.syncProjects[0].secret).toBe("legacy-secret");
    expect(JSON.parse(raw).v).toBe(2);
    expect(raw).not.toContain("legacy-secret");
    expect(localStorage.getItem(LS_CURRENT_PROJECT)).toBeNull();
  });
});
