import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ensureItemDefaults,
  loadSyncProjects,
  lockLocalData,
  LS_CURRENT_PROJECT,
  LS_SYNC_PROJECTS,
  saveSyncProjects,
  setMasterPassword,
  state,
  tryUnlock,
} from "../src/core/storage.js";

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
      type: "hotp",
      secret: " abcd ef12 ",
      algorithm: "sha256",
      digits: "8",
      counter: "12",
      pinned: 1,
      deleted: 0,
      note: null,
      shares: ["sid-a", { sid: "sid-b", k: "key-b" }, { sid: "sid-c" }, { nope: true }],
    })).toEqual({
      type: "hotp",
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
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      pinned: false,
      deleted: false,
      shares: [],
    });
  });
});

describe("encrypted sync project storage", () => {
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
