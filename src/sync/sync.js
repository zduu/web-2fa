// 同步：推送 / 拉取 / 自动同步 / 合并
// 端到端加密：每个项目用 PBKDF2(secret, "sync:"+id) 派生 AES-GCM 密钥

import { state, getCurrentProject, getGlobalToken, saveSyncProjects, persist, ensureItemDefaults, mergeShareRefs, normalizeStoredTimestamp, normalizeSyncAutoInterval } from "../core/storage.js";
import { deriveSyncKey, syncEncrypt, syncDecrypt } from "../core/crypto.js";
import { apiUrl } from "../core/runtime.js";
import { normalizeOtpPayload } from "../core/totp.js";

const RESERVED_SYNC_ID_PREFIXES = [
  "sync:",
  "syncbak:",
  "synctomb:",
  "share:",
  "sharekey:",
  "sharestat:",
  "vault:",
  "audit:",
];

export function normalizeSyncRouteId(value) {
  const id = String(value || "").trim();
  if (!id) return "";
  if (/[\x00-\x1F\x7F]/.test(id)) return "";
  if (RESERVED_SYNC_ID_PREFIXES.some((prefix) => id.startsWith(prefix))) return "";
  return id;
}

export function getSyncEndpoint(id) {
  const normalized = normalizeSyncRouteId(id);
  if (!normalized) throw newErr("Sync ID 格式不正确", "invalid-sync-id");
  return apiUrl(`/api/sync/${encodeURIComponent(normalized)}`);
}

// ----- merge logic -----
export function itemKey(it) {
  if (it?.id) return it.id;
  const payload = normalizeOtpPayload(it);
  const issuer = String(it?.issuer || "").trim();
  const account = String(it?.account || "").trim();
  return `${payload.type}|${payload.secret}|${issuer}|${account}`;
}

function pickLatest(a, b) {
  if (!a) return b; if (!b) return a;
  const at = normalizeStoredTimestamp(a.updatedAt, 0); const bt = normalizeStoredTimestamp(b.updatedAt, 0);
  return at >= bt ? a : b;
}

export function mergeItems(local, remote) {
  const map = new Map();
  for (const it of local.map((item) => ensureItemDefaults(item, { updatedAtFallback: 0 }))) map.set(itemKey(it), it);
  for (const it of remote.map((item) => ensureItemDefaults(item, { updatedAtFallback: 0 }))) {
    const k = itemKey(it);
    const merged = pickLatest(map.get(k), it);
    merged.shares = mergeShareRefs(map.get(k)?.shares, it.shares);
    map.set(k, merged);
  }
  return Array.from(map.values());
}

// ----- push / pull -----
function ensureOnline() {
  if (typeof navigator !== "undefined" && navigator.onLine === false) {
    throw newErr("当前离线，无法访问云端", "offline");
  }
}

export async function pushCurrent() {
  const cur = getCurrentProject();
  if (!cur) throw newErr("请先选择具体项目", "no-project");
  const rawId = String(cur.syncId || "").trim();
  const id = normalizeSyncRouteId(rawId);
  const secret = cur.secret || "";
  if (!rawId || !secret) throw newErr("项目缺少 Sync ID 或 Sync Secret", "missing");
  if (!id) throw newErr("Sync ID 格式不正确", "invalid-sync-id");
  ensureOnline();
  const token = getGlobalToken();
  const key = await deriveSyncKey(secret, id);
  const payload = await syncEncrypt({ items: state.items }, key);
  const res = await fetch(getSyncEndpoint(id), {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...(token ? { "X-Token": token } : {}) },
    body: JSON.stringify(payload)
  });
  throwForSyncErrorResponse(res, "推送");
  dispatchSyncWarningForResponse(res);
  cur.lastSyncedAt = Date.now();
  // also persist current items into project before saving
  cur.itemsData = (state.items || []).map(it => ({ ...it }));
  saveSyncProjects();
}

export async function pullCurrent() {
  const cur = getCurrentProject();
  if (!cur) throw newErr("请先选择具体项目", "no-project");
  const rawId = String(cur.syncId || "").trim();
  const id = normalizeSyncRouteId(rawId);
  const secret = cur.secret || "";
  if (!rawId || !secret) throw newErr("项目缺少 Sync ID 或 Sync Secret", "missing");
  if (!id) throw newErr("Sync ID 格式不正确", "invalid-sync-id");
  ensureOnline();
  const token = getGlobalToken();
  const key = await deriveSyncKey(secret, id);
  const res = await fetch(getSyncEndpoint(id), {
    headers: { ...(token ? { "X-Token": token } : {}), "Cache-Control": "no-store" }
  });
  if (res.status === 404) throw newErr("云端暂无数据", "empty", 404);
  if (res.status === 401) throw newErr("未授权（Admin Key 不正确）", "unauth", 401);
  if (res.status === 410 && res.headers?.get?.("X-Note") === "soft-deleted") {
    throw newErr("云端项目已删除，可在回收站恢复", "deleted", 410);
  }
  throwForSyncErrorResponse(res, "拉取");
  const payload = await res.json();
  let obj;
  try { obj = await syncDecrypt(payload, key); }
  catch { throw newErr("解密失败：Sync Secret 不一致", "decrypt"); }
  const remote = (obj.items || []).map(ensureItemDefaults);
  state.items = mergeItems(state.items, remote);
  await persist();
  cur.itemsData = (state.items || []).map(it => ({ ...it }));
  cur.lastSyncedAt = Date.now();
  saveSyncProjects();
}

// Push a specific project (used internally by share for "_all_" view)
export async function pushProject(proj) {
  const id = normalizeSyncRouteId(proj?.syncId);
  const secret = (proj && proj.secret) || "";
  if (!id || !secret) return;
  if (typeof navigator !== "undefined" && navigator.onLine === false) return;
  const token = getGlobalToken();
  const key = await deriveSyncKey(secret, id);
  const payload = await syncEncrypt({ items: proj.itemsData || [] }, key);
  const res = await fetch(getSyncEndpoint(id), {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...(token ? { "X-Token": token } : {}) },
    body: JSON.stringify(payload)
  });
  if (!isSyncErrorResponse(res)) {
    dispatchSyncWarningForResponse(res);
    proj.lastSyncedAt = Date.now();
    saveSyncProjects();
  }
}

// Delete a sync project on cloud
export async function deleteCloudProject(syncId) {
  const token = getGlobalToken();
  if (!token) throw newErr("需要 Admin Key 才能删除", "no-token");
  const id = normalizeSyncRouteId(syncId);
  if (!id) throw newErr("Sync ID 格式不正确", "invalid-sync-id");
  const res = await fetch(getSyncEndpoint(id), {
    method: "DELETE",
    headers: { "X-Token": token }
  });
  throwForSyncErrorResponse(res, "删除");
}

function isSyncErrorResponse(response) {
  const note = response?.headers?.get?.("X-Note") || "";
  return !response?.ok || note === "kv-missing" || note === "error";
}

function throwForSyncErrorResponse(response, action) {
  if (!isSyncErrorResponse(response)) return;
  const note = response?.headers?.get?.("X-Note") || "";
  let message = `${action}失败：${response?.status || 0}`;
  if (note === "kv-missing") message = "服务端未绑定 AUTH_KV";
  else if (note === "error") message = `${action}失败：服务端错误`;
  const error = newErr(message, "http", response?.status || 0);
  if (note) error.note = note;
  throw error;
}

function dispatchSyncWarningForResponse(response) {
  const note = response?.headers?.get?.("X-Note") || "";
  if (note === "github-backup-config") {
    dispatchSyncEvent("sync-warning", { note, message: "GitHub 备份配置不完整" });
  } else if (note === "github-backup-failed") {
    dispatchSyncEvent("sync-warning", { note, message: "GitHub 备份失败" });
  }
}

// ----- auto sync scheduler -----
const AUTO_PULL_INTERVAL_DEFAULT = 60_000;
const PUSH_RETRY_DELAYS = [2_000, 4_000, 8_000]; // 6.3 指数退避
let pullTimer = null;
let pushTimer = null;
let pushRetry = null;
let inFlightPush = false;
let inFlightPull = false;
let visibilityBound = false;

function getCurrentInterval() {
  const cur = getCurrentProject();
  return normalizeSyncAutoInterval(cur?.autoInterval, AUTO_PULL_INTERVAL_DEFAULT);
}

export function startAutoSync() {
  stopAutoSync();
  const doc = globalThis.document;
  if (!doc) return;
  bindVisibility();
  if (isDocumentVisible(doc)) {
    doPullSafe();
    pullTimer = setInterval(doPullSafe, getCurrentInterval());
  }
}
export function stopAutoSync() {
  if (pullTimer) { clearInterval(pullTimer); pullTimer = null; }
  if (pushTimer) { clearTimeout(pushTimer); pushTimer = null; }
  if (pushRetry) { clearTimeout(pushRetry); pushRetry = null; }
}

function bindVisibility() {
  if (visibilityBound) return;
  visibilityBound = bindAutoSyncVisibilityEvents({
    doc: globalThis.document,
    win: globalThis.window,
    onVisible: () => {
      const cur = getCurrentProject();
      if (!cur || !cur.auto) return;
      if (pullTimer) return;
      doPullSafe();
      pullTimer = setInterval(doPullSafe, getCurrentInterval());
    },
    onHidden: () => {
      if (pullTimer) { clearInterval(pullTimer); pullTimer = null; }
    },
    onOnline: () => {
      const cur = getCurrentProject();
      if (cur && cur.auto) doPullSafe();
    },
  });
}

export function isDocumentVisible(doc = globalThis.document) {
  try {
    return !!doc && doc.visibilityState === "visible";
  } catch {
    return false;
  }
}

export function bindAutoSyncVisibilityEvents({
  doc = globalThis.document,
  win = globalThis.window,
  onVisible = () => {},
  onHidden = () => {},
  onOnline = () => {},
} = {}) {
  let bound = false;
  if (doc && typeof doc.addEventListener === "function") {
    try {
      doc.addEventListener("visibilitychange", () => {
        if (isDocumentVisible(doc)) onVisible();
        else onHidden();
      });
      bound = true;
    } catch {}
  }
  if (win && typeof win.addEventListener === "function") {
    try {
      win.addEventListener("online", () => {
        if (isDocumentVisible(doc)) onOnline();
      });
      bound = true;
    } catch {}
  }
  return bound;
}

async function doPullSafe() {
  if (inFlightPull || inFlightPush) return;
  inFlightPull = true;
  try { await pullCurrent(); } catch {}
  finally { inFlightPull = false; }
}

// 6.3 自动 push 失败时指数退避重试
async function attemptPushWithRetry(attempt = 0) {
  if (inFlightPush) return;
  inFlightPush = true;
  try {
    await pushCurrent();
    if (attempt > 0) {
      dispatchSyncEvent("sync-recovered");
    }
  } catch (err) {
    const next = attempt + 1;
    const delay = PUSH_RETRY_DELAYS[attempt];
    if (delay && err && err.code !== "no-project" && err.code !== "missing") {
      dispatchSyncEvent("sync-failed", { attempt: next, delay, err });
      pushRetry = setTimeout(() => {
        pushRetry = null;
        inFlightPush = false; // 释放，让 attemptPushWithRetry 进入
        attemptPushWithRetry(next);
      }, delay);
      return;
    }
    dispatchSyncEvent("sync-give-up", { err });
  } finally {
    if (!pushRetry) inFlightPush = false;
  }
}

export function dispatchSyncEvent(name, detail) {
  const target = globalThis.window;
  if (!target || typeof target.dispatchEvent !== "function") return false;
  const EventCtor = typeof globalThis.CustomEvent === "function"
    ? globalThis.CustomEvent
    : (typeof globalThis.Event === "function" ? globalThis.Event : null);
  if (!EventCtor) return false;
  try {
    const event = EventCtor === globalThis.CustomEvent
      ? new EventCtor(name, detail === undefined ? undefined : { detail })
      : new EventCtor(name);
    target.dispatchEvent(event);
    return true;
  } catch {
    return false;
  }
}

export function scheduleAutoPush() {
  const cur = getCurrentProject();
  if (!cur || !cur.auto) return;
  if (pushTimer) clearTimeout(pushTimer);
  if (pushRetry) { clearTimeout(pushRetry); pushRetry = null; }
  pushTimer = setTimeout(() => attemptPushWithRetry(0), 1500);
}

// ----- merge all projects into current -----
export async function mergeAllProjectsIntoCurrent() {
  const target = getCurrentProject();
  if (!target) throw newErr("请先切换到具体项目", "no-project");
  let union = [];
  for (const p of state.syncProjects) {
    if (!p || !Array.isArray(p.itemsData)) continue;
    union = mergeItems(union, p.itemsData);
  }
  const before = Array.isArray(target.itemsData) ? target.itemsData.length : 0;
  const map = new Map(union.map(x => [itemKey(x), x]));
  target.itemsData = Array.from(map.values()).map(it => ({ ...it, deleted: !!it.deleted }));
  saveSyncProjects();
  state.items = target.itemsData.map(x => ({ ...x }));
  await persist();
  return { before, after: target.itemsData.length };
}

// ----- clean tombstones -----
export async function cleanDeleted() {
  const before = state.items.length;
  state.items = state.items.filter(x => !x.deleted);
  await persist();
  const cur = getCurrentProject();
  if (cur) { cur.itemsData = state.items.map(x => ({ ...x })); saveSyncProjects(); }
  return before - state.items.length;
}

function newErr(msg, code, status) {
  const e = new Error(msg);
  e.code = code; if (status !== undefined) e.status = status;
  return e;
}
