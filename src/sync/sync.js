// 同步：推送 / 拉取 / 自动同步 / 合并
// 端到端加密：每个项目用 PBKDF2(secret, "sync:"+id) 派生 AES-GCM 密钥

import { state, getCurrentProject, getGlobalToken, saveSyncProjects, persist, ensureItemDefaults } from "../core/storage.js";
import { deriveSyncKey, syncEncrypt, syncDecrypt } from "../core/crypto.js";

export function getSyncEndpoint(id) {
  return `/api/sync/${encodeURIComponent(id)}`;
}

// ----- merge logic -----
export function itemKey(it) {
  return it.id || `${it.type}|${(it.secret || "").replace(/\s+/g, "").toUpperCase()}|${it.issuer || ""}|${it.account || ""}`;
}

function pickLatest(a, b) {
  if (!a) return b; if (!b) return a;
  const at = Number(a.updatedAt || 0); const bt = Number(b.updatedAt || 0);
  return at >= bt ? a : b;
}

export function mergeItems(local, remote) {
  const map = new Map();
  for (const it of local.map(ensureItemDefaults)) map.set(itemKey(it), it);
  for (const it of remote.map(ensureItemDefaults)) {
    const k = itemKey(it);
    const merged = pickLatest(map.get(k), it);
    const a = (map.get(k)?.shares) || [];
    const b = (it.shares) || [];
    const bySid = new Map();
    for (const s of [...a, ...b]) {
      const entry = (typeof s === "string") ? { sid: s } : (s && typeof s.sid === "string" ? { sid: s.sid, k: s.k } : null);
      if (!entry) continue;
      if (!bySid.has(entry.sid)) bySid.set(entry.sid, entry);
      else {
        const prev = bySid.get(entry.sid);
        if (!prev.k && entry.k) prev.k = entry.k;
      }
    }
    merged.shares = Array.from(bySid.values());
    map.set(k, merged);
  }
  return Array.from(map.values());
}

// ----- push / pull -----
export async function pushCurrent() {
  const cur = getCurrentProject();
  if (!cur) throw newErr("请先选择具体项目", "no-project");
  const id = cur.syncId || "";
  const secret = cur.secret || "";
  if (!id || !secret) throw newErr("项目缺少 Sync ID 或 Sync Secret", "missing");
  const token = getGlobalToken();
  const key = await deriveSyncKey(secret, id);
  const payload = await syncEncrypt({ items: state.items }, key);
  const res = await fetch(getSyncEndpoint(id), {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...(token ? { "X-Token": token } : {}) },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw newErr(`推送失败：${res.status}`, "http", res.status);
  cur.lastSyncedAt = Date.now();
  // also persist current items into project before saving
  cur.itemsData = (state.items || []).map(it => ({ ...it }));
  saveSyncProjects();
}

export async function pullCurrent() {
  const cur = getCurrentProject();
  if (!cur) throw newErr("请先选择具体项目", "no-project");
  const id = cur.syncId || "";
  const secret = cur.secret || "";
  if (!id || !secret) throw newErr("项目缺少 Sync ID 或 Sync Secret", "missing");
  const token = getGlobalToken();
  const key = await deriveSyncKey(secret, id);
  const res = await fetch(getSyncEndpoint(id), {
    headers: { ...(token ? { "X-Token": token } : {}), "Cache-Control": "no-store" }
  });
  if (res.status === 404) throw newErr("云端暂无数据", "empty", 404);
  if (res.status === 401) throw newErr("未授权（Admin Key 不正确）", "unauth", 401);
  if (!res.ok) throw newErr(`拉取失败：${res.status}`, "http", res.status);
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
  const id = (proj && proj.syncId) || "";
  const secret = (proj && proj.secret) || "";
  if (!id || !secret) return;
  const token = getGlobalToken();
  const key = await deriveSyncKey(secret, id);
  const payload = await syncEncrypt({ items: proj.itemsData || [] }, key);
  const res = await fetch(getSyncEndpoint(id), {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...(token ? { "X-Token": token } : {}) },
    body: JSON.stringify(payload)
  });
  if (res.ok) { proj.lastSyncedAt = Date.now(); saveSyncProjects(); }
}

// Delete a sync project on cloud
export async function deleteCloudProject(syncId) {
  const token = getGlobalToken();
  if (!token) throw newErr("需要 Admin Key 才能删除", "no-token");
  const res = await fetch(getSyncEndpoint(syncId), {
    method: "DELETE",
    headers: { "X-Token": token }
  });
  if (!res.ok) throw newErr(`删除失败：${res.status}`, "http", res.status);
}

// ----- auto sync scheduler -----
let pullTimer = null;
let pushTimer = null;
let inFlightPush = false;
let inFlightPull = false;

export function startAutoSync() {
  stopAutoSync();
  // initial pull, then every 60s
  doPullSafe();
  pullTimer = setInterval(doPullSafe, 60_000);
}
export function stopAutoSync() {
  if (pullTimer) { clearInterval(pullTimer); pullTimer = null; }
  if (pushTimer) { clearTimeout(pushTimer); pushTimer = null; }
}

async function doPullSafe() {
  if (inFlightPull || inFlightPush) return;
  inFlightPull = true;
  try { await pullCurrent(); } catch {}
  finally { inFlightPull = false; }
}

export function scheduleAutoPush() {
  const cur = getCurrentProject();
  if (!cur || !cur.auto) return;
  if (pushTimer) clearTimeout(pushTimer);
  pushTimer = setTimeout(async () => {
    if (inFlightPush) return;
    inFlightPush = true;
    try { await pushCurrent(); } catch {}
    finally { inFlightPush = false; }
  }, 1500);
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
