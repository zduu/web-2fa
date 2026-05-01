// 分享：生成 / 撤销 / 列表 / 重新分享 / 绑定密钥
// 临时分享：随机 AES-GCM 密钥 + 随机 SID。密钥放 URL fragment (#k=...)。

import { state, getCurrentProject, getGlobalToken, saveSyncProjects, persist } from "../core/storage.js";
import { b64url } from "../core/crypto.js";
import { wrapShareKeyWithPassword } from "../core/share-password.js";
import { pushProject } from "../sync/sync.js";

export async function createShareLink(item, ttlSeconds = null, meta = {}) {
  if ((item.type || "totp") !== "totp") throw new Error("仅支持分享 TOTP");

  const note = typeof meta.note === "string" ? meta.note.slice(0, 280) : "";
  const maxAccess = Number(meta.maxAccess) > 0 ? Math.floor(Number(meta.maxAccess)) : 0;
  const password = typeof meta.password === "string" ? meta.password.trim() : "";
  const payloadObj = {
    type: "totp",
    secret: (item.secret || "").replace(/\s+/g, "").toUpperCase(),
    algorithm: (item.algorithm || "SHA1").toUpperCase(),
    digits: Number(item.digits || 6),
    period: Number(item.period || 30),
    label: `${item.issuer || ""}${item.account ? (" · " + item.account) : ""}`.trim(),
    note,
  };
  const pt = new TextEncoder().encode(JSON.stringify(payloadObj));
  const keyRaw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));

  const sidBytes = crypto.getRandomValues(new Uint8Array(12));
  const sid = b64url(sidBytes);
  const body = JSON.stringify({ v: 1, iv: b64url(iv), ct: b64url(ct) });
  let protectedBundle = null;
  const fragment = new URLSearchParams();
  if (password) {
    protectedBundle = await wrapShareKeyWithPassword(keyRaw, password);
    fragment.set("s", protectedBundle.s);
    fragment.set("iv", protectedBundle.iv);
    fragment.set("wk", protectedBundle.wk);
    fragment.set("iter", String(protectedBundle.iter));
  } else {
    fragment.set("k", b64url(keyRaw));
  }

  const qsParts = [];
  if (ttlSeconds === "perm" || ttlSeconds === 0) qsParts.push("ttl=perm");
  else if (Number.isFinite(Number(ttlSeconds)) && Number(ttlSeconds) > 0) qsParts.push(`ttl=${Math.round(Number(ttlSeconds))}`);
  if (maxAccess > 0) qsParts.push(`max=${maxAccess}`);
  const qs = qsParts.length ? "?" + qsParts.join("&") : "";

  const headers = { "Content-Type": "application/json" };
  const token = getGlobalToken();
  if (token) headers["X-Token"] = token;

  const res = await fetch(`/api/share/${encodeURIComponent(sid)}${qs}`, { method: "PUT", headers, body });
  if (!res.ok) { const e = new Error(`server-${res.status}`); e.status = res.status; throw e; }

  // also store the share key on the server (best effort, requires token)
  try {
    if (token) {
      const createdAt = Number(meta.createdAt || Date.now());
      await fetch(`/api/sharekey/${encodeURIComponent(sid)}${qs}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Token": token },
        body: JSON.stringify({
          k: b64url(keyRaw),
          label: meta.label || payloadObj.label || "(未命名)",
          projectName: meta.projectName || "",
          itemId: meta.itemId || item.id || "",
          issuer: item.issuer || "",
          account: item.account || "",
          createdAt,
          ttl: ttlSeconds === null ? "default" : ttlSeconds,
          maxAccess,
          requiresPassword: !!password,
          protectedBundle: protectedBundle || null,
        })
      });
    }
  } catch {}

  const link = `${location.origin}/shared.html?sid=${encodeURIComponent(sid)}#${fragment.toString()}`;
  return { link, sid, k: b64url(keyRaw), requiresPassword: !!password };
}

// Share an item that is currently visible (handles both single-project and "_all_" view)
export async function shareItem(item, ttlSeconds, note = "", maxAccess = 0, password = "") {
  const isAll = state.currentProjectId === "_all_";
  const target = isAll
    ? findItemInProject(item._projectId, item.id)
    : state.items.find(x => x.id === item.id);
  const projectName = isAll
    ? (state.syncProjects.find(p => p.id === item._projectId)?.name || "")
    : (getCurrentProject()?.name || "");
  const createdAt = Date.now();
  const result = await createShareLink(item, ttlSeconds, {
    label: `${item.issuer || ""}${item.account ? (" · " + item.account) : ""}`.trim() || "(未命名)",
    projectName,
    itemId: item.id,
    createdAt,
    note,
    maxAccess,
    password,
  });
  // Write share record back to source
  if (target) {
    if (!Array.isArray(target.shares)) target.shares = [];
    if (!target.shares.some(x => (typeof x === "string" ? x === result.sid : x.sid === result.sid))) {
      target.shares.push({ sid: result.sid, k: result.k });
    }
    target.updatedAt = createdAt;
  }
  if (isAll) {
    saveSyncProjects();
    const proj = state.syncProjects.find(p => p.id === item._projectId);
    if (proj) { try { await pushProject(proj); } catch {} }
  } else {
    await persist();
    const cur = getCurrentProject();
    if (cur) { cur.itemsData = state.items.map(x => ({ ...x })); saveSyncProjects(); }
  }
  return result;
}

function findItemInProject(projId, itemId) {
  const proj = state.syncProjects.find(p => p.id === projId);
  if (!proj || !Array.isArray(proj.itemsData)) return null;
  return proj.itemsData.find(x => x.id === itemId) || null;
}

export async function revokeShare(sid) {
  const token = getGlobalToken();
  const headers = token ? { "X-Token": token } : {};
  const res = await fetch(`/api/share/${encodeURIComponent(sid)}`, { method: "DELETE", headers });
  // best effort delete sharekey
  try { await fetch(`/api/sharekey/${encodeURIComponent(sid)}`, { method: "DELETE", headers }); } catch {}
  // also clear local references
  const removeFromList = (arr) => {
    if (!Array.isArray(arr)) return false;
    const before = arr.length;
    const filtered = arr.filter(x => (typeof x === "string" ? x !== sid : x?.sid !== sid));
    if (filtered.length !== before) { arr.length = 0; arr.push(...filtered); return true; }
    return false;
  };
  let changed = false;
  for (const it of state.items) if (removeFromList(it.shares)) changed = true;
  for (const proj of state.syncProjects) {
    if (!Array.isArray(proj.itemsData)) continue;
    for (const it of proj.itemsData) if (removeFromList(it.shares)) changed = true;
  }
  if (changed) { await persist(); saveSyncProjects(); }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

// HEAD probe for share existence
export async function probeShare(sid) {
  try {
    const r = await fetch(`/api/share/${encodeURIComponent(sid)}`, { method: "HEAD" });
    return r.status === 200;
  } catch { return false; }
}

// List of all local-known share refs (across all projects)
export function collectLocalShares() {
  const out = [];
  const push = (it, projName) => {
    if (!Array.isArray(it.shares) || !it.shares.length) return;
    for (const s of it.shares) {
      const sid = typeof s === "string" ? s : s?.sid;
      const k = typeof s === "string" ? null : s?.k;
      if (!sid) continue;
      out.push({
        sid, k,
        itemId: it.id,
        label: `${it.issuer || ""}${it.account ? (" · " + it.account) : ""}`.trim() || "(未命名)",
        projectName: projName,
      });
    }
  };
  for (const it of state.items) push(it, null);
  for (const proj of state.syncProjects) {
    if (!Array.isArray(proj.itemsData)) continue;
    for (const it of proj.itemsData) push(it, proj.name || "未命名");
  }
  // dedup by sid
  const seen = new Set();
  return out.filter(r => seen.has(r.sid) ? false : seen.add(r.sid));
}

export async function fetchCloudShares() {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const res = await fetch("/api/share/list", { headers: { "X-Token": token, "Cache-Control": "no-store" } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json().catch(() => ({ sids: [] }));
  return Array.isArray(data.sids) ? data.sids : [];
}

export async function fetchCloudShareStats(sids = []) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const params = new URLSearchParams();
  for (const sid of sids) {
    if (sid) params.append("sid", sid);
  }
  const qs = params.toString();
  const res = await fetch(`/api/share/stat${qs ? `?${qs}` : ""}`, {
    headers: { "X-Token": token, "Cache-Control": "no-store" }
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json().catch(() => ({ items: [] }));
  const map = new Map();
  for (const item of Array.isArray(data.items) ? data.items : []) {
    if (!item || typeof item.sid !== "string") continue;
    map.set(item.sid, {
      accessCount: Math.max(0, Number(item.accessCount || 0)),
      lastAccessAt: Number(item.lastAccessAt || 0) || null,
      accessUserAgentSample: typeof item.accessUserAgentSample === "string" ? item.accessUserAgentSample : "",
    });
  }
  return map;
}

export async function fetchSharedMeta(sid) {
  const token = getGlobalToken();
  if (!token) return null;
  try {
    const r = await fetch(`/api/sharekey/${encodeURIComponent(sid)}`, {
      headers: { "X-Token": token, "Cache-Control": "no-store" }
    });
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || typeof j.k !== "string") return null;
    return {
      sid,
      k: j.k,
      label: typeof j.label === "string" && j.label.trim() ? j.label.trim() : "分享",
      projectName: typeof j.projectName === "string" ? j.projectName : "",
      itemId: typeof j.itemId === "string" ? j.itemId : "",
      issuer: typeof j.issuer === "string" ? j.issuer : "",
      account: typeof j.account === "string" ? j.account : "",
      createdAt: Number(j.createdAt || 0) || null,
      ttl: j.ttl ?? null,
      requiresPassword: !!j.requiresPassword,
      protectedBundle: j.protectedBundle && typeof j.protectedBundle === "object" ? {
        s: typeof j.protectedBundle.s === "string" ? j.protectedBundle.s : "",
        iv: typeof j.protectedBundle.iv === "string" ? j.protectedBundle.iv : "",
        wk: typeof j.protectedBundle.wk === "string" ? j.protectedBundle.wk : "",
        iter: Number(j.protectedBundle.iter || 0) || null,
      } : null,
    };
  } catch {
    return null;
  }
}

export async function fetchCloudShareRecords() {
  const sids = await fetchCloudShares();
  const stats = await fetchCloudShareStats(sids);
  const records = await Promise.all(sids.map(async (sid) => {
    const meta = await fetchSharedMeta(sid);
    const stat = stats.get(sid) || { accessCount: 0, lastAccessAt: null, accessUserAgentSample: "" };
    return {
      ...(meta || { sid, k: null, label: "分享", projectName: "", itemId: "", issuer: "", account: "", createdAt: null, ttl: null, requiresPassword: false, protectedBundle: null }),
      ...stat,
    };
  }));
  records.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0) || a.sid.localeCompare(b.sid));
  return records;
}
