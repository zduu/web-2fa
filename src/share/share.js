// 分享：生成 / 撤销 / 列表 / 重新分享 / 绑定密钥
// 临时分享：随机 AES-GCM 密钥 + 随机 SID。
// 默认安全模式：密钥放 URL fragment (#ck=...)，服务端解密+计算验证码，接收方拿不到 secret。
// 可选完整模式（showSecret=true）：密钥放 URL fragment (#k=...)，客户端解密+本地计算。

import {
  state,
  getCurrentProject,
  getGlobalToken,
  saveSyncProjects,
  persist,
  mergeShareRefs,
  normalizeShareRefs,
} from "../core/storage.js";
import { b64url } from "../core/crypto.js";
import { wrapShareKeyWithPassword } from "../core/share-password.js";
import { pushProject } from "../sync/sync.js";
import { apiUrl, getPublicBaseUrl } from "../core/runtime.js";
import { normalizeOtpPayload } from "../core/totp.js";

export async function createShareLink(item, ttlSeconds = null, meta = {}) {
  const otpPayload = normalizeOtpPayload(item);
  if (otpPayload.type !== "totp") throw new Error("仅支持分享 TOTP");

  const showSecret = meta.showSecret === true;
  const note = typeof meta.note === "string" ? meta.note.slice(0, 280) : "";
  const maxAccess = normalizeNonNegativeInteger(meta.maxAccess, { max: 1_000_000 });
  const password = typeof meta.password === "string" ? meta.password.trim() : "";
  const label = formatShareLabel(item);
  const issuer = normalizeShareText(item?.issuer);
  const account = normalizeShareText(item?.account);
  const payloadObj = {
    type: "totp",
    secret: otpPayload.secret,
    algorithm: otpPayload.algorithm,
    digits: otpPayload.digits,
    period: otpPayload.period,
    label,
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

  const qsParts = [];
  if (ttlSeconds === "perm" || ttlSeconds === 0) qsParts.push("ttl=perm");
  else {
    const ttl = normalizePositiveInteger(ttlSeconds);
    if (ttl !== null) qsParts.push(`ttl=${ttl}`);
  }
  if (maxAccess > 0) qsParts.push(`max=${maxAccess}`);
  const qs = qsParts.length ? "?" + qsParts.join("&") : "";

  const headers = { "Content-Type": "application/json" };
  const token = getGlobalToken();
  if (token) headers["X-Token"] = token;

  let protectedBundle = null;
  const fragment = new URLSearchParams();

  if (showSecret) {
    // 完整模式：客户端解密，接收方能拿到完整 secret（可导入自己的验证器）
    const res = await fetch(apiUrl(`/api/share/${encodeURIComponent(sid)}${qs}`), { method: "PUT", headers, body });
    throwForCloudShareNote(res, "创建分享失败");
    if (!res.ok) { const e = new Error(`server-${res.status}`); e.status = res.status; throw e; }

    if (password) {
      protectedBundle = await wrapShareKeyWithPassword(keyRaw, password);
      fragment.set("s", protectedBundle.s);
      fragment.set("iv", protectedBundle.iv);
      fragment.set("wk", protectedBundle.wk);
      fragment.set("iter", String(protectedBundle.iter));
    } else {
      fragment.set("k", b64url(keyRaw));
    }
  } else {
    // 安全模式（默认）：服务端解密+计算验证码，接收方拿不到 secret
    const codeRes = await fetch(apiUrl(`/api/share-code/${encodeURIComponent(sid)}${qs}`), { method: "PUT", headers, body });
    throwForCloudShareNote(codeRes, "创建安全分享失败");
    if (!codeRes.ok) { const e = new Error(`server-${codeRes.status}`); e.status = codeRes.status; throw e; }

    if (password) {
      protectedBundle = await wrapShareKeyWithPassword(keyRaw, password);
      fragment.set("s", protectedBundle.s);
      fragment.set("iv", protectedBundle.iv);
      fragment.set("wk", protectedBundle.wk);
      fragment.set("iter", String(protectedBundle.iter));
      fragment.set("cm", "1");
    } else {
      fragment.set("ck", b64url(keyRaw));
    }
  }

  // Admin convenience: store share recovery material by default so any
  // ADMIN_KEY-authenticated device can copy the full link later.
  let recoveryStored = false;
  try {
    if (token && meta.storeKey !== false) {
      const createdAt = normalizeOptionalTimestamp(meta.createdAt) || Date.now();
      const keyRes = await fetch(apiUrl(`/api/sharekey/${encodeURIComponent(sid)}${qs}`), {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Token": token },
        body: JSON.stringify({
          k: password ? "" : b64url(keyRaw),
          label: normalizeShareText(meta.label) || payloadObj.label || "(未命名)",
          projectName: normalizeShareText(meta.projectName),
          itemId: normalizeShareText(meta.itemId || item.id),
          issuer,
          account,
          createdAt,
          ttl: ttlSeconds === null ? "default" : ttlSeconds,
          maxAccess,
          requiresPassword: !!password,
          showSecret,
          protectedBundle: protectedBundle || null,
        })
      });
      recoveryStored = keyRes.ok && !keyRes.headers?.get?.("X-Note");
    }
  } catch {}

  const link = `${getPublicBaseUrl()}/shared.html?sid=${encodeURIComponent(sid)}#${fragment.toString()}`;
  return { link, sid, k: b64url(keyRaw), requiresPassword: !!password, showSecret, recoveryStored };
}

// Share an item that is currently visible (handles both single-project and "_all_" view)
export async function shareItem(item, ttlSeconds, note = "", maxAccess = 0, password = "", storeKey = true, showSecret = false) {
  const isAll = state.currentProjectId === "_all_";
  const target = isAll
    ? findItemInProject(item._projectId, item.id)
    : state.items.find(x => x.id === item.id);
  const projectName = isAll
    ? (state.syncProjects.find(p => p.id === item._projectId)?.name || "")
    : (getCurrentProject()?.name || "");
  const createdAt = Date.now();
  const result = await createShareLink(item, ttlSeconds, {
    label: formatShareLabel(item) || "(未命名)",
    projectName,
    itemId: item.id,
    createdAt,
    note,
    maxAccess,
    password,
    storeKey,
    showSecret,
  });
  // Write share record back to source
  if (target) {
    target.shares = mergeShareRefs(target.shares, [{ sid: result.sid, k: result.k }]);
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

export function sharePayloadChanged(prev, next) {
  const prevPayload = normalizeOtpPayload(prev);
  const nextPayload = normalizeOtpPayload(next);
  return (
    prevPayload.type !== nextPayload.type ||
    prevPayload.secret !== nextPayload.secret ||
    String(prev?.issuer || "").trim() !== String(next?.issuer || "").trim() ||
    String(prev?.account || "").trim() !== String(next?.account || "").trim() ||
    prevPayload.algorithm !== nextPayload.algorithm ||
    prevPayload.digits !== nextPayload.digits ||
    prevPayload.period !== nextPayload.period ||
    prevPayload.counter !== nextPayload.counter
  );
}

function findItemInProject(projId, itemId) {
  const proj = state.syncProjects.find(p => p.id === projId);
  if (!proj || !Array.isArray(proj.itemsData)) return null;
  return proj.itemsData.find(x => x.id === itemId) || null;
}

export async function revokeShare(sid) {
  const normalizedSid = String(sid || "").trim();
  if (!normalizedSid) return false;
  await deleteRemoteShareResources(normalizedSid);
  // also clear local references
  const removeFromList = (arr) => {
    if (!Array.isArray(arr)) return false;
    const before = JSON.stringify(normalizeShareRefs(arr));
    const filtered = normalizeShareRefs(arr).filter((share) => share.sid !== normalizedSid);
    const after = JSON.stringify(filtered);
    if (after !== before) { arr.length = 0; arr.push(...filtered); return true; }
    return false;
  };
  let changed = false;
  for (const it of state.items) if (removeFromList(it.shares)) changed = true;
  for (const proj of state.syncProjects) {
    if (!Array.isArray(proj.itemsData)) continue;
    for (const it of proj.itemsData) if (removeFromList(it.shares)) changed = true;
  }
  if (changed) { await persist(); saveSyncProjects(); }
  return true;
}

export async function deleteRemoteShareResources(sid, token = getGlobalToken()) {
  const normalizedSid = normalizeShareText(sid);
  if (!normalizedSid) return false;
  const headers = token ? { "X-Token": token } : {};
  let shareError = null;
  try {
    const res = await fetch(apiUrl(`/api/share/${encodeURIComponent(normalizedSid)}`), { method: "DELETE", headers });
    throwForCloudShareNote(res, "删除分享失败");
    if (!res.ok) shareError = new Error(`HTTP ${res.status}`);
  } catch (error) {
    shareError = error;
  }
  try {
    await fetch(apiUrl(`/api/sharekey/${encodeURIComponent(normalizedSid)}`), { method: "DELETE", headers });
  } catch {}
  if (shareError) throw shareError;
  return true;
}

// HEAD probe for share existence
export async function probeShare(sid) {
  const normalizedSid = normalizeShareText(sid);
  if (!normalizedSid) return false;
  try {
    const r = await fetch(apiUrl(`/api/share/${encodeURIComponent(normalizedSid)}`), { method: "HEAD" });
    return r.status === 200 && !r.headers?.get?.("X-Note");
  } catch { return false; }
}

// List of all local-known share refs (across all projects)
export function collectLocalShares() {
  const out = [];
  const push = (it, projName) => {
    if (!Array.isArray(it.shares) || !it.shares.length) return;
    for (const s of normalizeShareRefs(it.shares)) {
      const { sid, k = null } = s;
      out.push({
        sid, k,
        itemId: it.id,
        label: formatShareLabel(it) || "(未命名)",
        projectName: projName,
      });
    }
  };
  for (const it of state.items) push(it, null);
  for (const proj of state.syncProjects) {
    if (!Array.isArray(proj.itemsData)) continue;
    for (const it of proj.itemsData) push(it, normalizeShareText(proj.name) || "未命名");
  }
  const bySid = new Map();
  for (const record of out) {
    if (!bySid.has(record.sid)) {
      bySid.set(record.sid, record);
      continue;
    }
    const prev = bySid.get(record.sid);
    if (!prev.k && record.k) prev.k = record.k;
  }
  return Array.from(bySid.values());
}

export function formatShareLabel(item) {
  const issuer = normalizeShareText(item?.issuer);
  const account = normalizeShareText(item?.account);
  if (issuer && account) return `${issuer} · ${account}`;
  return issuer || account || "";
}

export function formatShareResultStatus(label, copied, recoveryStored = true) {
  const name = normalizeShareText(label) || "分享";
  const action = copied ? "已复制" : "已生成";
  if (recoveryStored === false) {
    return `“${name}” 的分享链接${action}，但后台恢复材料未保存`;
  }
  return copied
    ? `“${name}” 的分享链接已复制，可直接扫码打开`
    : `“${name}” 的分享链接已生成，可扫码或手动复制`;
}

function normalizeShareText(value) {
  return String(value || "").trim();
}

export async function fetchCloudShares() {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const res = await fetch(apiUrl("/api/share/list"), { headers: { "X-Token": token, "Cache-Control": "no-store" } });
  throwForCloudShareNote(res, "加载分享列表失败");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json().catch(() => ({ sids: [] }));
  return normalizeShareIds(data.sids);
}

export async function fetchCloudShareStats(sids = []) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const ids = normalizeShareIds(sids);
  if (!ids.length) return new Map();
  const params = new URLSearchParams();
  for (const sid of ids) params.append("sid", sid);
  const qs = params.toString();
  const res = await fetch(apiUrl(`/api/share/stat${qs ? `?${qs}` : ""}`), {
    headers: { "X-Token": token, "Cache-Control": "no-store" }
  });
  throwForCloudShareNote(res, "加载分享统计失败");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json().catch(() => ({ items: [] }));
  const map = new Map();
  for (const item of Array.isArray(data.items) ? data.items : []) {
    const sid = normalizeShareText(item?.sid);
    if (!sid) continue;
    map.set(sid, {
      accessCount: normalizeNonNegativeInteger(item.accessCount),
      lastAccessAt: normalizeOptionalTimestamp(item.lastAccessAt),
      accessUserAgentSample: sanitizeShareUserAgent(item.accessUserAgentSample),
    });
  }
  return map;
}

export async function fetchSharedMeta(sid) {
  const normalizedSid = normalizeShareText(sid);
  const token = getGlobalToken();
  if (!token || !normalizedSid) return null;
  try {
    const r = await fetch(apiUrl(`/api/sharekey/${encodeURIComponent(normalizedSid)}`), {
      headers: { "X-Token": token, "Cache-Control": "no-store" }
    });
    if (!r.ok) return null;
    const j = await r.json();
    if (!j || typeof j.k !== "string") return null;
    return {
      sid: normalizedSid,
      k: j.k,
      label: normalizeShareText(j.label) || "分享",
      projectName: normalizeShareText(j.projectName),
      itemId: normalizeShareText(j.itemId),
      issuer: normalizeShareText(j.issuer),
      account: normalizeShareText(j.account),
      createdAt: normalizeOptionalTimestamp(j.createdAt),
      ttl: j.ttl ?? null,
      requiresPassword: j.requiresPassword === true,
      protectedBundle: j.protectedBundle && typeof j.protectedBundle === "object" ? {
        s: normalizeShareText(j.protectedBundle.s),
        iv: normalizeShareText(j.protectedBundle.iv),
        wk: normalizeShareText(j.protectedBundle.wk),
        iter: normalizePositiveInteger(j.protectedBundle.iter),
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
  records.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0) || a.sid.localeCompare(b.sid));
  return records;
}

function throwForCloudShareNote(response, fallbackMessage) {
  const note = response?.headers?.get?.("X-Note") || "";
  if (note === "kv-missing") throw new Error("服务端未绑定 AUTH_KV");
  if (note) throw new Error(fallbackMessage);
}

export function normalizeShareIds(values) {
  const list = Array.isArray(values) ? values : [];
  const out = [];
  const seen = new Set();
  for (const value of list) {
    const sid = normalizeShareText(value);
    if (!sid || seen.has(sid)) continue;
    seen.add(sid);
    out.push(sid);
  }
  return out;
}

function normalizeNonNegativeInteger(value, { fallback = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(0, n), max);
}

function normalizePositiveInteger(value) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n <= 0) return null;
  return n;
}

function normalizeOptionalTimestamp(value) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n <= 0 || n > Number.MAX_SAFE_INTEGER) return null;
  return n;
}

function sanitizeShareUserAgent(value) {
  if (typeof value !== "string") return "";
  const text = value.replace(/[\x00-\x1F\x7F]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.slice(0, 160) : "";
}
