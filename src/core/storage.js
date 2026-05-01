// 本地存储：localStorage 读写、主密码 AES-GCM 加解密、项目持久化
// 完全保留旧 schema 以保证数据迁移零干预

import { deriveKey, toB64, fromB64, KDF_ITERATIONS_DEFAULT } from "./crypto.js";
import {
  createLocalUnlockPasskey,
  evaluatePasskeyPrf,
  getPasskeyPrfSupport,
  unwrapBytesWithPasskeyPrf,
  wrapBytesWithPasskeyPrf,
} from "./passkey.js";

export const LS_KEY = "authenticator.v1";
export const LS_META = "authenticator.v1.meta";
export const LS_SYNC_PROJECTS = "authenticator.v1.syncProjects";
export const LS_GLOBAL_TOKEN = "authenticator.v1.globalToken";
export const LS_CURRENT_PROJECT = "authenticator.v1.currentProjectId";
export const SS_ADMIN_UNLOCKED = "authenticator.v1.adminUnlocked";

// state shared across modules
export const state = {
  items: [],
  unlocked: true,
  encMeta: null,
  key: null,                // CryptoKey（DEK）：用于 items AES-GCM
  dekRaw: null,             // DEK 的原始 32 字节（用于生成/更新恢复码）
  syncProjects: [],
  currentProjectId: null,
  globalToken: "",
  adminUnlocked: false,
  cloudProjects: [],
  cloudAggregatedItems: [],
  cloudSelectedProjects: new Set(),
};

export function ensureItemDefaults(it) {
  const out = { ...it };
  out.password = typeof out.password === "string" ? out.password : "";
  out.secret = (out.secret || "").replace(/\s+/g, "").toUpperCase();
  out.type = out.type || "totp";
  out.algorithm = (out.algorithm || "SHA1").toUpperCase();
  out.digits = Number(out.digits || 6);
  out.period = Number(out.period || 30);
  if (out.type === "hotp") out.counter = Number(out.counter || 0);
  out.updatedAt = Number(out.updatedAt || Date.now());
  out.deleted = !!out.deleted;
  out.pinned = !!out.pinned;
  out.note = typeof out.note === "string" ? out.note : "";
  if (Array.isArray(out.shares)) {
    out.shares = out.shares.map(s => {
      if (typeof s === "string") return { sid: s };
      if (s && typeof s.sid === "string") return { sid: s.sid, k: (typeof s.k === "string" && s.k) ? s.k : undefined };
      return null;
    }).filter(Boolean);
  } else {
    out.shares = [];
  }
  return out;
}

// ---------- master-password encrypted local storage ----------
// 5.7 数据加密改为 KEK→DEK 两层结构，便于挂多把锁（主密码 + 恢复码）
// meta v2 = { v:2, iter, master: { saltB64, wrappedDek: {iv,ct} }, recovery?: {...} }
async function importDek(rawBytes) {
  return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function wrapDek(dekBytes, kek) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, dekBytes));
  return { iv: toB64(iv), ct: toB64(ct) };
}
async function unwrapDek(wrapped, kek) {
  const iv = fromB64(wrapped.iv);
  const ct = fromB64(wrapped.ct);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, ct));
  return pt;
}

export async function persist() {
  const payload = JSON.stringify({ items: state.items });
  if (state.key && state.encMeta) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, state.key, new TextEncoder().encode(payload));
    const packed = { v: 2, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
    localStorage.setItem(LS_KEY, JSON.stringify(packed));
    localStorage.setItem(LS_META, JSON.stringify(state.encMeta));
  } else {
    localStorage.setItem(LS_KEY, payload);
    localStorage.removeItem(LS_META);
  }
}

export function load() {
  const metaStr = localStorage.getItem(LS_META);
  const data = localStorage.getItem(LS_KEY);
  if (!data) {
    if (metaStr) localStorage.removeItem(LS_META);
    state.items = [];
    state.unlocked = true;
    return;
  }
  try {
    if (metaStr) {
      state.unlocked = false;
    } else {
      const parsed = JSON.parse(data);
      state.items = (parsed.items || []).map(ensureItemDefaults);
      state.unlocked = true;
    }
  } catch {
    state.items = [];
    state.unlocked = true;
  }
}

export async function tryUnlock(password) {
  const metaStr = localStorage.getItem(LS_META);
  const data = localStorage.getItem(LS_KEY);
  if (!metaStr || !data) {
    state.unlocked = true;
    return true;
  }
  const meta = JSON.parse(metaStr);
  try {
    if (meta.v === 2 && meta.master) {
      // 新格式 KEK/DEK
      const iter = Number(meta.iter) || KDF_ITERATIONS_DEFAULT;
      const salt = fromB64(meta.master.saltB64);
      const kek = await deriveKey(password, salt, iter);
      const dekBytes = await unwrapDek(meta.master.wrappedDek, kek);
      state.dekRaw = dekBytes;
      state.key = await importDek(dekBytes);
      state.encMeta = meta;
      const parsed = JSON.parse(data);
      const iv = fromB64(parsed.iv);
      const ct = fromB64(parsed.ct);
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, ct);
      const txt = new TextDecoder().decode(new Uint8Array(plain));
      state.items = (JSON.parse(txt).items || []).map(ensureItemDefaults);
      state.unlocked = true;
      return true;
    }
    // legacy v1：主密码直接派生 key
    const salt = fromB64(meta.saltB64);
    const iter = Number(meta.iter) > 0 ? Number(meta.iter) : 150000;
    state.key = await deriveKey(password, salt, iter);
    state.encMeta = meta;
    let txt;
    try {
      const parsed = JSON.parse(data);
      const iv = fromB64(parsed.iv);
      const ct = fromB64(parsed.ct);
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, ct);
      txt = new TextDecoder().decode(new Uint8Array(plain));
    } catch {
      const iv = fromB64(meta.ivB64 || "");
      if (!iv.length) throw new Error("no-iv");
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, fromB64(data));
      txt = new TextDecoder().decode(new Uint8Array(plain));
    }
    const parsed = JSON.parse(txt);
    state.items = (parsed.items || []).map(ensureItemDefaults);
    state.unlocked = true;
    // 自动迁移到 v2（同时升级到默认迭代次数）
    try { await setMasterPassword(password); } catch {}
    return true;
  } catch {
    return false;
  }
}

export async function setMasterPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKey(password, salt, KDF_ITERATIONS_DEFAULT);
  // 复用已有 DEK（来自 legacy 解锁后的迁移），否则生成新 DEK
  let dekBytes = state.dekRaw;
  if (!dekBytes) dekBytes = crypto.getRandomValues(new Uint8Array(32));
  state.dekRaw = dekBytes;
  state.key = await importDek(dekBytes);
  const wrappedDek = await wrapDek(dekBytes, kek);
  const keepPasskey = state.encMeta?.passkey ? { ...state.encMeta.passkey } : undefined;
  state.encMeta = {
    v: 2,
    iter: KDF_ITERATIONS_DEFAULT,
    master: { saltB64: toB64(salt), wrappedDek },
    ...(keepPasskey ? { passkey: keepPasskey } : {}),
    // 改主密码会清除旧 recovery
  };
  await persist();
}

export async function clearMasterPassword() {
  state.key = null;
  state.dekRaw = null;
  state.encMeta = null;
  await persist();
}

// 5.7 生成恢复码（4 字符一组，共 8 组 = 32 字符 base32）
export function formatRecoveryCode(raw) {
  const s = String(raw || "").replace(/[^A-Z2-7]/gi, "").toUpperCase();
  const groups = [];
  for (let i = 0; i < s.length; i += 4) groups.push(s.slice(i, i + 4));
  return groups.join("-");
}

export async function generateRecoveryCode() {
  if (!state.dekRaw || !state.encMeta || state.encMeta.v !== 2) {
    throw new Error("需先设置主密码并解锁");
  }
  // 20 字节 -> base32 32 字符
  const { base32Encode } = await import("./totp.js");
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const codeRaw = base32Encode(bytes);
  const display = formatRecoveryCode(codeRaw);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKey(codeRaw, salt, KDF_ITERATIONS_DEFAULT);
  const wrappedDek = await wrapDek(state.dekRaw, kek);
  state.encMeta.recovery = { saltB64: toB64(salt), wrappedDek, createdAt: Date.now() };
  localStorage.setItem(LS_META, JSON.stringify(state.encMeta));
  return display;
}

export function hasRecoveryCode() {
  try {
    const meta = JSON.parse(localStorage.getItem(LS_META) || "null");
    return !!(meta && meta.v === 2 && meta.recovery && meta.recovery.wrappedDek);
  } catch { return false; }
}

export function clearRecoveryCode() {
  if (!state.encMeta) return;
  delete state.encMeta.recovery;
  localStorage.setItem(LS_META, JSON.stringify(state.encMeta));
}

export async function getPasskeySupport() {
  return getPasskeyPrfSupport();
}

export function hasPasskeyUnlock() {
  try {
    const meta = JSON.parse(localStorage.getItem(LS_META) || "null");
    return !!(meta && meta.v === 2 && meta.passkey && meta.passkey.credentialId && meta.passkey.wrappedDek);
  } catch {
    return false;
  }
}

export function getPasskeySlotInfo() {
  try {
    const meta = JSON.parse(localStorage.getItem(LS_META) || "null");
    if (!meta || meta.v !== 2 || !meta.passkey) return null;
    return meta.passkey;
  } catch {
    return null;
  }
}

export async function setupPasskeyUnlock(label = "") {
  if (!state.dekRaw || !state.encMeta || state.encMeta.v !== 2) {
    throw new Error("需先设置主密码并解锁，才能启用 Passkey。");
  }
  const passkey = await createLocalUnlockPasskey({ label });
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrappedDek = await wrapBytesWithPasskeyPrf(state.dekRaw, passkey.prfOutput, salt);
  state.encMeta.passkey = {
    credentialId: passkey.credentialId,
    saltB64: toB64(salt),
    wrappedDek,
    label: passkey.label || "",
    transports: Array.isArray(passkey.transports) ? passkey.transports : [],
    createdAt: Date.now(),
  };
  localStorage.setItem(LS_META, JSON.stringify(state.encMeta));
  return state.encMeta.passkey;
}

export function clearPasskeyUnlock() {
  if (!state.encMeta?.passkey) return;
  delete state.encMeta.passkey;
  localStorage.setItem(LS_META, JSON.stringify(state.encMeta));
}

export async function unlockWithRecoveryCode(code) {
  const metaStr = localStorage.getItem(LS_META);
  const data = localStorage.getItem(LS_KEY);
  if (!metaStr || !data) return false;
  const meta = JSON.parse(metaStr);
  if (!meta || meta.v !== 2 || !meta.recovery) return false;
  const cleaned = String(code || "").replace(/[^A-Z2-7]/gi, "").toUpperCase();
  if (!cleaned) return false;
  try {
    const iter = Number(meta.iter) || KDF_ITERATIONS_DEFAULT;
    const salt = fromB64(meta.recovery.saltB64);
    const kek = await deriveKey(cleaned, salt, iter);
    const dekBytes = await unwrapDek(meta.recovery.wrappedDek, kek);
    state.dekRaw = dekBytes;
    state.key = await importDek(dekBytes);
    state.encMeta = meta;
    const parsed = JSON.parse(data);
    const iv = fromB64(parsed.iv);
    const ct = fromB64(parsed.ct);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, ct);
    const txt = new TextDecoder().decode(new Uint8Array(plain));
    state.items = (JSON.parse(txt).items || []).map(ensureItemDefaults);
    state.unlocked = true;
    return true;
  } catch {
    return false;
  }
}

export async function unlockWithPasskey() {
  const metaStr = localStorage.getItem(LS_META);
  const data = localStorage.getItem(LS_KEY);
  if (!metaStr || !data) return { ok: false, msg: "当前没有加密数据。" };
  const meta = JSON.parse(metaStr);
  if (!meta || meta.v !== 2 || !meta.passkey) return { ok: false, msg: "当前未启用 Passkey 解锁。" };
  try {
    const resolved = await evaluatePasskeyPrf(meta.passkey.credentialId);
    const dekBytes = await unwrapBytesWithPasskeyPrf(
      meta.passkey.wrappedDek,
      resolved.prfOutput,
      fromB64(meta.passkey.saltB64)
    );
    state.dekRaw = dekBytes;
    state.key = await importDek(dekBytes);
    state.encMeta = meta;
    const parsed = JSON.parse(data);
    const iv = fromB64(parsed.iv);
    const ct = fromB64(parsed.ct);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, ct);
    const txt = new TextDecoder().decode(new Uint8Array(plain));
    state.items = (JSON.parse(txt).items || []).map(ensureItemDefaults);
    state.unlocked = true;
    return { ok: true };
  } catch (e) {
    if (e?.name === "NotAllowedError" || e?.name === "AbortError") {
      return { ok: false, canceled: true, msg: "已取消 Passkey 验证。" };
    }
    return { ok: false, msg: "Passkey 验证失败，或当前浏览器不支持该凭证。" };
  }
}

// ---------- sync projects persistence ----------
export function loadSyncProjects() {
  try {
    const projects = JSON.parse(localStorage.getItem(LS_SYNC_PROJECTS) || "[]");
    state.syncProjects = projects;
    state.currentProjectId = localStorage.getItem(LS_CURRENT_PROJECT) || null;
  } catch {
    state.syncProjects = [];
    state.currentProjectId = null;
  }
}

export function saveSyncProjects() {
  localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify(state.syncProjects));
  if (state.currentProjectId) {
    localStorage.setItem(LS_CURRENT_PROJECT, state.currentProjectId);
  } else {
    localStorage.removeItem(LS_CURRENT_PROJECT);
  }
}

export function getCurrentProject() {
  if (!state.currentProjectId || state.currentProjectId === "_all_") return null;
  return state.syncProjects.find(p => p.id === state.currentProjectId) || null;
}

// ---------- global token (renamed concept "Admin Key") ----------
export function loadGlobalToken() {
  try { return localStorage.getItem(LS_GLOBAL_TOKEN) || ""; }
  catch { return ""; }
}

export function saveGlobalToken(token) {
  if (token) localStorage.setItem(LS_GLOBAL_TOKEN, token);
  else localStorage.removeItem(LS_GLOBAL_TOKEN);
}

export function getGlobalToken() {
  return state.globalToken || loadGlobalToken();
}

// ---------- admin unlocked flag (session only) ----------
export function loadAdminUnlocked() {
  try { return sessionStorage.getItem(SS_ADMIN_UNLOCKED) === "1"; }
  catch { return false; }
}

export function saveAdminUnlocked(v) {
  try {
    if (v) sessionStorage.setItem(SS_ADMIN_UNLOCKED, "1");
    else sessionStorage.removeItem(SS_ADMIN_UNLOCKED);
  } catch {}
  state.adminUnlocked = !!v;
}
