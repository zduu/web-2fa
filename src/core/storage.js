// 本地存储：localStorage 读写、主密码 AES-GCM 加解密、项目持久化
// 完全保留旧 schema 以保证数据迁移零干预

import { deriveKey, toB64, fromB64, KDF_ITERATIONS_DEFAULT, normalizeKdfIterations } from "./crypto.js";
import {
  createLocalUnlockPasskey,
  evaluatePasskeyPrf,
  getPasskeyPrfSupport,
  unwrapBytesWithPasskeyPrf,
  wrapBytesWithPasskeyPrf,
} from "./passkey.js";
import {
  normalizeHotpCounter,
  normalizeOtpAlgorithm,
  normalizeOtpDigits,
  normalizeOtpPeriod,
  normalizeOtpSecret,
  normalizeOtpType,
} from "./totp.js";

export const LS_KEY = "authenticator.v1";
export const LS_META = "authenticator.v1.meta";
export const LS_SYNC_PROJECTS = "authenticator.v1.syncProjects";
export const LS_GLOBAL_TOKEN = "authenticator.v1.globalToken";
export const LS_CURRENT_PROJECT = "authenticator.v1.currentProjectId";
export const SS_ADMIN_UNLOCKED = "authenticator.v1.adminUnlocked";
export const SYNC_AUTO_INTERVAL_DEFAULT = 60_000;
export const SYNC_AUTO_INTERVAL_MIN = 5_000;
export const SYNC_AUTO_INTERVAL_MAX = 24 * 3600_000;

let syncProjectsSaveQueue = Promise.resolve();
let syncProjectsSaveGeneration = 0;

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

export function normalizeShareRefs(shares) {
  if (!Array.isArray(shares)) return [];
  return shares.map((share) => {
    if (typeof share === "string") {
      const sid = share.trim();
      return sid ? { sid } : null;
    }
    if (share && typeof share.sid === "string") {
      const sid = share.sid.trim();
      if (!sid) return null;
      const k = typeof share.k === "string" && share.k ? share.k : undefined;
      return { sid, k };
    }
    return null;
  }).filter(Boolean);
}

export function mergeShareRefs(...groups) {
  const bySid = new Map();
  for (const share of groups.flatMap(normalizeShareRefs)) {
    if (!bySid.has(share.sid)) {
      bySid.set(share.sid, share);
      continue;
    }
    const prev = bySid.get(share.sid);
    if (!prev.k && share.k) prev.k = share.k;
  }
  return Array.from(bySid.values());
}

export function normalizeStoredTimestamp(value, fallback = Date.now()) {
  const ts = Math.trunc(Number(value));
  if (!Number.isFinite(ts) || ts <= 0 || ts > Number.MAX_SAFE_INTEGER) return fallback;
  return ts;
}

export function normalizeSyncAutoInterval(value, fallback = SYNC_AUTO_INTERVAL_DEFAULT) {
  const interval = Math.trunc(Number(value));
  if (!Number.isFinite(interval) || interval < SYNC_AUTO_INTERVAL_MIN || interval > SYNC_AUTO_INTERVAL_MAX) return fallback;
  return interval;
}

function normalizeStoredBoolean(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0 || value === null || value === undefined) return false;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "y";
  }
  return false;
}

export function ensureItemDefaults(it, options = {}) {
  const timestampFallback = options && typeof options === "object" && "updatedAtFallback" in options
    ? options.updatedAtFallback
    : Date.now();
  const out = { ...it };
  out.issuer = String(out.issuer || "").trim();
  out.account = String(out.account || "").trim();
  out.password = typeof out.password === "string" ? out.password : "";
  out.secret = normalizeOtpSecret(out.secret);
  out.type = normalizeOtpType(out.type);
  out.algorithm = normalizeOtpAlgorithm(out.algorithm);
  out.digits = normalizeOtpDigits(out.digits || 6);
  out.period = normalizeOtpPeriod(out.period || 30);
  out.counter = normalizeHotpCounter(out.counter ?? 0);
  out.updatedAt = normalizeStoredTimestamp(out.updatedAt, timestampFallback);
  out.deleted = normalizeStoredBoolean(out.deleted);
  out.pinned = normalizeStoredBoolean(out.pinned);
  out.note = typeof out.note === "string" ? out.note : "";
  out.shares = normalizeShareRefs(out.shares);
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

function isEncryptedPayload(parsed) {
  return !!(parsed && typeof parsed === "object" && !Array.isArray(parsed) && parsed.v === 2 && parsed.iv && parsed.ct);
}

async function encryptJsonPayload(value, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(value));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
  return { v: 2, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

async function decryptJsonPayload(parsed, key) {
  const iv = fromB64(parsed.iv);
  const ct = fromB64(parsed.ct);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(new Uint8Array(plain)));
}

export function normalizeSyncProject(project) {
  return {
    ...project,
    id: String(project?.id || "").trim(),
    name: String(project?.name || "").trim(),
    syncId: String(project?.syncId || "").trim(),
    secret: typeof project?.secret === "string" ? project.secret.trim() : "",
    auto: normalizeStoredBoolean(project?.auto),
    autoInterval: normalizeSyncAutoInterval(project?.autoInterval),
    lastSyncedAt: normalizeStoredTimestamp(project?.lastSyncedAt, 0),
    itemsData: Array.isArray(project?.itemsData)
      ? project.itemsData.map(ensureItemDefaults)
      : [],
    itemOrder: Array.isArray(project?.itemOrder) ? project.itemOrder.slice() : [],
  };
}

function normalizeSyncProjects(projects) {
  return (Array.isArray(projects) ? projects : []).map(normalizeSyncProject);
}

function applySyncProjectsPayload(payload, fallbackCurrentProjectId = null) {
  const projects = Array.isArray(payload) ? payload : payload?.projects;
  state.syncProjects = normalizeSyncProjects(projects);
  const requestedCurrentProjectId = Array.isArray(payload) ? fallbackCurrentProjectId : (payload?.currentProjectId || fallbackCurrentProjectId);
  state.currentProjectId = normalizeCurrentProjectId(requestedCurrentProjectId, state.syncProjects);

  if (state.currentProjectId === "_all_") {
    state.items = [];
    for (const p of state.syncProjects) {
      for (const it of p.itemsData || []) {
        state.items.push({ ...it, _projectId: p.id, _projectName: normalizeProjectDisplayName(p.name) });
      }
    }
    return;
  }

  const current = state.syncProjects.find((p) => p.id === state.currentProjectId);
  if (current) state.items = current.itemsData.map((it) => ({ ...it }));
}

function normalizeProjectDisplayName(value) {
  return String(value || "").trim() || "未命名";
}

function normalizeCurrentProjectId(value, projects) {
  const requested = String(value || "").trim();
  const list = Array.isArray(projects) ? projects : [];
  if (requested === "_all_") return list.length ? "_all_" : null;
  if (requested && list.some((project) => project.id === requested)) return requested;
  return list.find((project) => project.id)?.id || null;
}

function readLocalStorage(key, fallback = null) {
  try {
    return globalThis.localStorage?.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function removeLocalStorage(key) {
  try {
    globalThis.localStorage?.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

async function loadSyncProjectsAfterUnlock() {
  try {
    const raw = readLocalStorage(LS_SYNC_PROJECTS);
    if (!raw) {
      state.syncProjects = [];
      state.currentProjectId = readLocalStorage(LS_CURRENT_PROJECT);
      return;
    }

    const parsed = JSON.parse(raw);
    if (isEncryptedPayload(parsed)) {
      const payload = await decryptJsonPayload(parsed, state.key);
      applySyncProjectsPayload(payload, readLocalStorage(LS_CURRENT_PROJECT));
      return;
    }

    // Legacy plaintext project cache. Load it once, then the caller re-saves it encrypted.
    applySyncProjectsPayload(parsed, readLocalStorage(LS_CURRENT_PROJECT));
  } catch {
    state.syncProjects = [];
    state.currentProjectId = readLocalStorage(LS_CURRENT_PROJECT);
  }
}

export async function persist() {
  const payload = { items: state.items };
  if (state.key && state.encMeta) {
    const packed = await encryptJsonPayload(payload, state.key);
    localStorage.setItem(LS_KEY, JSON.stringify(packed));
    localStorage.setItem(LS_META, JSON.stringify(state.encMeta));
  } else {
    localStorage.setItem(LS_KEY, JSON.stringify(payload));
    localStorage.removeItem(LS_META);
  }
}

export function load() {
  const metaStr = readLocalStorage(LS_META);
  const data = readLocalStorage(LS_KEY);
  if (!data) {
    if (metaStr) removeLocalStorage(LS_META);
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
  const metaStr = readLocalStorage(LS_META);
  const data = readLocalStorage(LS_KEY);
  if (!metaStr || !data) {
    state.unlocked = true;
    return true;
  }
  try {
    const meta = JSON.parse(metaStr);
    if (meta.v === 2 && meta.master) {
      // 新格式 KEK/DEK
      const iter = normalizeKdfIterations(meta.iter);
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
      await loadSyncProjectsAfterUnlock();
      try { await saveSyncProjects(); } catch {}
      state.unlocked = true;
      return true;
    }
    // legacy v1：主密码直接派生 key
    const salt = fromB64(meta.saltB64);
    const iter = normalizeKdfIterations(meta.iter, 150000);
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
    await loadSyncProjectsAfterUnlock();
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
  await saveSyncProjects();
}

export async function clearMasterPassword() {
  state.key = null;
  state.dekRaw = null;
  state.encMeta = null;
  await persist();
  await saveSyncProjects();
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
    const meta = JSON.parse(readLocalStorage(LS_META) || "null");
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
    const meta = JSON.parse(readLocalStorage(LS_META) || "null");
    return !!(meta && meta.v === 2 && meta.passkey && meta.passkey.credentialId && meta.passkey.wrappedDek);
  } catch {
    return false;
  }
}

export function getPasskeySlotInfo() {
  try {
    const meta = JSON.parse(readLocalStorage(LS_META) || "null");
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
  const metaStr = readLocalStorage(LS_META);
  const data = readLocalStorage(LS_KEY);
  if (!metaStr || !data) return false;
  const cleaned = String(code || "").replace(/[^A-Z2-7]/gi, "").toUpperCase();
  if (!cleaned) return false;
  try {
    const meta = JSON.parse(metaStr);
    if (!meta || meta.v !== 2 || !meta.recovery) return false;
    const iter = normalizeKdfIterations(meta.iter);
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
    await loadSyncProjectsAfterUnlock();
    try { await saveSyncProjects(); } catch {}
    state.unlocked = true;
    return true;
  } catch {
    return false;
  }
}

export async function unlockWithPasskey() {
  const metaStr = readLocalStorage(LS_META);
  const data = readLocalStorage(LS_KEY);
  if (!metaStr || !data) return { ok: false, msg: "当前没有加密数据。" };
  try {
    const meta = JSON.parse(metaStr);
    if (!meta || meta.v !== 2 || !meta.passkey) return { ok: false, msg: "当前未启用 Passkey 解锁。" };
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
    await loadSyncProjectsAfterUnlock();
    try { await saveSyncProjects(); } catch {}
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
    if (readLocalStorage(LS_META)) {
      state.syncProjects = [];
      state.currentProjectId = null;
      return;
    }
    const parsed = JSON.parse(readLocalStorage(LS_SYNC_PROJECTS) || "[]");
    if (isEncryptedPayload(parsed)) {
      state.syncProjects = [];
      state.currentProjectId = null;
      return;
    }
    applySyncProjectsPayload(parsed, readLocalStorage(LS_CURRENT_PROJECT));
  } catch {
    state.syncProjects = [];
    state.currentProjectId = null;
  }
}

export function saveSyncProjects() {
  const hasMaster = !!(state.encMeta || readLocalStorage(LS_META));
  if (hasMaster && !state.key) {
    return Promise.resolve();
  }

  const snapshot = {
    projects: normalizeSyncProjects(state.syncProjects),
    currentProjectId: state.currentProjectId || null,
  };
  const generation = ++syncProjectsSaveGeneration;

  if (state.key && state.encMeta) {
    const key = state.key;
    syncProjectsSaveQueue = syncProjectsSaveQueue.catch(() => {}).then(async () => {
      const packed = await encryptJsonPayload(snapshot, key);
      if (generation !== syncProjectsSaveGeneration) return;
      try {
        localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify(packed));
        localStorage.removeItem(LS_CURRENT_PROJECT);
      } catch (e) {
        console.error("saveSyncProjects: localStorage write failed", e?.message || e);
      }
    });
    return syncProjectsSaveQueue;
  }

  try {
    localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify(snapshot.projects));
    if (state.currentProjectId) {
      localStorage.setItem(LS_CURRENT_PROJECT, state.currentProjectId);
    } else {
      localStorage.removeItem(LS_CURRENT_PROJECT);
    }
  } catch (e) {
    console.error("saveSyncProjects: localStorage write failed", e?.message || e);
  }
  return Promise.resolve();
}

export function lockLocalData() {
  if (!state.key && !state.encMeta && !readLocalStorage(LS_META)) return;
  state.key = null;
  state.dekRaw = null;
  state.unlocked = false;
  state.items = [];
  state.syncProjects = [];
  state.currentProjectId = null;
}

export function getCurrentProject() {
  if (!state.currentProjectId || state.currentProjectId === "_all_") return null;
  return state.syncProjects.find(p => p.id === state.currentProjectId) || null;
}

// ---------- global token (renamed concept "Admin Key") ----------
export function loadGlobalToken() {
  try {
    const sessionToken = sessionStorage.getItem(LS_GLOBAL_TOKEN) || "";
    if (sessionToken) return sessionToken;
  } catch {}
  const legacyToken = readLocalStorage(LS_GLOBAL_TOKEN, "");
  if (legacyToken) {
    try { sessionStorage.setItem(LS_GLOBAL_TOKEN, legacyToken); } catch {}
    removeLocalStorage(LS_GLOBAL_TOKEN);
  }
  return legacyToken;
}

export function saveGlobalToken(token) {
  try {
    if (token) sessionStorage.setItem(LS_GLOBAL_TOKEN, token);
    else sessionStorage.removeItem(LS_GLOBAL_TOKEN);
  } catch {}
  removeLocalStorage(LS_GLOBAL_TOKEN);
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
