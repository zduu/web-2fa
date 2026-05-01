// 本地存储：localStorage 读写、主密码 AES-GCM 加解密、项目持久化
// 完全保留旧 schema 以保证数据迁移零干预

import { deriveKey, toB64, fromB64 } from "./crypto.js";

export const LS_KEY = "authenticator.v1";
export const LS_META = "authenticator.v1.meta";
export const LS_SYNC = "authenticator.v1.sync";
export const LS_SYNC_PROJECTS = "authenticator.v1.syncProjects";
export const LS_GLOBAL_TOKEN = "authenticator.v1.globalToken";
export const LS_CURRENT_PROJECT = "authenticator.v1.currentProjectId";
export const SS_ADMIN_UNLOCKED = "authenticator.v1.adminUnlocked";

// state shared across modules
export const state = {
  items: [],
  unlocked: true,
  encMeta: null,
  key: null,                // CryptoKey for master password
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
  if (!data) { state.items = []; state.unlocked = true; return; }
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
    const salt = fromB64(meta.saltB64);
    state.key = await deriveKey(password, salt);
    state.encMeta = meta;
    let txt;
    try {
      const parsed = JSON.parse(data);
      const iv = fromB64(parsed.iv);
      const ct = fromB64(parsed.ct);
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, ct);
      txt = new TextDecoder().decode(new Uint8Array(plain));
    } catch {
      // legacy v1 format
      const iv = fromB64(meta.ivB64 || "");
      if (!iv.length) throw new Error("no-iv");
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, fromB64(data));
      txt = new TextDecoder().decode(new Uint8Array(plain));
    }
    const parsed = JSON.parse(txt);
    state.items = (parsed.items || []).map(ensureItemDefaults);
    state.unlocked = true;
    return true;
  } catch {
    return false;
  }
}

export async function setMasterPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  state.key = await deriveKey(password, salt);
  state.encMeta = { saltB64: toB64(salt) };
  await persist();
}

export async function clearMasterPassword() {
  state.key = null;
  state.encMeta = null;
  await persist();
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
