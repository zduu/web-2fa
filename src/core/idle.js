// 闲置自动锁定（5.1 + 5.2）
// - 监听 mousemove/keydown/pointerdown，更新 lastActive
// - 每 30s 检查一次：超过 idleMs 触发锁定回调
// - visibilitychange=hidden 启动后台计时器，N 分钟内未回 visible 也触发锁定
// - 配置项：idleLockMinutes（>0 启用，<=0 关闭）；hiddenLockMinutes（同）

import { lockLocalData, state, saveAdminUnlocked, saveGlobalToken } from "./storage.js";

export const LS_IDLE_LOCK = "authenticator.v1.idleLockMinutes";
export const LS_HIDDEN_LOCK = "authenticator.v1.hiddenLockMinutes";

const DEFAULT_IDLE = 10;   // 分钟，0 = 禁用
const DEFAULT_HIDDEN = 5;  // 分钟，0 = 禁用
const MAX_LOCK_MINUTES = 1440;
const CHECK_INTERVAL_MS = 30 * 1000;

let lastActive = Date.now();
let checkTimer = null;
let hiddenAt = 0;
let bound = false;
let onLockCb = null;

export function getIdleMinutes() {
  const raw = readLocalStorage(LS_IDLE_LOCK);
  if (raw === null) return DEFAULT_IDLE;
  return normalizeLockMinutes(raw, DEFAULT_IDLE);
}
export function setIdleMinutes(n) {
  writeLocalStorage(LS_IDLE_LOCK, String(normalizeLockMinutes(n, 0)));
}
export function getHiddenMinutes() {
  const raw = readLocalStorage(LS_HIDDEN_LOCK);
  if (raw === null) return DEFAULT_HIDDEN;
  return normalizeLockMinutes(raw, DEFAULT_HIDDEN);
}
export function setHiddenMinutes(n) {
  writeLocalStorage(LS_HIDDEN_LOCK, String(normalizeLockMinutes(n, 0)));
}

export function normalizeLockMinutes(value, fallback) {
  const minutes = Math.trunc(Number(value));
  if (!Number.isFinite(minutes) || minutes < 0) return fallback;
  return Math.min(MAX_LOCK_MINUTES, minutes);
}

function pump() {
  lastActive = Date.now();
  hiddenAt = 0;
}

export function startIdleWatcher(onLock) {
  onLockCb = onLock;
  const doc = globalThis.document;
  if (!doc || typeof doc.addEventListener !== "function") return;
  if (bound) return;
  bound = bindIdleWatcherEvents({
    doc,
    win: globalThis.window,
    onActivity: pump,
    onHidden: () => { hiddenAt = Date.now(); },
    onVisible: () => { hiddenAt = 0; pump(); },
  });
  if (!bound) return;
  if (checkTimer) clearInterval(checkTimer);
  checkTimer = setInterval(check, CHECK_INTERVAL_MS);
}

export function stopIdleWatcher() {
  if (checkTimer) { clearInterval(checkTimer); checkTimer = null; }
}

function check() {
  // 仅在管理员或本地已解锁时才有意义
  if (!state.adminUnlocked && state.unlocked) {
    // 普通访客模式下，state.unlocked 默认 true 但没敏感数据；除非有主密码加密才需重锁
    if (!state.key) return;
  }
  const idleMin = getIdleMinutes();
  if (idleMin > 0) {
    const idleMs = idleMin * 60_000;
    if (Date.now() - lastActive >= idleMs) { triggerLock("idle"); return; }
  }
  const hidMin = getHiddenMinutes();
  if (hidMin > 0 && hiddenAt > 0) {
    const hidMs = hidMin * 60_000;
    if (Date.now() - hiddenAt >= hidMs) { triggerLock("hidden"); return; }
  }
}

function triggerLock(reason) {
  // 锁管理员（不影响普通本地数据访问）
  if (state.adminUnlocked) {
    state.globalToken = "";
    saveGlobalToken("");
    saveAdminUnlocked(false);
  }
  // 仅当本地数据是加密保存的（state.key 存在）时才清空内存中的 key 与 items
  // 否则普通用户没有主密码加密，items 也不应被清空
  if (state.key) {
    lockLocalData();
  }
  hiddenAt = 0;
  lastActive = Date.now();
  try { onLockCb?.(reason); } catch (e) { console.error(e); }
}

export function getIdleVisibilityState(doc = globalThis.document) {
  try {
    return String(doc?.visibilityState || "");
  } catch {
    return "";
  }
}

export function bindIdleWatcherEvents({
  doc = globalThis.document,
  win = globalThis.window,
  onActivity = () => {},
  onHidden = () => {},
  onVisible = () => {},
} = {}) {
  let boundAny = false;
  if (win && typeof win.addEventListener === "function") {
    for (const ev of ["mousemove", "keydown", "pointerdown", "touchstart", "wheel"]) {
      try {
        win.addEventListener(ev, onActivity, { passive: true });
        boundAny = true;
      } catch {}
    }
  }
  if (doc && typeof doc.addEventListener === "function") {
    try {
      doc.addEventListener("visibilitychange", () => {
        if (getIdleVisibilityState(doc) === "hidden") onHidden();
        else onVisible();
      });
      boundAny = true;
    } catch {}
  }
  return boundAny;
}

function readLocalStorage(key) {
  try { return globalThis.localStorage?.getItem(key) ?? null; }
  catch { return null; }
}

function writeLocalStorage(key, value) {
  try { globalThis.localStorage?.setItem(key, value); }
  catch {}
}

// 测试用：手动触发
export function _debugLock(reason = "manual") { triggerLock(reason); }
