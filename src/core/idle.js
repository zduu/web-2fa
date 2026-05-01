// 闲置自动锁定（5.1 + 5.2）
// - 监听 mousemove/keydown/pointerdown，更新 lastActive
// - 每 30s 检查一次：超过 idleMs 触发锁定回调
// - visibilitychange=hidden 启动后台计时器，N 分钟内未回 visible 也触发锁定
// - 配置项：idleLockMinutes（>0 启用，<=0 关闭）；hiddenLockMinutes（同）

import { state, saveAdminUnlocked, saveGlobalToken } from "./storage.js";

export const LS_IDLE_LOCK = "authenticator.v1.idleLockMinutes";
export const LS_HIDDEN_LOCK = "authenticator.v1.hiddenLockMinutes";

const DEFAULT_IDLE = 10;   // 分钟，0 = 禁用
const DEFAULT_HIDDEN = 5;  // 分钟，0 = 禁用
const CHECK_INTERVAL_MS = 30 * 1000;

let lastActive = Date.now();
let checkTimer = null;
let hiddenAt = 0;
let bound = false;
let onLockCb = null;

export function getIdleMinutes() {
  const raw = localStorage.getItem(LS_IDLE_LOCK);
  if (raw === null) return DEFAULT_IDLE;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_IDLE;
}
export function setIdleMinutes(n) {
  localStorage.setItem(LS_IDLE_LOCK, String(Math.max(0, Math.min(1440, Number(n) || 0))));
}
export function getHiddenMinutes() {
  const raw = localStorage.getItem(LS_HIDDEN_LOCK);
  if (raw === null) return DEFAULT_HIDDEN;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_HIDDEN;
}
export function setHiddenMinutes(n) {
  localStorage.setItem(LS_HIDDEN_LOCK, String(Math.max(0, Math.min(1440, Number(n) || 0))));
}

function pump() {
  lastActive = Date.now();
  hiddenAt = 0;
}

export function startIdleWatcher(onLock) {
  onLockCb = onLock;
  if (bound) return;
  bound = true;
  ["mousemove", "keydown", "pointerdown", "touchstart", "wheel"].forEach(ev => {
    window.addEventListener(ev, pump, { passive: true });
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") hiddenAt = Date.now();
    else { hiddenAt = 0; pump(); }
  });
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
    state.key = null;
    state.unlocked = false;
    state.items = [];
  }
  hiddenAt = 0;
  lastActive = Date.now();
  try { onLockCb?.(reason); } catch (e) { console.error(e); }
}

// 测试用：手动触发
export function _debugLock(reason = "manual") { triggerLock(reason); }
