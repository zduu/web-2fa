// 应用入口：粘合 home / drawer / add / scanner，处理初始化和事件流

import {
  state, load, loadSyncProjects, loadGlobalToken, loadAdminUnlocked,
  persist, saveSyncProjects, getCurrentProject
} from "./src/core/storage.js";
import { initHome, renderHome, renderProjectBar, startTicker, setCardActions } from "./src/ui/home.js";
import { initDrawer, openDrawer } from "./src/ui/drawer.js";
import { openAddModal, openEditModal } from "./src/ui/add.js";
import { attachScanner } from "./src/ui/scanner.js";
import { switchToProject, ensureProjectActive } from "./src/sync/projects.js";
import { startAutoSync, scheduleAutoPush, pushProject, stopAutoSync } from "./src/sync/sync.js";
import { shareItem } from "./src/share/share.js";
import { toast, copyText } from "./src/ui/toast.js";
import { confirmDialog, openModal } from "./src/ui/modal.js";
import { ensureItemDefaults } from "./src/core/storage.js";
import { startIdleWatcher } from "./src/core/idle.js";
import { applyDensity } from "./src/ui/prefs.js";
import { importFromFileHandle } from "./src/ui/import-export.js";
import { parseOtpAuth, parseOtpAuthMigration } from "./src/core/totp.js";
import { importFingerprint, normalizeImportedItem } from "./src/core/imports.js";
import { initTheme } from "./src/ui/theme.js";
import { canUseCloudApis, isLocalOnlyApp } from "./src/core/runtime.js";

const main = document.getElementById("main");
let dataChangedDebounce = null;

// ----- init -----
async function init() {
  initTheme();
  applyDensity();
  loadSyncProjects();
  load();
  state.globalToken = loadGlobalToken();
  state.adminUnlocked = loadAdminUnlocked();
  ensureProjectActive();
  await normalizeProjectContext();

  // sync state.items with currently selected project (in case state was loaded directly)
  if (state.currentProjectId === "_all_") {
    await switchToProject("_all_");
  } else {
    const cur = getCurrentProject();
    if (cur && Array.isArray(cur.itemsData) && state.items.length === 0) {
      state.items = cur.itemsData.map(it => ({ ...it }));
    }
  }

  initHome(main);
  initDrawer(rerenderAll);

  setCardActions({
    onEdit: handleEdit,
    onShare: handleShare,
    onDelete: handleDelete,
  });

  rerenderAll();
  startTicker();
  bindGlobalEvents();

  // service worker
  if (canUseCloudApis() && "serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").then((reg) => {
      // 8.1 检测新版本
      const promptUpdate = (worker) => {
        if (!worker) return;
        toast("发现新版本", "ok", 60_000, {
          action: {
            label: "刷新",
            onClick: () => {
              worker.postMessage("SKIP_WAITING");
            },
          },
        });
      };
      if (reg.waiting) promptUpdate(reg.waiting);
      reg.addEventListener("updatefound", () => {
        const nw = reg.installing;
        if (!nw) return;
        nw.addEventListener("statechange", () => {
          if (nw.state === "installed" && navigator.serviceWorker.controller) {
            promptUpdate(reg.waiting || nw);
          }
        });
      });
      let refreshing = false;
      navigator.serviceWorker.addEventListener("controllerchange", () => {
        if (refreshing) return;
        refreshing = true;
        location.reload();
      });
      // 每 30 分钟主动检查一次更新
      setInterval(() => reg.update().catch(() => {}), 30 * 60_000);
    }).catch(() => {});
  }

  // gate check
  if (canUseCloudApis()) gateCheck();

  // auto sync if enabled on current project
  const cur = getCurrentProject();
  if (canUseCloudApis() && cur && cur.auto) startAutoSync();

  // listen to data-changed events from cards (HOTP advance)
  if (canUseCloudApis()) {
    window.addEventListener("data-changed", () => scheduleAutoPush());
  }

  // 6.3 同步状态事件
  window.addEventListener("sync-failed", (e) => {
    const d = e.detail || {};
    toast(`同步失败，${Math.round((d.delay || 0) / 1000)}s 后重试 (${d.attempt}/3)`, "warn", 1800);
  });
  window.addEventListener("sync-recovered", () => {
    toast("同步已恢复", "ok", 1500);
  });
  window.addEventListener("sync-give-up", () => {
    toast("同步多次失败，已放弃自动重试", "err", 3200);
  });

  // 闲置自动锁定（5.1 + 5.2）
  startIdleWatcher((reason) => {
    stopAutoSync();
    rerenderAll();
    toast(reason === "hidden" ? "离开过久已锁定" : "闲置已锁定", "warn", 2400);
  });

  // 时间漂移检测（5.3）
  if (canUseCloudApis()) detectTimeDrift();
  // 网络变化重新检测
  window.addEventListener("online", () => {
    if (canUseCloudApis()) detectTimeDrift();
    updateStatusBar();
  });
  window.addEventListener("offline", updateStatusBar);

  // 8.5 PWA share_target / 直接打开 otpauth 链接
  handleShareTargetIfAny();

  updateStatusBar();
}

function rerenderAll() {
  normalizeProjectContext().then(() => {
    renderProjectBar(async (id) => {
      await switchToProject(id);
      rerenderAll();
    });
    renderHome();
    updateStatusBar();
  });
}

function bindGlobalEvents() {
  document.getElementById("btn-add").addEventListener("click", openAdd);
  document.getElementById("fab-add").addEventListener("click", openAdd);
  document.getElementById("btn-settings").addEventListener("click", () => openDrawer(isLocalOnlyApp() || state.adminUnlocked ? "sync" : "data"));

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      // tick will run automatically; nothing extra
    }
  });

  // 2.2 全局键盘快捷键
  document.addEventListener("keydown", (e) => {
    // 输入态不拦截
    const t = e.target;
    const isTyping = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
    if (isTyping) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    if (e.key === "n" || e.key === "N") { e.preventDefault(); openAdd(); }
    else if (e.key === ",") { e.preventDefault(); openDrawer(isLocalOnlyApp() || state.adminUnlocked ? "sync" : "data"); }
    else if (e.key === "?") { e.preventDefault(); showShortcuts(); }
  });

  // 3.3 / 3.4 拖拽文件到页面导入（应用 JSON / Aegis / Bitwarden / andOTP）
  let dragDepth = 0;
  const dropZone = document.body;
  const dropOverlay = ensureDropOverlay();
  dropZone.addEventListener("dragenter", (e) => {
    if (!hasJsonFile(e)) return;
    dragDepth++;
    e.preventDefault();
    dropOverlay.classList.add("show");
  });
  dropZone.addEventListener("dragover", (e) => {
    if (!hasJsonFile(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  });
  dropZone.addEventListener("dragleave", (e) => {
    if (!hasJsonFile(e)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropOverlay.classList.remove("show");
  });
  dropZone.addEventListener("drop", async (e) => {
    if (!hasJsonFile(e)) return;
    e.preventDefault();
    dragDepth = 0;
    dropOverlay.classList.remove("show");
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    // 汇总视图只读；其他场景（具体项目 / 访客本地）都允许拖入
    if (state.currentProjectId === "_all_") {
      toast("汇总视图为只读，请切换到具体项目再拖入文件", "warn");
      return;
    }
    const ok = await importFromFileHandle(file);
    if (ok) rerenderAll();
  });
}

function hasJsonFile(e) {
  if (!e.dataTransfer) return false;
  const types = Array.from(e.dataTransfer.types || []);
  return types.includes("Files");
}

function ensureDropOverlay() {
  let el = document.getElementById("drop-overlay");
  if (el) return el;
  el = document.createElement("div");
  el.id = "drop-overlay";
  el.className = "drop-overlay";
  el.innerHTML = `<div class="drop-hint">📥 释放文件以导入到当前项目</div>`;
  document.body.appendChild(el);
  return el;
}

function showShortcuts() {
  openModal({
    title: "键盘快捷键",
    bodyHtml: `
      <ul class="shortcuts">
        <li><kbd>/</kbd> 聚焦搜索框</li>
        <li><kbd>n</kbd> 新建账号</li>
        <li><kbd>,</kbd> 打开设置</li>
        <li><kbd>?</kbd> 显示此帮助</li>
        <li><kbd>Esc</kbd> 关闭弹窗</li>
        <li>卡片获得焦点后：<kbd>Enter</kbd> 复制，<kbd>m</kbd> 菜单，<kbd>p</kbd> 置顶切换，<kbd>e</kbd> 编辑</li>
      </ul>
    `,
    footerHtml: `<div class="btn-row right"><button class="btn" data-act="close">好的</button></div>`,
    onMount: (r, doClose) => r.querySelector('[data-act="close"]').addEventListener("click", doClose),
  });
}

async function normalizeProjectContext() {
  if (isLocalOnlyApp() || state.adminUnlocked) return;
  if (state.currentProjectId !== "_all_") return;
  const fallback = state.syncProjects[0];
  if (!fallback) return;
  await switchToProject(fallback.id);
}

// ----- add new account -----
function openAdd() {
  if (!state.unlocked) {
    toast("请先在“设置 → 数据”里解锁本地数据", "warn");
    openDrawer("data");
    return;
  }
  if (state.currentProjectId === "_all_") {
    toast("汇总视图为只读，请切换到具体项目再添加", "warn");
    openDrawer("sync");
    return;
  }
  openAddModal({
    onSubmit: async (items) => {
      await importIntoCurrent(items, "导入完成");
    },
    onScan: (rootEl, doClose) => {
      attachScanner(rootEl, doClose, async (items) => {
        await importIntoCurrent(items, "扫码导入完成");
      });
    }
  });
}

async function importIntoCurrent(rawItems, actionLabel = "导入完成") {
  const stat = addManyToCurrent(rawItems);
  if (stat.added || stat.restored) {
    await persist();
    const cur = getCurrentProject();
    if (cur) {
      cur.itemsData = state.items.map(x => ({ ...x }));
      saveSyncProjects();
    }
    scheduleAutoPush();
    rerenderAll();
  }
  toast(formatImportResult(stat, actionLabel), (stat.added || stat.restored) ? "ok" : "warn");
}

function addManyToCurrent(rawItems) {
  const stat = { added: 0, restored: 0, skipped: 0 };
  const existing = buildImportLookup(state.items);
  const batchSeen = new Set();

  for (const raw of rawItems || []) {
    const normalized = normalizeImportedItem(raw);
    if (!normalized.secret) {
      stat.skipped++;
      continue;
    }

    const key = importFingerprint(normalized);
    if (batchSeen.has(key)) {
      stat.skipped++;
      continue;
    }
    batchSeen.add(key);

    const match = existing.get(key);
    if (!match) {
      const item = ensureItemDefaults({
        ...normalized,
        id: createItemId(),
        shares: [],
      });
      state.items.push(item);
      existing.set(key, item);
      stat.added++;
      continue;
    }

    if (match.deleted) {
      Object.assign(match, normalized, {
        id: match.id,
        password: normalized.password || match.password || "",
        deleted: false,
        updatedAt: Date.now(),
        shares: Array.isArray(match.shares) ? match.shares : [],
      });
      existing.set(key, match);
      stat.restored++;
      continue;
    }

    stat.skipped++;
  }

  return stat;
}

function buildImportLookup(items) {
  const map = new Map();
  for (const item of items || []) {
    const normalized = ensureItemDefaults(item);
    const key = importFingerprint(normalized);
    const prev = map.get(key);
    if (!prev) {
      map.set(key, item);
      continue;
    }
    if (prev.deleted && !item.deleted) {
      map.set(key, item);
      continue;
    }
    if (prev.deleted === !!item.deleted && Number(item.updatedAt || 0) >= Number(prev.updatedAt || 0)) {
      map.set(key, item);
    }
  }
  return map;
}

function createItemId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function formatImportResult(stat, actionLabel) {
  const parts = [];
  if (stat.added) parts.push(`新增 ${stat.added}`);
  if (stat.restored) parts.push(`恢复 ${stat.restored}`);
  if (stat.skipped) parts.push(`跳过重复 ${stat.skipped}`);
  if (!parts.length) parts.push("没有可导入的账户");
  return `${actionLabel}：${parts.join("，")}`;
}

// ----- card actions -----
async function handleShare(item) {
  if (isLocalOnlyApp()) {
    toast("本地 APK 版不支持云分享", "warn");
    return;
  }
  const choice = await chooseTtl();
  if (!choice || choice.cancel) return;
  try {
    const r = await shareItem(item, choice.ttl, choice.note || "", choice.maxAccess || 0, choice.password || "");
    const copied = await copyText(r.link);
    await showShareLinkDialog({
      label: `${item.issuer || ""}${item.account ? " · " + item.account : ""}`.trim() || "分享",
      link: r.link,
      ttl: choice.ttl,
      maxAccess: choice.maxAccess || 0,
      copied,
      password: choice.password || "",
      requiresPassword: !!r.requiresPassword,
    });
  } catch (e) {
    toast(`分享失败${e.status ? "：" + e.status : ""}`, "err");
  }
}

async function showShareLinkDialog({ label, link, ttl, maxAccess, copied, password, requiresPassword }) {
  let countdownTimer = null;
  const expiresAt = typeof ttl === "number" && ttl > 0 ? Date.now() + ttl * 1000 : null;
  openModal({
    title: "分享链接已生成",
    bodyHtml: `
      <div class="share-result col gap-2">
        <div class="share-qr-card">
          <div class="share-qr-stage center" id="share-qr-stage" aria-live="polite">
            <div class="text-sm muted">二维码生成中…</div>
          </div>
        </div>
        <div class="share-result-meta">
          <div class="share-result-title" id="share-link-status"></div>
          <div class="share-result-sub muted" id="share-link-expiry"></div>
        </div>
        ${requiresPassword ? `
          <div class="field">
            <label for="share-password-value">接收方访问口令</label>
            <input id="share-password-value" class="input mono" readonly />
            <div class="hint">链接里不包含这个口令。请通过其他安全渠道单独告诉接收方。</div>
          </div>
        ` : ""}
        <div class="field">
          <label for="share-link-value">分享链接</label>
          <input id="share-link-value" class="input mono" readonly />
        </div>
      </div>
    `,
    footerHtml: `
      <div class="btn-row between">
        <button class="btn ghost" data-act="open">打开链接</button>
        <div class="btn-row right">
          ${requiresPassword ? '<button class="btn ghost" data-act="copy-password">复制口令</button>' : ""}
          <button class="btn ghost" data-act="copy">复制链接</button>
          <button class="btn" data-act="done">完成</button>
        </div>
      </div>
    `,
    onClose: () => {
      if (countdownTimer) clearInterval(countdownTimer);
    },
    onMount: async (root, close) => {
      const input = root.querySelector("#share-link-value");
      const passwordInput = root.querySelector("#share-password-value");
      const status = root.querySelector("#share-link-status");
      const expiry = root.querySelector("#share-link-expiry");
      const qrStage = root.querySelector("#share-qr-stage");
      if (input) input.value = link;
      if (passwordInput) passwordInput.value = password;
      if (status) status.textContent = copied
        ? `“${label}” 的分享链接已复制，可直接扫码打开`
        : `“${label}” 的分享链接已生成，可扫码或手动复制`;

      const renderMeta = () => {
        const parts = [];
        if (ttl === "perm" || ttl === 0) parts.push("永久有效（高风险）");
        else if (expiresAt) parts.push(`剩余 ${formatShareCountdown(expiresAt - Date.now())}`);
        else parts.push("按服务端默认有效期");
        if (maxAccess > 0) parts.push(`最多 ${maxAccess} 次访问`);
        if (requiresPassword) parts.push("需访问口令");
        if (expiry) expiry.textContent = parts.join(" · ");
      };

      renderMeta();
      if (expiresAt) countdownTimer = setInterval(renderMeta, 1000);

      root.querySelector('[data-act="copy-password"]')?.addEventListener("click", async () => {
        const ok = await copyText(password);
        toast(ok ? "已复制口令" : "复制失败", ok ? "ok" : "err");
      });
      root.querySelector('[data-act="copy"]')?.addEventListener("click", async () => {
        const ok = await copyText(link);
        toast(ok ? "已复制链接" : "复制失败", ok ? "ok" : "err");
      });
      root.querySelector('[data-act="open"]')?.addEventListener("click", () => {
        window.open(link, "_blank", "noopener,noreferrer");
      });
      root.querySelector('[data-act="done"]')?.addEventListener("click", () => close("done"));

      try {
        const { renderQrSvg } = await import("./src/core/qrgen.js");
        qrStage.innerHTML = renderQrSvg(link, { pixelSize: 7 });
        qrStage.querySelector("svg")?.setAttribute("aria-label", "分享链接二维码");
      } catch {
        qrStage.innerHTML = '<div class="empty-msg">二维码生成失败，请直接复制链接</div>';
      }
    }
  });
}

function formatShareCountdown(ms) {
  if (!(ms > 0)) return "即将过期";
  const total = Math.ceil(ms / 1000);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours > 0) return `${hours}小时 ${String(minutes).padStart(2, "0")}分`;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function handleEdit(item) {
  openEditModal(item, {
    onSubmit: async (next) => {
      try {
        const stat = await saveEditedItem(item, next);
        rerenderAll();
        if (stat.failed > 0) {
          toast(`已保存，但有 ${stat.failed} 个旧分享未能撤销`, "warn", 2800);
        } else if (stat.revoked > 0) {
          toast(`已保存，并撤销 ${stat.revoked} 个旧分享`, "ok");
        } else {
          toast("已保存", "ok");
        }
      } catch (e) {
        toast(e.message || "保存失败", "err");
      }
    }
  });
}

async function saveEditedItem(item, next) {
  const stat = { revoked: 0, failed: 0 };
  const patch = ensureItemDefaults({
    ...item,
    ...next,
    id: item.id,
    shares: Array.isArray(item.shares) ? item.shares : [],
    deleted: false,
    updatedAt: Date.now(),
  });

  if (state.currentProjectId === "_all_") {
    const proj = state.syncProjects.find(p => p.id === item._projectId);
    if (!proj || !Array.isArray(proj.itemsData)) throw new Error("未找到源项目");
    const target = proj.itemsData.find(x => x.id === item.id);
    if (!target) throw new Error("未找到账户");
    if (sharePayloadChanged(target, patch)) {
      const r = await revokeAllShares(target);
      stat.revoked += r.revoked;
      stat.failed += r.failed.length;
      patch.shares = Array.isArray(target.shares) ? target.shares : [];
    }
    Object.assign(target, patch);
    saveSyncProjects();
    try { await pushProject(proj); }
    catch { toast("本地已保存，但同步到云端失败", "warn", 2600); }
    return stat;
  }

  const target = state.items.find(x => x.id === item.id);
  if (!target) throw new Error("未找到账户");
  if (sharePayloadChanged(target, patch)) {
    const r = await revokeAllShares(target);
    stat.revoked += r.revoked;
    stat.failed += r.failed.length;
    patch.shares = Array.isArray(target.shares) ? target.shares : [];
  }
  Object.assign(target, patch);
  await persist();
  const cur = getCurrentProject();
  if (cur) {
    cur.itemsData = state.items.map(x => ({ ...x }));
    saveSyncProjects();
  }
  scheduleAutoPush();
  return stat;
}

function sharePayloadChanged(prev, next) {
  return (
    (prev.type || "totp") !== (next.type || "totp") ||
    String(prev.secret || "").replace(/\s+/g, "").toUpperCase() !== String(next.secret || "").replace(/\s+/g, "").toUpperCase() ||
    String(prev.issuer || "") !== String(next.issuer || "") ||
    String(prev.account || "") !== String(next.account || "") ||
    String(prev.algorithm || "SHA1").toUpperCase() !== String(next.algorithm || "SHA1").toUpperCase() ||
    Number(prev.digits || 6) !== Number(next.digits || 6) ||
    Number(prev.period || 30) !== Number(next.period || 30) ||
    Number(prev.counter || 0) !== Number(next.counter || 0)
  );
}

function chooseTtl() {
  return new Promise((resolve) => {
    const { close, root } = openModal({
      title: "分享有效期",
      bodyHtml: `
        <div class="col gap-2">
          <div class="section-card" style="margin-bottom:8px;">
            <div class="text-sm" style="font-weight:600; margin-bottom:6px;">这会分享该账户的 2FA Secret</div>
            <div class="hint" style="line-height:1.7;">
              对方拿到链接后，不是只看到当前验证码，而是能持续生成后续验证码。撤销链接也无法收回对方已经看到或抄走的 Secret。
            </div>
          </div>
          <label class="row gap-2"><input type="radio" name="ttl" value="default" checked /> <span>默认（后端配置，常为 24 小时）</span></label>
          <label class="row gap-2"><input type="radio" name="ttl" value="3600" /> <span>1 小时</span></label>
          <label class="row gap-2"><input type="radio" name="ttl" value="86400" /> <span>24 小时</span></label>
          <label class="row gap-2"><input type="radio" name="ttl" value="perm" /> <span>永久（高风险，不推荐）</span></label>
          <div class="field mt-2">
            <label>最多访问次数 <span class="muted">（0 = 不限）</span></label>
            <select id="share-max" class="input">
              <option value="0">不限</option>
              <option value="1">1 次（一次性，访问后立即失效）</option>
              <option value="3">3 次</option>
              <option value="5">5 次</option>
              <option value="10">10 次</option>
            </select>
          </div>
          <div class="field mt-2">
            <label>备注 <span class="muted">（可选，最多 280 字，对方页面可见）</span></label>
            <textarea id="share-note" class="input" maxlength="280" placeholder="例如：登录 X 网站请用此码"></textarea>
          </div>
          <div class="field mt-2">
            <label>接收方访问口令 <span class="muted">（可选，不填则只靠链接）</span></label>
            <input id="share-passcode" class="input" type="password" maxlength="128" placeholder="留空表示不设置额外口令" />
            <div class="hint">设置后，链接本身无法直接打开，需要接收方另行输入这个口令。</div>
          </div>
        </div>
      `,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">取消</button>
          <button class="btn" data-act="ok">生成链接</button>
        </div>
      `,
      onMount: (r, doClose) => {
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => { doClose(); resolve({ cancel: true }); });
        r.querySelector('[data-act="ok"]').addEventListener("click", async () => {
          const v = r.querySelector('input[name="ttl"]:checked')?.value || "default";
          const note = (r.querySelector("#share-note")?.value || "").trim();
          const maxAccess = Number(r.querySelector("#share-max")?.value || 0) || 0;
          const password = (r.querySelector("#share-passcode")?.value || "").trim();
          if (v === "perm") {
            const ok = await confirmDialog({
              title: "确认永久分享？",
              message: "永久分享会长期暴露这个 2FA Secret。即使之后撤销链接，也无法收回对方已经看到或保存的 Secret。确定继续？",
              danger: true,
              okText: "仍然分享",
            });
            if (!ok) return;
          }
          doClose();
          const ttl = v === "default" ? null : (v === "perm" ? "perm" : Number(v));
          resolve({ ttl, note, maxAccess, password });
        });
      }
    });
    root.parentElement.addEventListener("click", (e) => {
      if (e.target === root.parentElement) resolve({ cancel: true });
    });
  });
}

async function handleDelete(item) {
  const ok = await confirmDialog({
    title: "删除账户？",
    message: `${item.issuer || "(未命名)"} ${item.account ? "· " + item.account : ""}`,
    danger: true,
    okText: "删除",
  });
  if (!ok) return;

  const isAll = state.currentProjectId === "_all_";
  let shareRevoke = { attempted: 0, revoked: 0, failed: [] };

  // 记录撤销快照
  let undoSnapshot = null;

  if (isAll) {
    // mark deleted in source project
    const proj = state.syncProjects.find(p => p.id === item._projectId);
    if (!proj) { toast("未找到源项目", "err"); return; }
    if (!Array.isArray(proj.itemsData)) proj.itemsData = [];
    const target = proj.itemsData.find(x => x.id === item.id);
    if (target) {
      undoSnapshot = {
        scope: "all",
        projectId: proj.id,
        itemId: item.id,
        prev: { deleted: !!target.deleted, updatedAt: Number(target.updatedAt || 0), shares: Array.isArray(target.shares) ? target.shares.map(s => (typeof s === "string" ? { sid: s } : { ...s })) : [] },
      };
      target.deleted = true;
      target.updatedAt = Date.now();
    }
    shareRevoke = await revokeAllShares(target);
    saveSyncProjects();
    item.deleted = true; // hide in aggregated view
  } else {
    const target = state.items.find(x => x.id === item.id);
    if (!target) return;
    undoSnapshot = {
      scope: "current",
      itemId: item.id,
      prev: { deleted: !!target.deleted, updatedAt: Number(target.updatedAt || 0), shares: Array.isArray(target.shares) ? target.shares.map(s => (typeof s === "string" ? { sid: s } : { ...s })) : [] },
    };
    target.deleted = true;
    target.updatedAt = Date.now();
    shareRevoke = await revokeAllShares(target);
    await persist();
    const cur = getCurrentProject();
    if (cur) { cur.itemsData = state.items.map(x => ({ ...x })); saveSyncProjects(); }
  }
  rerenderAll();
  scheduleAutoPush();

  // 撤销动作（不能恢复已撤销的远端 share，但可以恢复 deleted 标志）
  const doUndo = async () => {
    try {
      if (undoSnapshot.scope === "all") {
        const proj = state.syncProjects.find(p => p.id === undoSnapshot.projectId);
        const target = proj?.itemsData?.find(x => x.id === undoSnapshot.itemId);
        if (target) {
          target.deleted = undoSnapshot.prev.deleted;
          target.updatedAt = undoSnapshot.prev.updatedAt || Date.now();
        }
        saveSyncProjects();
      } else {
        const target = state.items.find(x => x.id === undoSnapshot.itemId);
        if (target) {
          target.deleted = undoSnapshot.prev.deleted;
          target.updatedAt = undoSnapshot.prev.updatedAt || Date.now();
        }
        await persist();
        const cur = getCurrentProject();
        if (cur) { cur.itemsData = state.items.map(x => ({ ...x })); saveSyncProjects(); }
      }
      rerenderAll();
      scheduleAutoPush();
      toast("已恢复（注意：已撤销的分享链接无法恢复）", "ok", 2400);
    } catch (e) { toast("撤销失败：" + (e.message || e), "err"); }
  };

  if (shareRevoke.failed.length) {
    toast(`已删除，但 ${shareRevoke.failed.length}/${shareRevoke.attempted} 个分享撤销失败`, "warn", 4000, { action: undoSnapshot ? { label: "撤销", onClick: doUndo } : undefined });
  } else if (shareRevoke.revoked > 0) {
    toast(`已删除（同时撤销 ${shareRevoke.revoked} 个分享）`, "ok", 4000, { action: undoSnapshot ? { label: "撤销", onClick: doUndo } : undefined });
  } else {
    toast("已删除", "ok", 4000, { action: undoSnapshot ? { label: "撤销", onClick: doUndo } : undefined });
  }
}

async function revokeAllShares(item) {
  const result = { attempted: 0, revoked: 0, failed: [] };
  if (!item || !Array.isArray(item.shares) || !item.shares.length) return result;
  const token = state.globalToken;
  const headers = token ? { "X-Token": token } : {};
  const kept = [];
  for (const s of item.shares) {
    const sid = typeof s === "string" ? s : s?.sid;
    if (!sid) continue;
    result.attempted++;
    try {
      const res = await fetch(`/api/share/${encodeURIComponent(sid)}`, { method: "DELETE", headers });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      result.revoked++;
    } catch (e) {
      kept.push(s);
      result.failed.push({ sid, error: e?.message || "network" });
    }
  }
  item.shares = kept;
  return result;
}

// ----- status bar (top-right indicators) -----
let timeDriftSec = 0;

function updateStatusBar() {
  const bar = document.getElementById("status-bar");
  const dot = document.getElementById("status-dot");
  const txt = document.getElementById("status-text");
  const sub = document.getElementById("brand-sub");
  if (!bar || !dot || !txt) return;

  const hasProject = state.syncProjects.length > 0;
  const cur = getCurrentProject();
  const isAdmin = state.adminUnlocked;

  let parts = [];
  if (!state.unlocked) parts.push("已加密");
  if (!hasProject) parts.push("仅本地");
  else if (state.currentProjectId === "_all_") parts.push("汇总视图");
  else if (cur) parts.push(cur.name || "项目");
  if (isAdmin) parts.push("管理员");
  if (typeof navigator !== "undefined" && navigator.onLine === false) parts.push("离线");
  if (Math.abs(timeDriftSec) >= 15) parts.push(`时间偏差 ${timeDriftSec > 0 ? "+" : ""}${timeDriftSec}s`);

  txt.textContent = parts.join(" · ");
  dot.className = "dot" + (state.unlocked ? "" : " warn") + (Math.abs(timeDriftSec) >= 15 ? " warn" : "");

  bar.classList.remove("hidden");

  // sub-line in header
  if (sub) {
    sub.textContent = hasProject
      ? (state.currentProjectId === "_all_" ? "全部汇总（只读）" : (cur?.name || "本地"))
      : "本地存储 · 离线可用";
  }
}

// 5.3 启动时检测系统时间漂移：用 HEAD / 的 Date 头与 Date.now() 对比
async function detectTimeDrift() {
  try {
    const t0 = Date.now();
    const res = await fetch("/", { method: "HEAD", cache: "no-store" });
    const t1 = Date.now();
    const dateHeader = res.headers.get("Date");
    if (!dateHeader) return;
    const serverMs = Date.parse(dateHeader);
    if (!Number.isFinite(serverMs)) return;
    // 修正请求往返：服务器 Date 大致对应 t0..t1 中点
    const localMid = (t0 + t1) / 2;
    const driftMs = localMid - serverMs;
    timeDriftSec = Math.round(driftMs / 1000);
    if (Math.abs(timeDriftSec) >= 30) {
      toast(`系统时间偏差 ${timeDriftSec > 0 ? "+" : ""}${timeDriftSec}s，验证码可能无效，请校准系统时间`, "warn", 4500);
    }
    updateStatusBar();
  } catch {
    // 忽略，离线状态下不可用
  }
}

// ----- gate -----
async function gateCheck() {
  try {
    const res = await fetch("/api/gate", { method: "GET", headers: { "Cache-Control": "no-cache" } });
    if (res.status === 403) showGateModal();
  } catch {}
}

function showGateModal() {
  openModal({
    title: "🔒 访问验证",
    bodyHtml: `
      <p class="hint mb-2">此站点启用了访问口令，请输入后继续。</p>
      <div class="field">
        <input id="g-pass" class="input" type="password" placeholder="访问口令" />
      </div>
      <div id="g-msg" class="hint mt-2" style="color: var(--danger);"></div>
    `,
    footerHtml: `
      <div class="btn-row right">
        <button class="btn" data-act="ok">进入</button>
      </div>
    `,
    dismissible: false,
    onMount: (r, doClose) => {
      const pass = r.querySelector("#g-pass");
      const msg = r.querySelector("#g-msg");
      pass.focus();
      const submit = async () => {
        const pw = pass.value;
        if (!pw) { msg.textContent = "请输入访问口令"; return; }
        try {
          const res = await fetch("/api/gate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: pw })
          });
          if (res.ok) { doClose(); toast("已通过验证", "ok"); }
          else { msg.textContent = "口令错误"; }
        } catch { msg.textContent = "网络错误"; }
      };
      pass.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
      r.querySelector('[data-act="ok"]').addEventListener("click", submit);
    }
  });
}

// 8.5 处理 share_target / otpauth URL 参数
async function handleShareTargetIfAny() {
  const params = new URLSearchParams(location.search);
  const candidates = [params.get("text"), params.get("url"), params.get("title")].filter(Boolean);
  let items = [];
  for (const raw of candidates) {
    if (raw.startsWith("otpauth://")) {
      const it = parseOtpAuth(raw);
      if (it && it.secret) items.push(it);
    } else if (raw.startsWith("otpauth-migration://")) {
      const arr = parseOtpAuthMigration(raw);
      if (arr.length) items.push(...arr);
    }
  }
  if (!items.length) return;
  // 清理 URL 参数（避免刷新重复导入）
  history.replaceState({}, "", location.pathname);
  // 等待初始化完成后导入
  setTimeout(async () => {
    if (state.currentProjectId === "_all_") {
      toast("汇总视图为只读，请切换到具体项目再导入", "warn");
      return;
    }
    if (!state.unlocked) {
      toast("请先解锁本地数据再导入", "warn");
      return;
    }
    await importIntoCurrent(items, "已通过分享导入");
  }, 100);
}

// ----- start -----
init();
