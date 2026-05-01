// 应用入口：粘合 home / drawer / add / scanner，处理初始化和事件流

import {
  state, load, loadSyncProjects, loadGlobalToken, loadAdminUnlocked,
  persist, saveSyncProjects, getCurrentProject
} from "./src/core/storage.js";
import { initHome, renderHome, renderProjectBar, startTicker, setCardActions } from "./src/ui/home.js";
import { initDrawer, openDrawer } from "./src/ui/drawer.js";
import { openAddModal, openEditModal } from "./src/ui/add.js";
import { attachScanner } from "./src/ui/scanner.js";
import { switchToProject, ensureProjectActive, saveCurrentProjectItems } from "./src/sync/projects.js";
import { startAutoSync, scheduleAutoPush, pullCurrent, pushProject } from "./src/sync/sync.js";
import { shareItem } from "./src/share/share.js";
import { toast, copyText } from "./src/ui/toast.js";
import { confirmDialog, openModal } from "./src/ui/modal.js";
import { ensureItemDefaults } from "./src/core/storage.js";

const main = document.getElementById("main");
let dataChangedDebounce = null;

// ----- init -----
async function init() {
  loadSyncProjects();
  load();
  state.globalToken = loadGlobalToken();
  state.adminUnlocked = loadAdminUnlocked();
  ensureProjectActive();

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
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }

  // gate check
  gateCheck();

  // auto sync if enabled on current project
  const cur = getCurrentProject();
  if (cur && cur.auto) startAutoSync();

  // listen to data-changed events from cards (HOTP advance)
  window.addEventListener("data-changed", () => scheduleAutoPush());

  updateStatusBar();
}

function rerenderAll() {
  renderProjectBar(async (id) => {
    await switchToProject(id);
    rerenderAll();
  });
  renderHome();
  updateStatusBar();
}

function bindGlobalEvents() {
  document.getElementById("btn-add").addEventListener("click", openAdd);
  document.getElementById("fab-add").addEventListener("click", openAdd);
  document.getElementById("btn-settings").addEventListener("click", () => openDrawer("sync"));

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      // tick will run automatically; nothing extra
    }
  });
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

function normalizeImportedItem(raw) {
  return ensureItemDefaults({
    type: raw?.type || "totp",
    issuer: String(raw?.issuer || "").trim(),
    account: String(raw?.account || "").trim(),
    password: typeof raw?.password === "string" ? raw.password : "",
    secret: raw?.secret || "",
    algorithm: raw?.algorithm || "SHA1",
    digits: Number(raw?.digits || 6),
    period: Number(raw?.period || 30),
    counter: Number(raw?.counter || 0),
    deleted: false,
    updatedAt: Date.now(),
  });
}

function importFingerprint(item) {
  const normalized = ensureItemDefaults(item);
  return [
    normalized.type || "totp",
    String(normalized.secret || "").replace(/\s+/g, "").toUpperCase(),
    String(normalized.issuer || "").trim(),
    String(normalized.account || "").trim(),
    String(normalized.algorithm || "SHA1").toUpperCase(),
    Number(normalized.digits || 6),
    normalized.type === "hotp" ? `counter:${Number(normalized.counter || 0)}` : `period:${Number(normalized.period || 30)}`,
  ].join("|");
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
  const ttl = await chooseTtl();
  if (ttl === "cancel") return;
  try {
    const r = await shareItem(item, ttl);
    const ok = await copyText(r.link);
    toast(ok ? "分享链接已复制" : `已生成：${r.link}`, ok ? "ok" : "warn");
  } catch (e) {
    toast(`分享失败${e.status ? "：" + e.status : ""}`, "err");
  }
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
        </div>
      `,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">取消</button>
          <button class="btn" data-act="ok">生成链接</button>
        </div>
      `,
      onMount: (r, doClose) => {
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => { doClose(); resolve("cancel"); });
        r.querySelector('[data-act="ok"]').addEventListener("click", async () => {
          const v = r.querySelector('input[name="ttl"]:checked')?.value || "default";
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
          resolve(v === "default" ? null : (v === "perm" ? "perm" : Number(v)));
        });
      }
    });
    root.parentElement.addEventListener("click", (e) => {
      if (e.target === root.parentElement) resolve("cancel");
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

  if (isAll) {
    // mark deleted in source project
    const proj = state.syncProjects.find(p => p.id === item._projectId);
    if (!proj) { toast("未找到源项目", "err"); return; }
    if (!Array.isArray(proj.itemsData)) proj.itemsData = [];
    const target = proj.itemsData.find(x => x.id === item.id);
    if (target) {
      target.deleted = true;
      target.updatedAt = Date.now();
    }
    shareRevoke = await revokeAllShares(target);
    saveSyncProjects();
    item.deleted = true; // hide in aggregated view
  } else {
    const target = state.items.find(x => x.id === item.id);
    if (!target) return;
    target.deleted = true;
    target.updatedAt = Date.now();
    shareRevoke = await revokeAllShares(target);
    await persist();
    const cur = getCurrentProject();
    if (cur) { cur.itemsData = state.items.map(x => ({ ...x })); saveSyncProjects(); }
  }
  rerenderAll();
  scheduleAutoPush();
  if (shareRevoke.failed.length) {
    toast(`账户已删除，但 ${shareRevoke.failed.length}/${shareRevoke.attempted} 个分享撤销失败，请到“分享”页检查`, "warn", 3200);
  } else if (shareRevoke.revoked > 0) {
    toast(`已删除，并撤销 ${shareRevoke.revoked} 个分享`, "ok");
  } else {
    toast("已删除", "ok");
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

  txt.textContent = parts.join(" · ");
  dot.className = "dot" + (state.unlocked ? "" : " warn");

  bar.classList.remove("hidden");

  // sub-line in header
  if (sub) {
    sub.textContent = hasProject
      ? (state.currentProjectId === "_all_" ? "全部汇总（只读）" : (cur?.name || "本地"))
      : "本地存储 · 离线可用";
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

// ----- start -----
init();
