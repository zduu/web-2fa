// 右侧抽屉 + L2 / L3 面板渲染
// L2：项目同步 / 数据 / 关于
// L3：管理员模式（云端浏览 / Vault / 迁移 / 模式切换 / 退出）

import { state, saveSyncProjects, tryUnlock, setMasterPassword, clearMasterPassword,
  loadAdminUnlocked, generateRecoveryCode, hasRecoveryCode, clearRecoveryCode, unlockWithRecoveryCode,
  getPasskeySupport, hasPasskeyUnlock, getPasskeySlotInfo, setupPasskeyUnlock, clearPasskeyUnlock, unlockWithPasskey } from "../core/storage.js";
import {
  listProjects, detectDuplicateSyncIds, createProject, updateProject, deleteProject,
  switchToProject, saveCurrentProjectItems
} from "../sync/projects.js";
import {
  pushCurrent, pullCurrent, mergeAllProjectsIntoCurrent, cleanDeleted,
  startAutoSync, stopAutoSync, scheduleAutoPush, deleteCloudProject
} from "../sync/sync.js";
import { toast, copyText, escapeHtml } from "./toast.js";
import { confirmDialog, openModal, promptDialog } from "./modal.js";
import { verifyAdminKey, unlockAdmin, lockAdmin } from "../admin/unlock.js";
import { APP_VERSION } from "../core/version.js";
import {
  getIdleMinutes, setIdleMinutes,
  getHiddenMinutes, setHiddenMinutes,
} from "../core/idle.js";
import { getDensity, setDensity } from "./prefs.js";
import { getThemePreference, setThemePreference } from "./theme.js";
import {
  scorePassword, getUnlockBlockMs, recordUnlockFail, clearUnlockFails,
} from "../core/password-strength.js";
import { pemFingerprint } from "../core/crypto.js";
import {
  apiUrl, canUseCloudApis, clearCloudBaseUrls, getCloudBaseUrls,
  isAndroidApp, isLocalOnlyApp, setCloudBaseUrls,
} from "../core/runtime.js";

const moduleCache = {
  share: null,
  importExport: null,
  cloud: null,
  vault: null,
};

function loadShareModule() {
  moduleCache.share ||= import("../share/share.js");
  return moduleCache.share;
}

function loadImportExportModule() {
  moduleCache.importExport ||= import("./import-export.js");
  return moduleCache.importExport;
}

function loadCloudModule() {
  moduleCache.cloud ||= import("../sync/cloud.js");
  return moduleCache.cloud;
}

function loadVaultModule() {
  moduleCache.vault ||= import("../sync/vault.js");
  return moduleCache.vault;
}

// 5.11 高危操作二次确认：要求重新输入 Admin Key
async function reauthAdmin(reasonLabel = "高危操作") {
  const k = await promptDialog({
    title: `请重新验证：${reasonLabel}`,
    label: "Admin Key",
    placeholder: "二次确认避免误操作",
    type: "password",
    okText: "确认",
  });
  if (k === null) return false;
  const r = await verifyAdminKey(k);
  if (!r.ok) { toast(r.msg || "Admin Key 不正确", "err"); return false; }
  return true;
}

// 5.4 强密码 prompt：实时显示强度条
function promptStrongPassword(title) {
  return new Promise((resolve) => {
    const { close, root } = openModal({
      title,
      bodyHtml: `
        <div class="field">
          <label for="sp-pass">主密码（建议 12+ 字符，混合大小写/数字/符号）</label>
          <input id="sp-pass" class="input" type="password" placeholder="主密码" autocomplete="new-password" />
        </div>
        <div id="sp-meter" class="strength-meter"><span></span></div>
        <div id="sp-label" class="text-xs muted" style="margin-top:6px;">未输入</div>
        <ul id="sp-hints" class="text-xs hint" style="margin-top:6px;"></ul>
        <div class="field mt-2">
          <label for="sp-pass2">再次输入</label>
          <input id="sp-pass2" class="input" type="password" placeholder="重复确认" autocomplete="new-password" />
        </div>
      `,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">取消</button>
          <button class="btn" data-act="ok">保存</button>
        </div>
      `,
      onMount: (r, doClose) => {
        const p = r.querySelector("#sp-pass");
        const p2 = r.querySelector("#sp-pass2");
        const meter = r.querySelector("#sp-meter");
        const label = r.querySelector("#sp-label");
        const hints = r.querySelector("#sp-hints");
        function refresh() {
          const { score, label: lab, hints: list } = scorePassword(p.value);
          meter.dataset.score = String(score);
          label.textContent = `强度：${lab}`;
          hints.innerHTML = list.map(h => `<li>${escapeHtml(h)}</li>`).join("");
        }
        p.addEventListener("input", refresh);
        refresh();
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => { doClose(); resolve(null); });
        r.querySelector('[data-act="ok"]').addEventListener("click", async () => {
          const pw = p.value;
          if (!pw) { toast("请输入主密码", "warn"); return; }
          if (pw !== p2.value) { toast("两次输入不一致", "warn"); return; }
          const { score } = scorePassword(pw);
          if (score < 2) {
            const ok = await confirmDialog({
              title: "密码偏弱",
              message: "当前密码强度评分较低，建议至少 12 字符并包含大小写/数字/符号。仍要使用此密码？",
              danger: true,
              okText: "仍然使用",
            });
            if (!ok) return;
          }
          doClose();
          resolve(pw);
        });
        p.focus();
      },
    });
  });
}

let backdrop = null;
let drawer = null;
let onChangeCb = null; // notify outer to re-render home
let activePaneRenderToken = 0;
const SS_ADMIN_ENTRY_VISIBLE = "authenticator.v1.adminEntryVisible";

function loadAdminEntryVisible() {
  try { return sessionStorage.getItem(SS_ADMIN_ENTRY_VISIBLE) === "1"; }
  catch { return false; }
}

function saveAdminEntryVisible(v) {
  try {
    if (v) sessionStorage.setItem(SS_ADMIN_ENTRY_VISIBLE, "1");
    else sessionStorage.removeItem(SS_ADMIN_ENTRY_VISIBLE);
  } catch {}
}

export function initDrawer(onChange) {
  onChangeCb = onChange;

  backdrop = document.createElement("div");
  backdrop.className = "drawer-backdrop";

  drawer = document.createElement("aside");
  drawer.className = "drawer" + (isLocalOnlyApp() ? " local-app" : "");
  drawer.innerHTML = `
    <div class="drawer-head">
      <h2>设置</h2>
      <button class="close" aria-label="关闭">✕</button>
    </div>
    <nav class="drawer-tabs" role="tablist" aria-label="设置分区">
      <button class="tab project-tab active" id="drawer-tab-sync" role="tab" aria-selected="true" aria-controls="drawer-pane-sync" tabindex="0" data-tab="sync">项目</button>
      <button class="tab" id="drawer-tab-data" role="tab" aria-selected="false" aria-controls="drawer-pane-data" tabindex="-1" data-tab="data">数据</button>
      <button class="tab admin-only cloud-only" id="drawer-tab-share" role="tab" aria-selected="false" aria-controls="drawer-pane-share" tabindex="-1" data-tab="share">分享</button>
      <button class="tab admin-only cloud-only" id="drawer-tab-admin" role="tab" aria-selected="false" aria-controls="drawer-pane-admin" tabindex="-1" data-tab="admin">管理员</button>
      <button class="tab" id="drawer-tab-about" role="tab" aria-selected="false" aria-controls="drawer-pane-about" tabindex="-1" data-tab="about">关于</button>
    </nav>
    <div class="drawer-body">
      <div class="drawer-pane active" id="drawer-pane-sync" role="tabpanel" aria-labelledby="drawer-tab-sync" data-pane="sync"></div>
      <div class="drawer-pane" id="drawer-pane-data" role="tabpanel" aria-labelledby="drawer-tab-data" data-pane="data"></div>
      <div class="drawer-pane" id="drawer-pane-share" role="tabpanel" aria-labelledby="drawer-tab-share" data-pane="share"></div>
      <div class="drawer-pane" id="drawer-pane-admin" role="tabpanel" aria-labelledby="drawer-tab-admin" data-pane="admin"></div>
      <div class="drawer-pane" id="drawer-pane-about" role="tabpanel" aria-labelledby="drawer-tab-about" data-pane="about"></div>
    </div>
  `;

  document.body.appendChild(backdrop);
  document.body.appendChild(drawer);

  backdrop.addEventListener("click", closeDrawer);
  drawer.querySelector(".close").addEventListener("click", closeDrawer);

  drawer.querySelectorAll(".tab").forEach(t => {
    t.addEventListener("click", () => {
      setDrawerTab(t.dataset.tab);
      renderActivePane();
    });
    t.addEventListener("keydown", (e) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
      e.preventDefault();
      const tabs = Array.from(drawer.querySelectorAll('.tab'))
        .filter((el) => getComputedStyle(el).display !== "none");
      const current = tabs.indexOf(t);
      if (current === -1) return;
      let next = current;
      if (e.key === "Home") next = 0;
      else if (e.key === "End") next = tabs.length - 1;
      else if (e.key === "ArrowRight") next = (current + 1) % tabs.length;
      else if (e.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
      const target = tabs[next];
      if (!target) return;
      setDrawerTab(target.dataset.tab);
      renderActivePane();
      target.focus();
    });
  });

  // sync admin class with state
  syncAdminClass();
}

function syncAdminClass() {
  if (isLocalOnlyApp()) drawer.classList.add("local-app");
  else drawer.classList.remove("local-app");
  if (state.adminUnlocked) drawer.classList.add("admin");
  else drawer.classList.remove("admin");
}

export function openDrawer(initialTab = "sync") {
  // refresh admin flag from session
  state.adminUnlocked = loadAdminUnlocked();
  syncAdminClass();
  const adminOnlyTabs = new Set(["sync", "share", "admin"]);
  let tab = initialTab;
  if ((initialTab === "share" || initialTab === "admin") && !canUseCloudApis()) tab = "sync";
  else if (!isLocalOnlyApp() && !state.adminUnlocked && adminOnlyTabs.has(initialTab)) tab = "data";
  setDrawerTab(tab);

  backdrop.classList.add("show");
  drawer.classList.add("show");
  renderActivePane();
}

export function closeDrawer() {
  backdrop.classList.remove("show");
  drawer.classList.remove("show");
  // commit edits if any
  saveCurrentProjectItems();
  onChangeCb?.();
}

function activePaneName() {
  return drawer.querySelector(".tab.active")?.dataset.tab || (isLocalOnlyApp() || state.adminUnlocked ? "sync" : "data");
}

function setDrawerTab(tabName) {
  drawer.querySelectorAll(".tab").forEach((t) => {
    const active = t.dataset.tab === tabName;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", active ? "true" : "false");
    t.tabIndex = active ? 0 : -1;
  });
  drawer.querySelectorAll(".drawer-pane").forEach((p) => {
    const active = p.dataset.pane === tabName;
    p.classList.toggle("active", active);
    p.toggleAttribute("hidden", !active);
  });
}

function renderActivePane() {
  const renderToken = ++activePaneRenderToken;
  const name = activePaneName();
  const pane = drawer.querySelector(`[data-pane="${name}"]`);
  if (!pane) return;
  if (name === "sync") renderSyncPane(pane);
  else if (name === "data") renderDataPane(pane);
  else if (name === "share") renderSharePane(pane);
  else if (name === "admin") void renderAdminPane(pane, renderToken);
  else if (name === "about") renderAboutPane(pane);
}

// ===========================================================================
// SYNC pane (项目)
// ===========================================================================
function renderSyncPane(pane) {
  const localApp = isLocalOnlyApp();
  const projectEnabled = localApp || state.adminUnlocked;
  if (!projectEnabled) {
    pane.innerHTML = `
      <div class="empty-msg">
        项目与同步仅管理员可用。
      </div>
    `;
    return;
  }

  const dupMap = localApp ? new Map() : detectDuplicateSyncIds();
  const projects = listProjects();
  const cur = state.syncProjects.find(p => p.id === state.currentProjectId);
  const isAdmin = !!state.adminUnlocked;

  let html = `
    <div class="section">
      <h3>${localApp ? "本地项目" : "同步项目"}</h3>
      <div class="section-card">
        <div class="row between mb-2">
          <span class="text-sm muted">${projects.length ? `${projects.length} 个项目` : "尚未创建项目"}</span>
          <button class="btn sm" data-act="new-project">+ 新建项目</button>
        </div>
        <div class="list" id="proj-list"></div>
      </div>
    </div>

    ${cur ? `
    <div class="section">
      <h3>${localApp ? "当前项目" : "当前项目操作"}</h3>
      <div class="section-card col gap-2">
        <div class="row between">
          <div>
            <div class="text-sm" style="font-weight:600;">${escapeHtml(cur.name || "未命名")}</div>
            <div class="text-xs muted mono">${escapeHtml(localApp ? "仅本地保存" : (cur.syncId || "-"))}</div>
          </div>
          <span class="tag ${cur.lastSyncedAt ? "ok" : ""}">${localApp ? "本地项目" : (cur.lastSyncedAt ? "上次同步：" + new Date(cur.lastSyncedAt).toLocaleTimeString() : "未同步")}</span>
        </div>
        <div class="btn-row">
          ${localApp ? "" : '<button class="btn" data-act="push">⬆ 推送</button><button class="btn ghost" data-act="pull">⬇ 拉取</button>'}
          <button class="btn ghost" data-act="merge-all">合并所有</button>
        </div>
        ${localApp ? '<p class="hint">本地 APK 模式下，项目仅用于本机分类隔离，不连接任何远程服务。</p>' : `<label class="row gap-2">
          <input type="checkbox" id="auto-sync" ${cur.auto ? "checked" : ""}/>
          <span class="text-sm">启用自动同步（保存后自动推送，每 60s 自动拉取）</span>
        </label>`}
        <button class="btn ghost sm" data-act="edit-current">编辑当前项目</button>
      </div>
    </div>
    ` : ""}

    <div class="section">
      <details>
        <summary class="hint" style="cursor:pointer; user-select:none;">概念说明</summary>
        <div class="hint mt-2" style="line-height:1.7;">
          ${localApp
            ? '<p><strong>本地项目</strong>：每个项目的数据都只保存在当前手机里，用于分类、分库和汇总查看。</p><p><strong>全部汇总视图</strong>：本地虚拟视图，只汇总本机上已有项目的数据。</p>'
            : `<p><strong>Sync Secret</strong>：每个项目独立的端到端加密密钥，跨设备必须一致；忘记后无法恢复云端数据。</p>
          ${isAdmin ? '<p><strong>Admin Key</strong>：服务端配置的管理员主密钥。在严格模式下，没有 Admin Key 无法读写云端。</p>' : ""}
          <p><strong>全部汇总视图</strong>：本地虚拟视图，只显示你已创建的项目数据。不会自动拉取云端其他项目。</p>`}
        </div>
      </details>
    </div>
  `;

  pane.innerHTML = html;

  const list = pane.querySelector("#proj-list");
  if (!projects.length) {
    list.innerHTML = `<div class="empty-msg">${localApp ? '点击"新建项目"开始本地分组管理' : '点击"新建项目"开始多设备同步'}</div>`;
  } else {
    // 全部汇总
    const allLi = document.createElement("div");
    allLi.className = "list-item" + (state.currentProjectId === "_all_" ? " active" : "");
    allLi.innerHTML = `
      <div class="li-info">
        <div class="li-title">📊 全部项目（汇总视图）</div>
        <div class="li-sub">只读，显示所有项目的验证码</div>
      </div>
      <div class="li-actions">
        <button class="btn ghost sm" data-switch="_all_">切换</button>
      </div>`;
    list.appendChild(allLi);

    for (const p of projects) {
      const isCur = p.id === state.currentProjectId;
      const dup = !localApp && p.syncId && dupMap.get(p.syncId) > 1;
      const li = document.createElement("div");
      li.className = "list-item" + (isCur ? " active" : "");
      li.innerHTML = `
        <div class="li-info">
          <div class="li-title">${escapeHtml(p.name || "未命名")} ${dup ? '<span class="tag warn">ID 重复</span>' : ""}</div>
          <div class="li-sub">${escapeHtml(localApp ? "仅本地保存" : (p.syncId || "-"))}</div>
        </div>
        <div class="li-actions">
          ${isCur ? '<span class="tag ok">当前</span>' : `<button class="btn ghost sm" data-switch="${p.id}">切换</button>`}
          <button class="btn ghost sm" data-edit="${p.id}">✏️</button>
        </div>`;
      list.appendChild(li);
    }
  }

  // bindings
  pane.querySelector('[data-act="new-project"]')?.addEventListener("click", () => openProjectEditor(null, pane));
  pane.querySelectorAll("[data-edit]").forEach(b => b.addEventListener("click", () => openProjectEditor(b.dataset.edit, pane)));
  pane.querySelectorAll("[data-switch]").forEach(b => b.addEventListener("click", async () => {
    await switchToProject(b.dataset.switch);
    renderSyncPane(pane);
    onChangeCb?.();
  }));

  if (cur) {
    pane.querySelector('[data-act="push"]')?.addEventListener("click", async () => {
      try { await pushCurrent(); toast("已推送", "ok"); }
      catch (e) { toast(e.message, "err"); }
    });
    pane.querySelector('[data-act="pull"]')?.addEventListener("click", async () => {
      try { await pullCurrent(); toast("已同步", "ok"); onChangeCb?.(); }
      catch (e) {
        if (e.code === "empty") toast("云端暂无数据", "warn");
        else toast(e.message, "err");
      }
    });
    pane.querySelector('[data-act="merge-all"]').addEventListener("click", async () => {
      const ok = await confirmDialog({
        title: "合并所有项目",
        message: localApp
          ? "将本机所有已保存项目的条目合并到当前项目。继续？"
          : "将本地所有已保存项目的条目合并到当前项目，并推送到云端。继续？",
      });
      if (!ok) return;
      try {
        const stat = await mergeAllProjectsIntoCurrent();
        toast(`合并完成：${stat.before} → ${stat.after} 条`, "ok");
        if (!localApp) {
          try { await pushCurrent(); toast("已推送", "ok"); } catch {}
        }
        onChangeCb?.();
      } catch (e) { toast(e.message, "err"); }
    });
    pane.querySelector("#auto-sync")?.addEventListener("change", (e) => {
      cur.auto = e.target.checked;
      saveSyncProjects();
      if (cur.auto) startAutoSync(); else stopAutoSync();
      toast(cur.auto ? "已启用自动同步" : "已停用自动同步", "ok");
    });
    pane.querySelector('[data-act="edit-current"]').addEventListener("click", () => openProjectEditor(cur.id, pane));
  }
}

function openProjectEditor(projectId, parentPane) {
  const localApp = isLocalOnlyApp();
  if (!localApp && !state.adminUnlocked) {
    toast("项目与同步仅管理员可用", "warn");
    return;
  }
  const proj = projectId ? state.syncProjects.find(p => p.id === projectId) : null;
  const isNew = !proj;
  const { close, root } = openModal({
    title: isNew ? (localApp ? "新建本地项目" : "新建同步项目") : "编辑项目",
    bodyHtml: localApp ? `
      <div class="field">
        <label>项目名称</label>
        <input id="pe-name" class="input" placeholder="如：个人账号" value="${escapeHtml(proj?.name || "")}" />
      </div>
      <div class="hint mt-2">本地 APK 模式下，项目数据仅保存在当前设备，不需要 Sync ID、Secret 或 Admin Key。</div>
    ` : `
      <div class="field">
        <label>项目名称</label>
        <input id="pe-name" class="input" placeholder="如：个人账号" value="${escapeHtml(proj?.name || "")}" />
      </div>
      <div class="field mt-2">
        <label>Sync ID <span class="muted">（云端唯一标识，自定义）</span></label>
        <input id="pe-id" class="input mono" placeholder="my-personal-2fa" value="${escapeHtml(proj?.syncId || "")}" />
      </div>
      <div class="field mt-2">
        <label>Sync Secret <span class="muted">（端到端加密密钥，跨设备一致）</span></label>
        <div class="input-with-toggle">
          <input id="pe-secret" class="input" type="password" placeholder="设置一个强随机字符串" value="${escapeHtml(proj?.secret || "")}" />
          <button type="button" class="toggle" data-toggle>👁</button>
        </div>
      </div>
      <label class="row gap-2 mt-3">
        <input type="checkbox" id="pe-auto" ${proj?.auto ? "checked" : ""} />
        <span class="text-sm">启用自动同步</span>
      </label>
      <div class="field mt-2">
        <label for="pe-interval">自动拉取频率</label>
        <select id="pe-interval" class="input">
          <option value="30000" ${Number(proj?.autoInterval) === 30000 ? "selected" : ""}>30 秒</option>
          <option value="60000" ${(!proj?.autoInterval || Number(proj?.autoInterval) === 60000) ? "selected" : ""}>1 分钟（默认）</option>
          <option value="300000" ${Number(proj?.autoInterval) === 300000 ? "selected" : ""}>5 分钟</option>
          <option value="900000" ${Number(proj?.autoInterval) === 900000 ? "selected" : ""}>15 分钟</option>
          <option value="3600000" ${Number(proj?.autoInterval) === 3600000 ? "selected" : ""}>1 小时</option>
        </select>
      </div>
    `,
    footerHtml: `
      <div class="btn-row right">
        ${proj ? '<button class="btn danger" data-act="del">删除项目</button>' : ""}
        <button class="btn ghost" data-act="cancel">取消</button>
        <button class="btn" data-act="save">保存</button>
      </div>
    `,
    onMount: (r, doClose) => {
      r.querySelector("[data-toggle]")?.addEventListener("click", () => {
        const inp = r.querySelector("#pe-secret");
        inp.type = inp.type === "password" ? "text" : "password";
      });
      r.querySelector('[data-act="cancel"]').addEventListener("click", doClose);
      r.querySelector('[data-act="save"]').addEventListener("click", async () => {
        const name = r.querySelector("#pe-name").value.trim();
        if (!name) { toast("请填写项目名称", "warn"); return; }
        let saved;
        if (localApp) {
          if (proj) {
            saved = updateProject(projectId, { name });
          } else {
            saved = createProject({ name });
          }
        } else {
          const syncId = r.querySelector("#pe-id").value.trim();
          const secret = r.querySelector("#pe-secret").value;
          const auto = r.querySelector("#pe-auto").checked;
          const autoInterval = Number(r.querySelector("#pe-interval")?.value) || 60000;
          if (!syncId || !secret) { toast("请填写 Sync ID 和 Secret", "warn"); return; }
          const dup = state.syncProjects.find(p => p.id !== projectId && (p.syncId || "").trim() === syncId);
          if (dup) {
            const ok = await confirmDialog({
              title: "Sync ID 重复",
              message: `已有项目 "${dup.name || dup.id}" 使用相同的 Sync ID，继续保存将共用同一云端数据，可能互相覆盖。仍要继续？`,
              danger: true
            });
            if (!ok) return;
          }
          if (proj) {
            saved = updateProject(projectId, { name, syncId, secret, auto, autoInterval });
          } else {
            saved = createProject({ name, syncId, secret, auto, autoInterval });
          }
        }
        await switchToProject(saved.id);
        if (!localApp) {
          if (saved.auto) startAutoSync(); else stopAutoSync();
        }
        doClose();
        renderSyncPane(parentPane);
        onChangeCb?.();
        toast(proj ? "项目已更新" : "项目已创建", "ok");
      });
      r.querySelector('[data-act="del"]')?.addEventListener("click", async () => {
        const ok = await confirmDialog({
          title: "删除项目？",
          message: localApp
            ? "本地项目数据会从当前设备删除。"
            : "本地项目数据会被删除（云端密文不会自动删除，请在管理员面板手动清理）。",
          danger: true,
          okText: "删除"
        });
        if (!ok) return;
        deleteProject(projectId);
        doClose();
        renderSyncPane(parentPane);
        onChangeCb?.();
        toast("项目已删除", "ok");
      });
    }
  });
}

// ===========================================================================
// DATA pane (数据)
// ===========================================================================
function renderDataPane(pane) {
  const hasMaster = !!localStorage.getItem("authenticator.v1.meta");
  const isLocked = !state.unlocked;
  const hasPasskey = hasPasskeyUnlock();
  const passkeyInfo = getPasskeySlotInfo();
  const cloudCfg = isAndroidApp() ? getCloudBaseUrls() : null;

  pane.innerHTML = `
    ${cloudCfg ? `
    <div class="section">
      <h3>云端地址</h3>
      <div class="section-card col gap-2">
        <div class="field">
          <label for="cloud-api-url">云端 API 地址</label>
          <input id="cloud-api-url" class="input mono" inputmode="url" placeholder="https://your-app.pages.dev" value="${escapeHtml(cloudCfg.apiBaseUrl || "")}" />
        </div>
        <div class="field">
          <label for="cloud-public-url">公开站点地址 <span class="muted">（分享链接用，可留空）</span></label>
          <input id="cloud-public-url" class="input mono" inputmode="url" placeholder="默认同云端 API 地址" value="${escapeHtml(cloudCfg.publicBaseUrl || "")}" />
        </div>
        <div class="row between">
          <span class="tag ${cloudCfg.apiBaseUrl ? "ok" : "warn"}">${cloudCfg.apiBaseUrl ? "已配置" : "未配置"}</span>
          <div class="btn-row">
            <button class="btn ghost sm" data-act="cloud-clear">清空</button>
            <button class="btn sm" data-act="cloud-save">保存</button>
          </div>
        </div>
        <p class="hint">只影响同步版 APK。保存后，推送、拉取、分享和管理员接口会使用这个地址；纯本地 APK 不会连接云端。</p>
      </div>
    </div>
    ` : ""}

    <div class="section">
      <h3>导入 / 导出</h3>
      <div class="section-card col gap-2">
        <p class="hint">导出当前${state.syncProjects?.length ? "项目" : "本地账户库"}的全部账户为 JSON 文件（可选用密码加密），或导出为 Google Authenticator 迁移二维码。</p>
        <div class="btn-row">
          <button class="btn ghost" data-act="export">📤 导出</button>
          <button class="btn ghost" data-act="export-qr">🔳 批量二维码</button>
          <button class="btn ghost" data-act="import">📥 导入</button>
        </div>
      </div>
    </div>

    <div class="section">
      <h3>主密码（本地加密）</h3>
      <div class="section-card col gap-2">
        <div class="row between">
          <span class="text-sm">本地数据状态</span>
          <span class="tag ${isLocked ? "warn" : (hasMaster ? "ok" : "")}">${isLocked ? "已加密未解锁" : (hasMaster ? "已加密" : "未加密")}</span>
        </div>
        <p class="hint">设置后，本地存储将使用 AES-GCM + PBKDF2 加密。<strong>忘记主密码可用恢复码（如已生成）找回。</strong></p>
        <div class="btn-row">
          ${isLocked
            ? `<button class="btn" data-act="unlock">🔓 输入密码解锁</button>
               ${hasPasskey ? '<button class="btn ghost" data-act="unlock-passkey">🪪 用 Passkey 解锁</button>' : ""}
               ${hasRecoveryCode() ? '<button class="btn ghost" data-act="unlock-recovery">用恢复码解锁</button>' : ""}`
            : `<button class="btn" data-act="set-master">${hasMaster ? "🔁 更改主密码" : "🔐 设置主密码"}</button>
               ${hasMaster ? `<button class="btn ghost" data-act="setup-passkey">${hasPasskey ? "重置 Passkey" : "启用 Passkey"}</button>` : ""}
               ${hasPasskey ? '<button class="btn ghost danger" data-act="clear-passkey">移除 Passkey</button>' : ""}
               ${hasMaster ? '<button class="btn ghost" data-act="gen-recovery">' + (hasRecoveryCode() ? "重置恢复码" : "生成恢复码") + '</button>' : ""}
               ${hasMaster ? '<button class="btn ghost danger" data-act="clear-master">移除加密</button>' : ""}`}
        </div>
        <div class="row between">
          <span class="text-sm">Passkey 快捷解锁</span>
          <span class="tag ${hasPasskey ? "ok" : ""}" id="passkey-status-tag">${hasPasskey ? "已启用" : "检测中"}</span>
        </div>
        <p class="hint" id="passkey-status-text">${hasPasskey
          ? `已绑定 Passkey${passkeyInfo?.label ? `：${escapeHtml(passkeyInfo.label)}` : ""}。后续可用生物识别或设备 PIN 快捷解锁。`
          : "可选：启用 Passkey 后，下次可不输入主密码直接解锁当前浏览器上的本地加密数据。需要 HTTPS 和支持 WebAuthn PRF 的浏览器/认证器。"}</p>
        ${(!isLocked && hasMaster && hasRecoveryCode()) ? '<div class="text-xs muted">恢复码已生成。改主密码会使旧恢复码失效。</div>' : ""}
      </div>
    </div>

    <div class="section">
      <h3>清理</h3>
      <div class="section-card col gap-2">
        <p class="hint">彻底删除已标记为"删除"的条目（tombstone）。仅当你确认其他设备已经同步到删除状态后再执行，否则旧设备可能把已删账户带回来。</p>
        <button class="btn ghost" data-act="clean">🧹 清理已删除条目</button>
      </div>
    </div>

    <div class="section">
      <h3>自动锁定</h3>
      <div class="section-card col gap-2">
        <p class="hint">闲置或离开页面过久时，自动重锁管理员模式与本地主密码加密。0 = 禁用。</p>
        <div class="row gap-2">
          <div class="field grow">
            <label for="idle-min">闲置（分钟）</label>
            <input id="idle-min" class="input" type="number" min="0" max="1440" step="1" value="${getIdleMinutes()}" />
          </div>
          <div class="field grow">
            <label for="hidden-min">离开页面（分钟）</label>
            <input id="hidden-min" class="input" type="number" min="0" max="1440" step="1" value="${getHiddenMinutes()}" />
          </div>
        </div>
      </div>
    </div>

    <div class="section">
      <h3>显示</h3>
      <div class="section-card col gap-2">
        <div class="field">
          <label>主题</label>
          <div class="row gap-3" role="radiogroup" aria-label="主题">
            <label class="row gap-1"><input type="radio" name="theme" value="dark" ${getThemePreference() === "dark" ? "checked" : ""} /> <span class="text-sm">暗色</span></label>
            <label class="row gap-1"><input type="radio" name="theme" value="light" ${getThemePreference() === "light" ? "checked" : ""} /> <span class="text-sm">亮色</span></label>
            <label class="row gap-1"><input type="radio" name="theme" value="auto" ${getThemePreference() === "auto" ? "checked" : ""} /> <span class="text-sm">跟随系统</span></label>
          </div>
        </div>
        <div class="row gap-3">
          <label class="row gap-1"><input type="radio" name="density" value="comfortable" ${getDensity() === "comfortable" ? "checked" : ""} /> <span class="text-sm">舒适</span></label>
          <label class="row gap-1"><input type="radio" name="density" value="compact" ${getDensity() === "compact" ? "checked" : ""} /> <span class="text-sm">紧凑</span></label>
        </div>
      </div>
    </div>
  `;

  pane.querySelector('[data-act="export"]').addEventListener("click", async () => {
    const { exportCurrent } = await loadImportExportModule();
    await exportCurrent();
  });
  pane.querySelector('[data-act="export-qr"]').addEventListener("click", async () => {
    const { exportCurrentMigrationQrs } = await loadImportExportModule();
    await exportCurrentMigrationQrs();
  });
  pane.querySelector('[data-act="import"]').addEventListener("click", async () => {
    const { importFromFile } = await loadImportExportModule();
    const ok = await importFromFile();
    if (ok) { renderActivePane(); onChangeCb?.(); }
  });

  pane.querySelector('[data-act="cloud-save"]')?.addEventListener("click", async () => {
    const apiBaseUrl = pane.querySelector("#cloud-api-url")?.value || "";
    const publicBaseUrl = pane.querySelector("#cloud-public-url")?.value || "";
    try {
      const saved = setCloudBaseUrls({ apiBaseUrl, publicBaseUrl });
      stopAutoSync();
      syncAdminClass();
      toast(saved.apiBaseUrl ? "云端地址已保存" : "云端地址已清空", "ok");
      renderDataPane(pane);
      onChangeCb?.();
    } catch (e) {
      toast(e.message || "保存失败", "err");
    }
  });

  pane.querySelector('[data-act="cloud-clear"]')?.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "清空云端地址？",
      message: "清空后，同步版 APK 会停止访问云端，直到重新填写地址。",
      danger: true,
      okText: "清空",
    });
    if (!ok) return;
    clearCloudBaseUrls();
    stopAutoSync();
    syncAdminClass();
    toast("云端地址已清空", "ok");
    renderDataPane(pane);
    onChangeCb?.();
  });

  pane.querySelector('[data-act="set-master"]')?.addEventListener("click", async () => {
    const pwd = await promptStrongPassword(hasMaster ? "更改主密码" : "设置主密码");
    if (!pwd) return;
    await setMasterPassword(pwd);
    toast("主密码已设置并加密", "ok");
    renderDataPane(pane);
  });

  pane.querySelector('[data-act="clear-master"]')?.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "移除加密？",
      message: "本地数据将以明文形式保存，确定要移除主密码加密？",
      danger: true,
    });
    if (!ok) return;
    await clearMasterPassword();
    toast("已移除加密", "ok");
    renderDataPane(pane);
  });

  pane.querySelector('[data-act="unlock"]')?.addEventListener("click", async () => {
    const blockMs = getUnlockBlockMs();
    if (blockMs > 0) {
      toast(`请等待 ${Math.ceil(blockMs / 1000)} 秒后再尝试`, "warn", 2400);
      return;
    }
    const pwd = await promptDialog({
      title: "解锁数据",
      label: "请输入主密码",
      type: "password",
      okText: "解锁"
    });
    if (!pwd) return;
    const ok = await tryUnlock(pwd);
    if (ok) { clearUnlockFails(); toast("已解锁", "ok"); renderDataPane(pane); onChangeCb?.(); }
    else {
      const wait = recordUnlockFail();
      if (wait > 0) toast(`密码错误，已限速 ${wait} 秒`, "err", 2400);
      else toast("密码错误或数据损坏", "err");
    }
  });

  pane.querySelector('[data-act="unlock-passkey"]')?.addEventListener("click", async () => {
    const result = await unlockWithPasskey();
    if (result.ok) {
      clearUnlockFails();
      toast("已通过 Passkey 解锁", "ok");
      renderDataPane(pane);
      onChangeCb?.();
      return;
    }
    if (!result.canceled) toast(result.msg || "Passkey 解锁失败", "err");
  });

  // 5.7 恢复码相关
  pane.querySelector('[data-act="unlock-recovery"]')?.addEventListener("click", async () => {
    const code = await promptDialog({
      title: "用恢复码解锁",
      label: "请输入恢复码（不区分大小写，可含 - 与空格）",
      placeholder: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX",
      multiline: true,
      okText: "解锁",
    });
    if (!code) return;
    const ok = await unlockWithRecoveryCode(code);
    if (!ok) { toast("恢复码无效", "err"); return; }
    toast("恢复码解锁成功，请立即设置新主密码", "ok", 3200);
    // 解锁后强制设置新主密码
    const pwd = await promptStrongPassword("设置新主密码（恢复码解锁后必须重新设置）");
    if (pwd) {
      await setMasterPassword(pwd);
      toast("新主密码已设置；旧恢复码已失效，建议重新生成", "ok", 3200);
    } else {
      toast("已解锁但未重置主密码，请尽快设置", "warn", 3200);
    }
    renderDataPane(pane);
    onChangeCb?.();
  });

  pane.querySelector('[data-act="gen-recovery"]')?.addEventListener("click", async () => {
    if (hasRecoveryCode()) {
      const ok = await confirmDialog({
        title: "重置恢复码？",
        message: "旧恢复码将立即失效，仅最新一份恢复码可用。继续？",
        danger: true,
        okText: "重置",
      });
      if (!ok) return;
    }
    let code;
    try { code = await generateRecoveryCode(); }
    catch (e) { toast(e.message || "生成失败", "err"); return; }
    showRecoveryCodeDialog(code, () => renderDataPane(pane));
  });

  pane.querySelector('[data-act="setup-passkey"]')?.addEventListener("click", async () => {
    if (hasPasskey) {
      const ok = await confirmDialog({
        title: "重置 Passkey？",
        message: "旧 Passkey 快捷解锁将失效，仅最新绑定的一把 Passkey 可继续使用。继续？",
        danger: true,
        okText: "重置",
      });
      if (!ok) return;
    }
    try {
      await setupPasskeyUnlock(passkeyInfo?.label || "当前设备 Passkey");
      toast("Passkey 已启用，可用于后续快捷解锁", "ok", 2800);
      renderDataPane(pane);
    } catch (e) {
      if (e?.name === "NotAllowedError" || e?.name === "AbortError") return;
      toast(e.message || "启用 Passkey 失败", "err", 3200);
    }
  });

  pane.querySelector('[data-act="clear-passkey"]')?.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "移除 Passkey？",
      message: "移除后将不能再用生物识别或设备 PIN 快捷解锁，只能使用主密码或恢复码。",
      danger: true,
      okText: "移除",
    });
    if (!ok) return;
    clearPasskeyUnlock();
    toast("已移除 Passkey 快捷解锁", "ok");
    renderDataPane(pane);
  });

  pane.querySelector('[data-act="clean"]')?.addEventListener("click", async () => {
    const ok = await confirmDialog({
      title: "确认清理已删除条目？",
      message: "这会彻底移除本地 tombstone。尚未同步的其他设备之后可能无法得知这些账户已被删除，并可能把旧数据重新带回来。建议先确认其他设备已同步，清理后再尽快推送一次。",
      danger: true,
      okText: "确认清理",
    });
    if (!ok) return;
    const removed = await cleanDeleted();
    if (removed > 0) {
      scheduleAutoPush();
      toast(`已清理 ${removed} 条；请尽快同步到其他设备`, "warn", 3200);
      onChangeCb?.();
    }
    else toast("没有可清理的条目", "warn");
  });

  // 自动锁定输入
  pane.querySelector("#idle-min")?.addEventListener("change", (e) => {
    const v = Math.max(0, Math.min(1440, Number(e.target.value) || 0));
    setIdleMinutes(v);
    e.target.value = String(v);
    toast(v > 0 ? `闲置 ${v} 分钟自动锁定` : "已停用闲置锁定", "ok");
  });
  pane.querySelector("#hidden-min")?.addEventListener("change", (e) => {
    const v = Math.max(0, Math.min(1440, Number(e.target.value) || 0));
    setHiddenMinutes(v);
    e.target.value = String(v);
    toast(v > 0 ? `离开 ${v} 分钟自动锁定` : "已停用离开锁定", "ok");
  });

  pane.querySelectorAll('input[name="density"]').forEach(r => r.addEventListener("change", (e) => {
    setDensity(e.target.value);
    toast(e.target.value === "compact" ? "已切换为紧凑模式" : "已切换为舒适模式", "ok");
  }));
  pane.querySelectorAll('input[name="theme"]').forEach(r => r.addEventListener("change", (e) => {
    setThemePreference(e.target.value);
    const label = e.target.value === "auto" ? "已跟随系统主题" : (e.target.value === "light" ? "已切换为亮色主题" : "已切换为暗色主题");
    toast(label, "ok");
  }));

  void refreshPasskeySupportState(pane, { hasMaster, hasPasskey });
}

async function refreshPasskeySupportState(pane, { hasMaster, hasPasskey }) {
  const tag = pane.querySelector("#passkey-status-tag");
  const text = pane.querySelector("#passkey-status-text");
  const setupBtn = pane.querySelector('[data-act="setup-passkey"]');
  const unlockBtn = pane.querySelector('[data-act="unlock-passkey"]');
  if (!tag || !text) return;

  const support = await getPasskeySupport();
  if (!support.supported) {
    if (!hasPasskey) tag.textContent = "不可用";
    tag.classList.remove("ok");
    tag.classList.add("warn");
    text.textContent = support.reason || "当前环境不支持 Passkey 快捷解锁。";
    if (setupBtn) setupBtn.disabled = true;
    if (!hasPasskey && unlockBtn) unlockBtn.disabled = true;
    return;
  }

  if (hasPasskey) {
    tag.textContent = "已启用";
    tag.classList.add("ok");
    tag.classList.remove("warn");
    return;
  }

  if (!hasMaster) {
    tag.textContent = "待启用";
    tag.classList.remove("ok", "warn");
    text.textContent = "请先设置主密码并完成本地加密，再把 Passkey 作为额外快捷解锁方式启用。";
    if (setupBtn) setupBtn.disabled = true;
    return;
  }

  tag.textContent = "可启用";
  tag.classList.remove("warn");
  tag.classList.add("ok");
}

// ===========================================================================
// SHARE pane (分享)
// ===========================================================================
async function renderSharePane(pane) {
  if (!canUseCloudApis()) {
    pane.innerHTML = `
      <div class="empty-msg">
        本地 APK 版未启用云分享。
      </div>
    `;
    return;
  }
  const isAdmin = !!state.adminUnlocked;
  if (!isAdmin) {
    pane.innerHTML = `
      <div class="empty-msg">
        分享功能仅管理员可用。
      </div>
    `;
    return;
  }
  pane.innerHTML = `
    <div class="section">
      <h3>全部分享记录</h3>
      <div class="section-card col gap-2">
        <p class="hint">这里显示所有管理员设备可见的分享记录。复制可直接得到完整分享链接，撤销会删除云端记录。</p>
        <div class="btn-row">
          <button class="btn ghost sm" data-act="cloud-load">🔄 加载/刷新分享记录</button>
        </div>
        <div class="list" id="cloud-shares"><div class="empty-msg">尚未加载</div></div>
      </div>
    </div>
  `;

  pane.querySelector('[data-act="cloud-load"]')?.addEventListener("click", async () => {
    const cl = pane.querySelector("#cloud-shares");
    cl.innerHTML = '<div class="empty-msg">加载中…</div>';
    try {
      const { fetchCloudShareRecords, revokeShare } = await loadShareModule();
      const records = await fetchCloudShareRecords();
      cl.innerHTML = "";
      if (!records.length) { cl.innerHTML = `<div class="empty-msg">云端暂无分享</div>`; return; }
      for (const rec of records) {
        const li = document.createElement("div");
        li.className = "list-item";
        const label = rec.label || "分享";
        const accessBits = [];
        accessBits.push(`访问 ${Math.max(0, Number(rec.accessCount || 0))} 次`);
        accessBits.push(rec.lastAccessAt ? `最近 ${new Date(rec.lastAccessAt).toLocaleString()}` : "尚未访问");
        const metaParts = [
          `SID: ${rec.sid}`,
          rec.projectName ? rec.projectName : "",
          rec.createdAt ? new Date(rec.createdAt).toLocaleString() : "",
          rec.requiresPassword ? "口令保护" : "",
        ].filter(Boolean);
        li.innerHTML = `
          <div class="li-info">
            <div class="li-title">${escapeHtml(label)}</div>
            <div class="li-sub">${escapeHtml(metaParts.join(" · "))}</div>
            <div class="li-sub">${escapeHtml(accessBits.join(" · "))}</div>
            ${rec.accessUserAgentSample ? `<div class="li-sub">${escapeHtml(rec.accessUserAgentSample)}</div>` : ""}
          </div>
          <div class="li-actions">
            <button class="btn ghost sm" data-copy>📋</button>
            <button class="btn ghost sm" data-revoke>撤销</button>
          </div>`;
        cl.appendChild(li);
        li.querySelector("[data-copy]").addEventListener("click", async () => {
          if (rec.requiresPassword && rec.protectedBundle?.wk && rec.protectedBundle?.iv && rec.protectedBundle?.s) {
            const frag = new URLSearchParams();
            frag.set("wk", rec.protectedBundle.wk);
            frag.set("iv", rec.protectedBundle.iv);
            frag.set("s", rec.protectedBundle.s);
            if (rec.protectedBundle.iter) frag.set("iter", String(rec.protectedBundle.iter));
            const ok = await copyText(`${location.origin}/shared.html?sid=${encodeURIComponent(rec.sid)}#${frag.toString()}`);
            toast(ok ? "已复制受保护链接" : "复制失败", ok ? "ok" : "err");
          } else if (rec.requiresPassword) {
            const ok = await copyText(rec.sid);
            toast(ok ? "未保存受保护片段，已复制 SID" : "复制失败", ok ? "warn" : "err");
          } else if (rec.k) {
            const ok = await copyText(`${location.origin}/shared.html?sid=${encodeURIComponent(rec.sid)}#k=${rec.k}`);
            toast(ok ? "已复制链接" : "复制失败", ok ? "ok" : "err");
          } else {
            const ok = await copyText(rec.sid);
            toast(ok ? "未保存密钥，已复制 SID" : "复制失败", ok ? "warn" : "err");
          }
        });
        li.querySelector("[data-revoke]").addEventListener("click", async () => {
          try { await revokeShare(rec.sid); toast("已撤销", "ok"); li.remove(); }
          catch (e) { toast(`撤销失败：${e.message}`, "err"); }
        });
      }
    } catch (e) {
      cl.innerHTML = `<div class="empty-msg">加载失败：${escapeHtml(e.message)}</div>`;
    }
  });
}

// ===========================================================================
// ABOUT pane (关于)
// ===========================================================================
function renderAboutPane(pane) {
  const localApp = isLocalOnlyApp();
  const isAdmin = !!state.adminUnlocked;
  const adminEntryVisible = !localApp && (isAdmin || loadAdminEntryVisible());
  pane.innerHTML = `
    <div class="section">
      <h3>关于</h3>
      <div class="section-card col gap-2">
        <div class="row between"><span class="text-sm">版本</span><span class="tag" data-act="about-version">v${APP_VERSION}</span></div>
        <div class="row between"><span class="text-sm">数据存储</span><span class="text-sm muted">${localApp ? "localStorage · 本地 APK" : "localStorage + Cloudflare KV"}</span></div>
      </div>
    </div>

    ${adminEntryVisible ? `
    <div class="section">
      <h3>管理员模式</h3>
      <div class="section-card col gap-2">
        <p class="hint">输入服务端配置的 Admin Key 后可访问云端浏览、密钥托管、批量迁移等高级功能。</p>
        ${isAdmin
          ? `<div class="row between">
              <span class="tag ok">✓ 已解锁</span>
              <button class="btn ghost sm" data-act="logout-admin">退出管理员</button>
            </div>`
          : `<button class="btn" data-act="login-admin">🔑 输入 Admin Key 登录</button>`}
      </div>
    </div>
    ` : ""}

    <div class="section">
      <details>
        <summary class="hint" style="cursor:pointer; user-select:none;">访客模式 / 数据隐私说明</summary>
        <div class="hint mt-2" style="line-height:1.7;">
          ${localApp
            ? '<p>本地 APK 版不会连接远程云端。全部账户和项目都只保存在当前手机本地。</p><p>"全部汇总视图"只汇总本机已有项目，不会访问任何远程服务。</p>'
            : '<p>未启用同步项目时，全部数据只存储在浏览器 localStorage 中，离线可用，不会上传任何信息。</p><p>启用同步后，本地用 Sync Secret 端到端加密，云端只保存密文。</p><p>"全部汇总视图"是本地虚拟视图，不会访问其他用户的云端数据。</p>'}
        </div>
      </details>
    </div>
  `;

  if (!localApp) bindAdminEntryReveal(pane, adminEntryVisible);

  pane.querySelector('[data-act="login-admin"]')?.addEventListener("click", async () => {
    const key = await promptDialog({
      title: "管理员登录",
      label: "Admin Key",
      placeholder: "服务端 ADMIN_KEY 环境变量",
      type: "password",
      okText: "解锁"
    });
    if (!key) return;
    const r = await verifyAdminKey(key);
    if (r.ok) {
      unlockAdmin(key);
      syncAdminClass();
      toast("管理员模式已启用", "ok");
      onChangeCb?.();
      renderAboutPane(pane);
    } else {
      toast(r.msg || "验证失败", "err");
    }
  });

  pane.querySelector('[data-act="logout-admin"]')?.addEventListener("click", async () => {
    const ok = await confirmDialog({ title: "退出管理员", message: "退出后将无法访问高级功能。", okText: "退出" });
    if (!ok) return;
    lockAdmin();
    saveAdminEntryVisible(false);
    syncAdminClass();
    onChangeCb?.();
    renderAboutPane(pane);
    toast("已退出管理员", "ok");
  });
}

function bindAdminEntryReveal(pane, alreadyVisible) {
  const versionTag = pane.querySelector('[data-act="about-version"]');
  if (!versionTag || alreadyVisible) return;

  let taps = 0;
  let timer = null;
  versionTag.addEventListener("click", () => {
    taps++;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { taps = 0; timer = null; }, 1200);
    if (taps < 7) return;
    taps = 0;
    timer = null;
    saveAdminEntryVisible(true);
    toast("高级入口已显示", "ok");
    renderAboutPane(pane);
  });
}

// ===========================================================================
// ADMIN pane (L3)
// ===========================================================================
async function renderAdminPane(pane, renderToken) {
  if (!canUseCloudApis()) {
    pane.innerHTML = `
      <div class="empty-msg">
        本地 APK 版未启用云端管理功能。
      </div>
    `;
    return;
  }
  if (!state.adminUnlocked) {
    pane.innerHTML = `
      <div class="empty-msg">
        管理员模式未解锁。
      </div>
    `;
    return;
  }

  pane.innerHTML = `<div class="empty-msg">加载管理员模块…</div>`;

  const { getVaultEnabled, getVaultPubkey } = await loadVaultModule();
  if (renderToken !== activePaneRenderToken || activePaneName() !== "admin") return;

  const vaultEnabled = getVaultEnabled();
  const vaultPub = getVaultPubkey();

  pane.innerHTML = `
    <div class="section">
      <h3>站点访问密码</h3>
      <div class="section-card col gap-2">
        <p class="hint">访问口令内容固定来自 Cloudflare Pages 环境变量 <code>ACCESS_GATE</code>。这里仅控制是否启用该功能，保存结果会写入 Cloudflare KV。</p>
        <div class="row between">
          <span class="text-sm">当前状态</span>
          <span class="tag" id="site-gate-status">读取中</span>
        </div>
        <div id="site-gate-source" class="text-xs muted">正在读取当前配置…</div>
        <div id="site-gate-env" class="text-xs muted">正在检查环境变量…</div>
        <label class="row gap-2">
          <input type="checkbox" id="site-gate-enabled" />
          <span class="text-sm">启用访问口令</span>
        </label>
        <div class="btn-row">
          <button class="btn ghost sm" data-act="gate-refresh">刷新状态</button>
          <button class="btn sm" data-act="gate-save">保存访问设置</button>
        </div>
        <div class="text-xs muted">关闭后会立即移除当前浏览器的访问门 cookie。启用后当前浏览器会自动保留已授权状态。</div>
      </div>
    </div>

    <div class="section">
      <h3>云端浏览</h3>
      <div class="section-card col gap-2">
        <p class="hint">列出 KV 中所有 sync:* 项目，可解密查看 / 导出 / 批量管理。</p>
        <div class="btn-row">
          <button class="btn" data-act="cloud-load">🔄 加载所有云端项目</button>
        </div>
        <div id="cloud-list"></div>
      </div>
    </div>

    <div class="section">
      <h3>批量查看 / 导出</h3>
      <div class="section-card col gap-2">
        <div class="hint" style="line-height:1.7;">
          <p style="margin:0 0 6px;"><strong>用途</strong>：用一个或多个“同步密钥（Sync Secret）”尝试解开云端项目，先预览，再导出。</p>
          <p style="margin:0;">步骤：1. 先在上方加载云端项目并勾选目标项目 2. 在这里填写同步密钥 3. 点击“开始解密预览” 4. 确认内容后再导出</p>
        </div>
        <div class="field">
          <label>同步密钥（Sync Secret）<span class="muted">（可填多个，用换行或逗号分隔）</span></label>
          <textarea id="bulk-secrets" class="input" placeholder="例如：&#10;my-secret-a&#10;my-secret-b"></textarea>
        </div>
        <div class="btn-row">
          <button class="btn" data-act="bulk-preview">开始解密预览</button>
          <button class="btn ghost" data-act="bulk-clear">清空预览</button>
        </div>
        <div id="bulk-result"></div>

        <div class="divider"></div>
        <div class="hint" style="line-height:1.7;">
          <p style="margin:0 0 6px;"><strong>导出说明</strong>：只有成功解密并出现在预览里的内容才会导出。</p>
          <p style="margin:0;"><code>otpauth</code> 适合导入其他验证器，<code>JSON</code> 适合程序处理，<code>CSV</code> 适合表格查看。</p>
        </div>
        <div class="row gap-2 between">
          <select id="bulk-fmt" class="input" style="max-width:200px;">
            <option value="otpauth">导出为 otpauth 文本</option>
            <option value="json">导出为 JSON 文件</option>
            <option value="csv">导出为 CSV 表格</option>
          </select>
          <button class="btn ghost" data-act="bulk-export">⬇ 导出预览结果</button>
        </div>
        <div class="row gap-3">
          <label class="row gap-1"><input type="checkbox" id="bulk-split"/> <span class="text-xs">按项目分别导出</span></label>
          <label class="row gap-1"><input type="checkbox" id="bulk-selected"/> <span class="text-xs">只导出当前勾选的项目</span></label>
        </div>
      </div>
    </div>

    <div class="section">
      <h3>云端回收站</h3>
      <div class="section-card col gap-2">
        <p class="hint">软删除的同步项目会保留 7 天。备份保留最近 5 份共 30 天。</p>
        <div class="btn-row">
          <button class="btn ghost sm" data-act="trash-load">🗑 列出回收站</button>
        </div>
        <div id="trash-list"></div>
      </div>
    </div>

    <div class="section">
      <h3>审计日志</h3>
      <div class="section-card col gap-2">
        <p class="hint">记录最近 30 天的写操作，包含方法、路径、状态码、IP 摘要和 User-Agent 摘要。</p>
        <div class="btn-row">
          <button class="btn ghost sm" data-act="audit-load">🧾 加载最近日志</button>
        </div>
        <div id="audit-list"></div>
      </div>
    </div>

    <div class="section">
      <h3>密钥托管 (Vault)</h3>
      <div class="section-card col gap-2">
        <p class="hint">用 RSA 公钥加密 Sync Secret 后存放在云端，丢失本地数据时可用 RSA 私钥找回。</p>
        <label class="row gap-2"><input type="checkbox" id="vault-on" ${vaultEnabled ? "checked" : ""} /> <span class="text-sm">启用密钥托管功能</span></label>
        <div class="field">
          <label>RSA 公钥 (PEM / SPKI / Base64 DER)</label>
          <textarea id="vault-pub" class="input mono" placeholder="-----BEGIN PUBLIC KEY-----&#10;...">${escapeHtml(vaultPub)}</textarea>
          <div id="vault-fp" class="text-xs muted mono" style="margin-top:4px;"></div>
        </div>
        <div class="btn-row">
          <button class="btn ghost sm" data-act="vault-escrow">托管选中项目密钥</button>
          <button class="btn ghost sm" data-act="vault-recover">用私钥找回密钥</button>
          <button class="btn ghost sm" data-act="vault-migrate">批量密钥迁移</button>
        </div>
      </div>
    </div>
  `;

  bindAdminPane(pane);
}

function bindAdminPane(pane) {
  let cloudProjects = [];
  let aggregated = [];
  const selected = state.cloudSelectedProjects = state.cloudSelectedProjects || new Set();
  let gateState = null;

  const cloudList = pane.querySelector("#cloud-list");
  const gateStatus = pane.querySelector("#site-gate-status");
  const gateSource = pane.querySelector("#site-gate-source");
  const gateEnv = pane.querySelector("#site-gate-env");
  const gateEnabled = pane.querySelector("#site-gate-enabled");

  function syncGateInputs() {
    if (!gateEnabled) return;
    const locked = gateState?.editable === false;
    const cannotEnable = !gateState?.passwordConfigured;
    gateEnabled.disabled = locked;
    pane.querySelector('[data-act="gate-refresh"]')?.toggleAttribute("disabled", locked);
    pane.querySelector('[data-act="gate-save"]')?.toggleAttribute("disabled", locked || (cannotEnable && gateEnabled.checked));
  }

  function renderGateState(info) {
    gateState = info;
    if (!gateStatus || !gateSource || !gateEnv || !gateEnabled) return;
    gateEnabled.checked = !!info?.enabled;
    gateStatus.className = `tag ${info?.enabled ? "ok" : ""}`;
    gateStatus.textContent = info?.enabled ? "已启用" : "未启用";

    const parts = [];
    if (info?.source === "kv") {
      parts.push(info.enabled ? "当前由站内开关启用" : "当前由站内开关关闭");
    } else if (info?.source === "env") {
      parts.push("当前沿用环境变量的默认启用状态");
    } else {
      parts.push("当前没有启用访问口令");
    }
    if (info?.updatedAt) parts.push(`最近修改：${new Date(info.updatedAt).toLocaleString()}`);
    if (info?.editable === false) parts.push("服务端未绑定 AUTH_KV，无法站内修改");
    gateSource.textContent = parts.join(" · ");
    gateEnv.textContent = info?.passwordConfigured
      ? "Pages 环境变量 ACCESS_GATE：已配置"
      : "Pages 环境变量 ACCESS_GATE：未配置，当前无法启用访问口令";
    syncGateInputs();
  }

  async function loadGateState() {
    if (!gateStatus || !gateSource) return;
    gateStatus.className = "tag";
    gateStatus.textContent = "读取中";
    gateSource.textContent = "正在读取当前配置…";
    try {
      const res = await fetch(apiUrl("/api/admin/access-gate"), {
        headers: {
          "X-Token": state.globalToken,
          "X-KV-Admin-Key": state.globalToken,
          "Cache-Control": "no-store",
        }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data?.success === false) throw new Error(data.error || "读取失败");
      renderGateState(data);
    } catch (e) {
      gateStatus.className = "tag warn";
      gateStatus.textContent = "读取失败";
      gateSource.textContent = e.message || "读取失败";
      if (gateEnv) gateEnv.textContent = "";
    }
  }

  async function loadCloud() {
    cloudList.innerHTML = `<div class="empty-msg">加载中…</div>`;
    try {
      const { listAllCloudProjects } = await loadCloudModule();
      cloudProjects = await listAllCloudProjects();
      state.cloudProjects = cloudProjects;
      if (!cloudProjects.length) { cloudList.innerHTML = `<div class="empty-msg">云端暂无项目</div>`; return; }
      cloudList.innerHTML = `
        <div class="row between mb-2">
          <span class="text-sm muted">${cloudProjects.length} 个项目</span>
          <div class="row gap-1">
            <button class="btn ghost sm" data-sel="all">全选</button>
            <button class="btn ghost sm" data-sel="none">清空</button>
          </div>
        </div>
        <div class="list" id="cl-items"></div>
      `;
      const items = cloudList.querySelector("#cl-items");
      for (const p of cloudProjects) {
        const li = document.createElement("div");
        li.className = "list-item";
        const checked = selected.has(p.syncId) ? "checked" : "";
        li.innerHTML = `
          <input type="checkbox" data-sel-id="${escapeHtml(p.syncId || "")}" ${checked} />
          <div class="li-info">
            <div class="li-title mono">${escapeHtml(p.syncId || "未知")}</div>
            <div class="li-sub">v${p.metadata?.version || 1} · ${p.metadata?.hasData ? "有数据" : "空"}</div>
          </div>
          <div class="li-actions">
            <button class="btn ghost sm" data-import="${escapeHtml(p.syncId || "")}">导入</button>
            <button class="btn ghost sm danger" data-del="${escapeHtml(p.syncId || "")}">删除</button>
          </div>
        `;
        items.appendChild(li);
      }
      items.querySelectorAll("[data-sel-id]").forEach(cb => cb.addEventListener("change", () => {
        if (cb.checked) selected.add(cb.dataset.selId);
        else selected.delete(cb.dataset.selId);
      }));
      cloudList.querySelector('[data-sel="all"]').addEventListener("click", () => {
        items.querySelectorAll("[data-sel-id]").forEach(cb => { cb.checked = true; selected.add(cb.dataset.selId); });
      });
      cloudList.querySelector('[data-sel="none"]').addEventListener("click", () => {
        items.querySelectorAll("[data-sel-id]").forEach(cb => { cb.checked = false; selected.delete(cb.dataset.selId); });
      });
      items.querySelectorAll("[data-import]").forEach(b => b.addEventListener("click", async () => {
        const syncId = b.dataset.import;
        if (state.syncProjects.some(p => p.syncId === syncId)) { toast("项目已存在", "warn"); return; }
        const sec = await promptDialog({
          title: "导入云端项目", label: `Sync Secret for ${syncId}`, type: "password", placeholder: "用于解密"
        });
        if (sec === null) return;
        const proj = createProject({ name: `云端-${syncId}`, syncId, secret: sec, auto: false });
        await switchToProject(proj.id);
        try { await pullCurrent(); toast("已导入", "ok"); }
        catch (e) { toast(`导入失败：${e.message}`, "err"); }
        onChangeCb?.();
      }));
      items.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async () => {
        const syncId = b.dataset.del;
        const ok = await confirmDialog({ title: "删除云端项目？", message: `永久删除 ${syncId} 的密文，无法恢复。`, danger: true, okText: "删除" });
        if (!ok) return;
        if (!(await reauthAdmin("删除云端项目"))) return;
        try { await deleteCloudProject(syncId); toast("已删除", "ok"); loadCloud(); }
        catch (e) { toast(`删除失败：${e.message}`, "err"); }
      }));
    } catch (e) {
      cloudList.innerHTML = `<div class="empty-msg">加载失败：${escapeHtml(e.message)}</div>`;
    }
  }

  gateEnabled?.addEventListener("change", syncGateInputs);
  pane.querySelector('[data-act="gate-refresh"]')?.addEventListener("click", loadGateState);
  pane.querySelector('[data-act="gate-save"]')?.addEventListener("click", async () => {
    if (!gateEnabled) return;
    if (gateEnabled.checked && !gateState?.passwordConfigured) {
      toast("请先在 Cloudflare Pages 配置 ACCESS_GATE 环境变量", "warn");
      return;
    }
    const ok = await confirmDialog({
      title: gateEnabled.checked ? "启用访问口令？" : "关闭访问口令？",
      message: gateEnabled.checked
        ? "保存后，将开始使用 Pages 环境变量 ACCESS_GATE 作为访问口令。当前浏览器会自动保留已授权状态。"
        : "关闭后，访客将不再需要先输入访问口令。",
      okText: "保存",
      danger: !gateEnabled.checked,
    });
    if (!ok) return;
    if (!(await reauthAdmin("修改站点访问口令"))) return;
    try {
      const res = await fetch(apiUrl("/api/admin/access-gate"), {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Token": state.globalToken,
          "X-KV-Admin-Key": state.globalToken,
          "Cache-Control": "no-store",
        },
        body: JSON.stringify({
          enabled: gateEnabled.checked,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data?.success === false) {
        throw new Error(data?.error || `HTTP ${res.status}`);
      }
      renderGateState(data);
      toast(gateEnabled.checked ? "访问口令已启用" : "访问口令已关闭", "ok");
    } catch (e) {
      toast(e.message || "保存失败", "err");
    }
  });

  pane.querySelector('[data-act="cloud-load"]').addEventListener("click", loadCloud);

  pane.querySelector('[data-act="bulk-preview"]').addEventListener("click", async () => {
    const secretsRaw = pane.querySelector("#bulk-secrets").value.trim();
    const secrets = secretsRaw.split(/\n|,/).map(s => s.trim()).filter(Boolean);
    if (!secrets.length) { toast("请先填写同步密钥", "warn"); return; }
    if (!cloudProjects.length) { toast("请先加载云端项目", "warn"); return; }
    const targetProjects = selected.size
      ? cloudProjects.filter(p => selected.has(p.syncId))
      : cloudProjects;
    if (!targetProjects.length) { toast("没有可预览的项目", "warn"); return; }
    pane.querySelector("#bulk-result").innerHTML = `<div class="empty-msg">解密中…</div>`;
    const { decryptCloudAll } = await loadCloudModule();
    const r = await decryptCloudAll({ projects: targetProjects, secrets });
    aggregated = r.items;
    state.cloudAggregatedItems = aggregated;
    if (!aggregated.length) {
      pane.querySelector("#bulk-result").innerHTML = `<div class="empty-msg">没有解开任何项目。请检查同步密钥是否正确，或先确认上方已加载云端项目。</div>`;
      return;
    }
    let html = `<div class="text-sm muted mb-2">预览完成：本次尝试了 ${targetProjects.length} 个项目，成功解出 ${aggregated.length} 条记录，仍有 ${r.failed} 个项目未解开。下面仅显示前 50 条：</div><div class="list">`;
    for (const it of aggregated.slice(0, 50)) {
      html += `<div class="list-item">
        <div class="li-info">
          <div class="li-title">${escapeHtml(it.issuer || "")} ${it.account ? "· " + escapeHtml(it.account) : ""}</div>
          <div class="li-sub">${escapeHtml(it._projectName || "-")}</div>
        </div>
      </div>`;
    }
    html += "</div>";
    pane.querySelector("#bulk-result").innerHTML = html;
  });

  pane.querySelector('[data-act="bulk-clear"]').addEventListener("click", () => {
    aggregated = [];
    state.cloudAggregatedItems = [];
    pane.querySelector("#bulk-result").innerHTML = "";
  });

  pane.querySelector('[data-act="bulk-export"]').addEventListener("click", () => {
    void (async () => {
      if (!aggregated.length) { toast("请先完成解密预览", "warn"); return; }
      const { exportDecrypted } = await loadCloudModule();
      const fmt = pane.querySelector("#bulk-fmt").value;
      const split = pane.querySelector("#bulk-split").checked;
      const onlySel = pane.querySelector("#bulk-selected").checked;
      exportDecrypted({ items: aggregated, format: fmt, split, selected: onlySel ? selected : null });
      toast("已生成下载", "ok");
    })();
  });

  // 6.6/6.7 回收站
  pane.querySelector('[data-act="trash-load"]')?.addEventListener("click", async () => {
    const cl = pane.querySelector("#trash-list");
    cl.innerHTML = '<div class="empty-msg">加载中…</div>';
    try {
      const token = state.globalToken;
      const res = await fetch(apiUrl("/api/sync-trash"), { headers: { "X-Token": token, "Cache-Control": "no-store" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const items = Array.isArray(data.items) ? data.items : [];
      if (!items.length) { cl.innerHTML = '<div class="empty-msg">回收站为空</div>'; return; }
      cl.innerHTML = "";
      for (const it of items) {
        const li = document.createElement("div");
        li.className = "list-item";
        li.innerHTML = `
          <div class="li-info">
            <div class="li-title mono">${escapeHtml(it.syncId)}</div>
            <div class="li-sub">${it.deletedAt ? `删除于 ${new Date(it.deletedAt).toLocaleString()}` : "时间未知"}</div>
          </div>
          <div class="li-actions">
            <button class="btn ghost sm" data-restore>恢复</button>
            <button class="btn ghost sm danger" data-purge>彻底删除</button>
          </div>`;
        cl.appendChild(li);
        li.querySelector("[data-restore]").addEventListener("click", async () => {
          try {
            const r = await fetch(apiUrl(`/api/sync-backup/${encodeURIComponent(it.syncId)}`), { headers: { "X-Token": state.globalToken, "Cache-Control": "no-store" } });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            const info = await r.json();
            const backups = Array.isArray(info.backups) ? info.backups : [];
            if (!backups.length) { toast("没有可用备份", "warn"); return; }
            const pick = backups[0]; // 最新一份
            const restore = await fetch(apiUrl(`/api/sync-backup/${encodeURIComponent(it.syncId)}?ts=${pick.ts}`), { method: "POST", headers: { "X-Token": state.globalToken } });
            if (!restore.ok) throw new Error(`HTTP ${restore.status}`);
            toast(`已用 ${new Date(pick.ts).toLocaleString()} 的备份恢复`, "ok");
            li.remove();
          } catch (e) { toast(`恢复失败：${e.message}`, "err"); }
        });
        li.querySelector("[data-purge]").addEventListener("click", async () => {
          const ok = await confirmDialog({ title: "彻底删除？", message: `${it.syncId} 的所有备份与 tombstone 将被清除。无法再恢复。`, danger: true, okText: "彻底删除" });
          if (!ok) return;
          if (!(await reauthAdmin("彻底删除项目"))) return;
          try {
            const r = await fetch(apiUrl(`/api/sync/${encodeURIComponent(it.syncId)}?hard=1`), { method: "DELETE", headers: { "X-Token": state.globalToken } });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            toast("已彻底删除", "ok");
            li.remove();
          } catch (e) { toast(`删除失败：${e.message}`, "err"); }
        });
      }
    } catch (e) {
      cl.innerHTML = `<div class="empty-msg">加载失败：${escapeHtml(e.message)}</div>`;
    }
  });
  pane.querySelector('[data-act="audit-load"]')?.addEventListener("click", async () => {
    const el = pane.querySelector("#audit-list");
    el.innerHTML = '<div class="empty-msg">加载中…</div>';
    try {
      const res = await fetch(apiUrl("/api/admin/audit?limit=100"), {
        headers: { "X-Token": state.globalToken, "Cache-Control": "no-store" }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const items = Array.isArray(data.items) ? data.items : [];
      if (!items.length) { el.innerHTML = '<div class="empty-msg">暂无日志</div>'; return; }
      el.innerHTML = "";
      for (const item of items) {
        const li = document.createElement("div");
        li.className = "list-item";
        const line1 = [
          item.method || "?",
          item.path || "/",
          item.status ? `HTTP ${item.status}` : "",
        ].filter(Boolean).join(" · ");
        const line2 = [
          item.ts ? new Date(item.ts).toLocaleString() : "",
          item.ipSummary ? `IP#${item.ipSummary}` : "",
        ].filter(Boolean).join(" · ");
        li.innerHTML = `
          <div class="li-info">
            <div class="li-title mono">${escapeHtml(line1)}</div>
            <div class="li-sub">${escapeHtml(line2)}</div>
            ${item.uaSample ? `<div class="li-sub">${escapeHtml(item.uaSample)}</div>` : ""}
          </div>`;
        el.appendChild(li);
      }
    } catch (e) {
      el.innerHTML = `<div class="empty-msg">加载失败：${escapeHtml(e.message)}</div>`;
    }
  });
  pane.querySelector("#vault-on").addEventListener("change", (e) => {
    void (async () => {
      const { setVaultEnabled } = await loadVaultModule();
      setVaultEnabled(e.target.checked);
      toast(e.target.checked ? "已启用密钥托管" : "已停用密钥托管", "ok");
    })();
  });
  pane.querySelector("#vault-pub").addEventListener("change", (e) => {
    void (async () => {
      const { setVaultPubkey } = await loadVaultModule();
      setVaultPubkey(e.target.value);
      toast("公钥已保存", "ok");
      refreshFingerprint(pane);
    })();
  });

  // 初始指纹渲染
  refreshFingerprint(pane);

  pane.querySelector('[data-act="vault-escrow"]').addEventListener("click", async () => {
    const { getVaultEnabled, escrowSecrets } = await loadVaultModule();
    if (!getVaultEnabled()) { toast("请先启用密钥托管", "warn"); return; }
    const pub = pane.querySelector("#vault-pub").value.trim();
    if (!pub) { toast("请填写 RSA 公钥", "warn"); return; }
    const secretsRaw = pane.querySelector("#bulk-secrets").value.trim();
    const secs = secretsRaw.split(/\n|,/).map(s => s.trim()).filter(Boolean);
    if (!secs.length) { toast("请在批量解密区输入 Sync Secret（取第一个用于托管）", "warn"); return; }
    const ids = selected.size ? Array.from(selected) : cloudProjects.map(p => p.syncId);
    if (!ids.length) { toast("请先加载并勾选云端项目", "warn"); return; }
    const ctl = openProgress("托管选中项目密钥");
    try {
      const r = await escrowSecrets({ syncIds: ids, secret: secs[0], pubKeyPem: pub, onProgress: (i, t) => ctl.update(i, t) });
      ctl.done(`成功 ${r.ok}，失败 ${r.fail}`);
      toast(`托管：成功 ${r.ok}，失败 ${r.fail}`, r.ok && !r.fail ? "ok" : (r.ok ? "warn" : "err"));
    } catch (e) { ctl.done("出错：" + e.message); toast(e.message, "err"); }
  });

  pane.querySelector('[data-act="vault-recover"]').addEventListener("click", async () => {
    const { recoverSecrets } = await loadVaultModule();
    const pem = await promptDialog({
      title: "找回密钥", label: "粘贴管理员 RSA 私钥 (PKCS8 PEM)",
      placeholder: "-----BEGIN PRIVATE KEY-----...", multiline: true
    });
    if (!pem) return;
    const ids = selected.size ? Array.from(selected) : cloudProjects.map(p => p.syncId);
    if (!ids.length) { toast("请先加载并勾选云端项目", "warn"); return; }
    const ctl = openProgress("找回选中项目密钥");
    try {
      const recovered = await recoverSecrets({ syncIds: ids, privKeyPem: pem, onProgress: (i, t) => ctl.update(i, t) });
      ctl.done(`找回 ${recovered.length} 个密钥`);
      if (!recovered.length) { toast("没有找回任何密钥", "warn"); return; }
      const text = recovered.map(r => `${r.id}: ${r.secret}`).join("\n") + "\n";
      const ts = Date.now();
      downloadBlobLike(`recovered-secrets-${ts}.txt`, text);
      toast(`已找回 ${recovered.length} 个密钥并下载`, "ok");
    } catch (e) { ctl.done("出错：" + e.message); toast(e.message, "err"); }
  });

  pane.querySelector('[data-act="vault-migrate"]').addEventListener("click", async () => {
    const { migrateSecrets } = await loadVaultModule();
    const ids = selected.size ? Array.from(selected) : [];
    if (!ids.length) { toast("请先加载并勾选云端项目", "warn"); return; }
    if (!(await reauthAdmin("批量密钥迁移"))) return;
    const oldRaw = await promptDialog({ title: "批量密钥迁移 1/2", label: "旧 Sync Secret (可多个，换行/逗号分隔)", multiline: true });
    if (!oldRaw) return;
    const newSec = await promptDialog({ title: "批量密钥迁移 2/2", label: "新 Sync Secret", type: "password" });
    if (!newSec) return;
    const oldSecs = oldRaw.split(/\n|,/).map(s => s.trim()).filter(Boolean);
    const ctl = openProgress("批量密钥迁移");
    try {
      const r = await migrateSecrets({ syncIds: ids, oldSecrets: oldSecs, newSecret: newSec, onProgress: (i, t) => ctl.update(i, t) });
      ctl.done(`成功 ${r.ok}，失败 ${r.fail}`);
      toast(`迁移：成功 ${r.ok}，失败 ${r.fail}`, r.ok && !r.fail ? "ok" : (r.ok ? "warn" : "err"));
    } catch (e) { ctl.done("出错：" + e.message); toast(e.message, "err"); }
  });

  syncGateInputs();
  void loadGateState();
}

function downloadBlobLike(filename, text) {
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}

async function refreshFingerprint(pane) {
  const txt = pane.querySelector("#vault-pub")?.value || "";
  const el = pane.querySelector("#vault-fp");
  if (!el) return;
  if (!txt.trim()) { el.textContent = ""; return; }
  const fp = await pemFingerprint(txt);
  el.textContent = fp ? `指纹 SHA-256: ${fp}` : "公钥格式无效";
  el.style.color = fp ? "" : "var(--danger, #ef4444)";
}

// 5.7 展示新生成的恢复码（含下载/复制按钮，关闭前提醒）
function showRecoveryCodeDialog(code, onClose) {
  const { close, root } = openModal({
    title: "🔑 你的恢复码",
    bodyHtml: `
      <p class="hint" style="line-height:1.7;">这是<strong>唯一一次</strong>查看恢复码的机会。请立即抄写或下载并保存到安全位置（不要保存在主密码所在设备）。</p>
      <p class="hint" style="line-height:1.7;">将来用恢复码解锁时，旧主密码会失效，需要重新设置主密码。</p>
      <div class="section-card mono" style="font-size:18px; letter-spacing:1px; line-height:2; text-align:center; user-select:all;">${escapeHtml(code)}</div>
      <div class="btn-row mt-3">
        <button class="btn ghost" data-act="copy">📋 复制</button>
        <button class="btn ghost" data-act="download">⬇ 下载为文件</button>
      </div>
    `,
    footerHtml: `<div class="btn-row right"><button class="btn" data-act="ack" disabled>我已保存</button></div>`,
    dismissible: false,
    onMount: (r, doClose) => {
      const ack = r.querySelector('[data-act="ack"]');
      let copied = false, downloaded = false;
      function refresh() { ack.disabled = !(copied || downloaded); }
      r.querySelector('[data-act="copy"]').addEventListener("click", async () => {
        const ok = await copyText(code);
        if (ok) { copied = true; refresh(); toast("已复制恢复码", "ok"); }
        else toast("复制失败", "err");
      });
      r.querySelector('[data-act="download"]').addEventListener("click", () => {
        const blob = new Blob([`Web 2FA Authenticator - Recovery Code\nGenerated: ${new Date().toISOString()}\n\n${code}\n\n请妥善保管。重置主密码或重置恢复码后此码将失效。\n`], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a"); a.href = url; a.download = `2fa-recovery-${Date.now()}.txt`; a.click(); URL.revokeObjectURL(url);
        downloaded = true; refresh();
      });
      ack.addEventListener("click", () => { doClose(); onClose?.(); });
    },
  });
}

// 7.4 简单进度条 modal
function openProgress(title) {
  const { close, root } = openModal({
    title,
    bodyHtml: `
      <div class="progress-line"><div class="bar" style="width:0%;"></div></div>
      <div id="prog-info" class="text-sm muted mt-2">准备中…</div>
    `,
    footerHtml: `<div class="btn-row right"><button class="btn ghost" data-act="hide" disabled>关闭</button></div>`,
    dismissible: false,
    onMount: (r, doClose) => {
      r._closeBtn = r.querySelector('[data-act="hide"]');
      r._closeBtn.addEventListener("click", doClose);
    },
  });
  return {
    update(i, total) {
      const pct = total ? Math.round((i / total) * 100) : 0;
      const bar = root.querySelector(".bar");
      if (bar) bar.style.width = pct + "%";
      const info = root.querySelector("#prog-info");
      if (info) info.textContent = `${i} / ${total} (${pct}%)`;
    },
    done(text) {
      const info = root.querySelector("#prog-info");
      if (info) info.textContent = text || "完成";
      const btn = root._closeBtn;
      if (btn) btn.disabled = false;
      // 自动关闭
      setTimeout(() => { try { close(); } catch {} }, 1200);
    },
  };
}
