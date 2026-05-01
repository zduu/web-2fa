// 右侧抽屉 + L2 / L3 面板渲染
// L2：项目同步 / 数据 / 关于
// L3：管理员模式（云端浏览 / Vault / 迁移 / 模式切换 / 退出）

import { state, saveSyncProjects, tryUnlock, setMasterPassword, clearMasterPassword,
  loadAdminUnlocked } from "../core/storage.js";
import {
  listProjects, detectDuplicateSyncIds, createProject, updateProject, deleteProject,
  switchToProject, saveCurrentProjectItems
} from "../sync/projects.js";
import {
  pushCurrent, pullCurrent, mergeAllProjectsIntoCurrent, cleanDeleted,
  startAutoSync, stopAutoSync, scheduleAutoPush, deleteCloudProject
} from "../sync/sync.js";
import { fetchCloudShareRecords, revokeShare } from "../share/share.js";
import { exportCurrent, importFromFile } from "./import-export.js";
import { toast, copyText, escapeHtml } from "./toast.js";
import { confirmDialog, openModal, promptDialog } from "./modal.js";
import { verifyAdminKey, unlockAdmin, lockAdmin } from "../admin/unlock.js";
import {
  listAllCloudProjects, decryptCloudAll, exportDecrypted
} from "../sync/cloud.js";
import {
  getVaultEnabled, setVaultEnabled, getVaultPubkey, setVaultPubkey,
  escrowSecrets, recoverSecrets, migrateSecrets
} from "../sync/vault.js";

let backdrop = null;
let drawer = null;
let onChangeCb = null; // notify outer to re-render home
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
  drawer.className = "drawer";
  drawer.innerHTML = `
    <div class="drawer-head">
      <h2>设置</h2>
      <button class="close" aria-label="关闭">✕</button>
    </div>
    <nav class="drawer-tabs">
      <button class="tab active" data-tab="sync">项目</button>
      <button class="tab" data-tab="data">数据</button>
      <button class="tab admin-only" data-tab="share">分享</button>
      <button class="tab admin-only" data-tab="admin">管理员</button>
      <button class="tab" data-tab="about">关于</button>
    </nav>
    <div class="drawer-body">
      <div class="drawer-pane active" data-pane="sync"></div>
      <div class="drawer-pane" data-pane="data"></div>
      <div class="drawer-pane" data-pane="share"></div>
      <div class="drawer-pane" data-pane="admin"></div>
      <div class="drawer-pane" data-pane="about"></div>
    </div>
  `;

  document.body.appendChild(backdrop);
  document.body.appendChild(drawer);

  backdrop.addEventListener("click", closeDrawer);
  drawer.querySelector(".close").addEventListener("click", closeDrawer);

  drawer.querySelectorAll(".tab").forEach(t => {
    t.addEventListener("click", () => {
      drawer.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === t));
      drawer.querySelectorAll(".drawer-pane").forEach(p => p.classList.toggle("active", p.dataset.pane === t.dataset.tab));
      renderActivePane();
    });
  });

  // sync admin class with state
  syncAdminClass();
}

function syncAdminClass() {
  if (state.adminUnlocked) drawer.classList.add("admin");
  else drawer.classList.remove("admin");
}

export function openDrawer(initialTab = "sync") {
  // refresh admin flag from session
  state.adminUnlocked = loadAdminUnlocked();
  syncAdminClass();
  const tab = (!state.adminUnlocked && (initialTab === "share" || initialTab === "admin")) ? "sync" : initialTab;
  drawer.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
  drawer.querySelectorAll(".drawer-pane").forEach(p => p.classList.toggle("active", p.dataset.pane === tab));

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
  return drawer.querySelector(".tab.active")?.dataset.tab || "sync";
}

function renderActivePane() {
  const name = activePaneName();
  const pane = drawer.querySelector(`[data-pane="${name}"]`);
  if (!pane) return;
  if (name === "sync") renderSyncPane(pane);
  else if (name === "data") renderDataPane(pane);
  else if (name === "share") renderSharePane(pane);
  else if (name === "admin") renderAdminPane(pane);
  else if (name === "about") renderAboutPane(pane);
}

// ===========================================================================
// SYNC pane (项目)
// ===========================================================================
function renderSyncPane(pane) {
  const dupMap = detectDuplicateSyncIds();
  const projects = listProjects();
  const cur = state.syncProjects.find(p => p.id === state.currentProjectId);
  const isAdmin = !!state.adminUnlocked;

  let html = `
    <div class="section">
      <h3>同步项目</h3>
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
      <h3>当前项目操作</h3>
      <div class="section-card col gap-2">
        <div class="row between">
          <div>
            <div class="text-sm" style="font-weight:600;">${escapeHtml(cur.name || "未命名")}</div>
            <div class="text-xs muted mono">${escapeHtml(cur.syncId || "-")}</div>
          </div>
          <span class="tag ${cur.lastSyncedAt ? "ok" : ""}">${cur.lastSyncedAt ? "上次同步：" + new Date(cur.lastSyncedAt).toLocaleTimeString() : "未同步"}</span>
        </div>
        <div class="btn-row">
          <button class="btn" data-act="push">⬆ 推送</button>
          <button class="btn ghost" data-act="pull">⬇ 拉取</button>
          <button class="btn ghost" data-act="merge-all">合并所有</button>
        </div>
        <label class="row gap-2">
          <input type="checkbox" id="auto-sync" ${cur.auto ? "checked" : ""}/>
          <span class="text-sm">启用自动同步（保存后自动推送，每 60s 自动拉取）</span>
        </label>
        <button class="btn ghost sm" data-act="edit-current">编辑当前项目</button>
      </div>
    </div>
    ` : ""}

    <div class="section">
      <details>
        <summary class="hint" style="cursor:pointer; user-select:none;">概念说明</summary>
        <div class="hint mt-2" style="line-height:1.7;">
          <p><strong>Sync Secret</strong>：每个项目独立的端到端加密密钥，跨设备必须一致；忘记后无法恢复云端数据。</p>
          ${isAdmin ? '<p><strong>Admin Key</strong>：服务端配置的管理员主密钥。在严格模式下，没有 Admin Key 无法读写云端。</p>' : ""}
          <p><strong>全部汇总视图</strong>：本地虚拟视图，只显示你已创建的项目数据。不会自动拉取云端其他项目。</p>
        </div>
      </details>
    </div>
  `;

  pane.innerHTML = html;

  const list = pane.querySelector("#proj-list");
  if (!projects.length) {
    list.innerHTML = `<div class="empty-msg">点击"新建项目"开始多设备同步</div>`;
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
      const dup = p.syncId && dupMap.get(p.syncId) > 1;
      const li = document.createElement("div");
      li.className = "list-item" + (isCur ? " active" : "");
      li.innerHTML = `
        <div class="li-info">
          <div class="li-title">${escapeHtml(p.name || "未命名")} ${dup ? '<span class="tag warn">ID 重复</span>' : ""}</div>
          <div class="li-sub">${escapeHtml(p.syncId || "-")}</div>
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
    pane.querySelector('[data-act="push"]').addEventListener("click", async () => {
      try { await pushCurrent(); toast("已推送", "ok"); }
      catch (e) { toast(e.message, "err"); }
    });
    pane.querySelector('[data-act="pull"]').addEventListener("click", async () => {
      try { await pullCurrent(); toast("已同步", "ok"); onChangeCb?.(); }
      catch (e) {
        if (e.code === "empty") toast("云端暂无数据", "warn");
        else toast(e.message, "err");
      }
    });
    pane.querySelector('[data-act="merge-all"]').addEventListener("click", async () => {
      const ok = await confirmDialog({
        title: "合并所有项目",
        message: "将本地所有已保存项目的条目合并到当前项目，并推送到云端。继续？",
      });
      if (!ok) return;
      try {
        const stat = await mergeAllProjectsIntoCurrent();
        toast(`合并完成：${stat.before} → ${stat.after} 条`, "ok");
        try { await pushCurrent(); toast("已推送", "ok"); } catch {}
        onChangeCb?.();
      } catch (e) { toast(e.message, "err"); }
    });
    pane.querySelector("#auto-sync").addEventListener("change", (e) => {
      cur.auto = e.target.checked;
      saveSyncProjects();
      if (cur.auto) startAutoSync(); else stopAutoSync();
      toast(cur.auto ? "已启用自动同步" : "已停用自动同步", "ok");
    });
    pane.querySelector('[data-act="edit-current"]').addEventListener("click", () => openProjectEditor(cur.id, pane));
  }
}

function openProjectEditor(projectId, parentPane) {
  const proj = projectId ? state.syncProjects.find(p => p.id === projectId) : null;
  const isNew = !proj;
  const { close, root } = openModal({
    title: isNew ? "新建同步项目" : "编辑项目",
    bodyHtml: `
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
    `,
    footerHtml: `
      <div class="btn-row right">
        ${proj ? '<button class="btn danger" data-act="del">删除项目</button>' : ""}
        <button class="btn ghost" data-act="cancel">取消</button>
        <button class="btn" data-act="save">保存</button>
      </div>
    `,
    onMount: (r, doClose) => {
      r.querySelector("[data-toggle]").addEventListener("click", () => {
        const inp = r.querySelector("#pe-secret");
        inp.type = inp.type === "password" ? "text" : "password";
      });
      r.querySelector('[data-act="cancel"]').addEventListener("click", doClose);
      r.querySelector('[data-act="save"]').addEventListener("click", async () => {
        const name = r.querySelector("#pe-name").value.trim();
        const syncId = r.querySelector("#pe-id").value.trim();
        const secret = r.querySelector("#pe-secret").value;
        const auto = r.querySelector("#pe-auto").checked;
        if (!name || !syncId || !secret) { toast("请填写名称、Sync ID 和 Secret", "warn"); return; }
        const dup = state.syncProjects.find(p => p.id !== projectId && (p.syncId || "").trim() === syncId);
        if (dup) {
          const ok = await confirmDialog({
            title: "Sync ID 重复",
            message: `已有项目 "${dup.name || dup.id}" 使用相同的 Sync ID，继续保存将共用同一云端数据，可能互相覆盖。仍要继续？`,
            danger: true
          });
          if (!ok) return;
        }
        let saved;
        if (proj) {
          saved = updateProject(projectId, { name, syncId, secret, auto });
        } else {
          saved = createProject({ name, syncId, secret, auto });
        }
        await switchToProject(saved.id);
        if (auto) startAutoSync(); else stopAutoSync();
        doClose();
        renderSyncPane(parentPane);
        onChangeCb?.();
        toast(proj ? "项目已更新" : "项目已创建", "ok");
      });
      r.querySelector('[data-act="del"]')?.addEventListener("click", async () => {
        const ok = await confirmDialog({
          title: "删除项目？",
          message: "本地项目数据会被删除（云端密文不会自动删除，请在管理员面板手动清理）。",
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

  pane.innerHTML = `
    <div class="section">
      <h3>导入 / 导出</h3>
      <div class="section-card col gap-2">
        <p class="hint">导出当前项目的全部账户为 JSON 文件（可选用密码加密）。</p>
        <div class="btn-row">
          <button class="btn ghost" data-act="export">📤 导出</button>
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
        <p class="hint">设置后，本地存储将使用 AES-GCM + PBKDF2 加密。<strong>忘记主密码无法恢复数据。</strong></p>
        <div class="btn-row">
          ${isLocked
            ? '<button class="btn" data-act="unlock">🔓 输入密码解锁</button>'
            : `<button class="btn" data-act="set-master">${hasMaster ? "🔁 更改主密码" : "🔐 设置主密码"}</button>
               ${hasMaster ? '<button class="btn ghost danger" data-act="clear-master">移除加密</button>' : ""}`}
        </div>
      </div>
    </div>

    <div class="section">
      <h3>清理</h3>
      <div class="section-card col gap-2">
        <p class="hint">彻底删除已标记为"删除"的条目（tombstone）。仅当你确认其他设备已经同步到删除状态后再执行，否则旧设备可能把已删账户带回来。</p>
        <button class="btn ghost" data-act="clean">🧹 清理已删除条目</button>
      </div>
    </div>
  `;

  pane.querySelector('[data-act="export"]').addEventListener("click", () => exportCurrent());
  pane.querySelector('[data-act="import"]').addEventListener("click", async () => {
    const ok = await importFromFile();
    if (ok) { renderActivePane(); onChangeCb?.(); }
  });

  pane.querySelector('[data-act="set-master"]')?.addEventListener("click", async () => {
    const pwd = await promptDialog({
      title: hasMaster ? "更改主密码" : "设置主密码",
      label: "请输入主密码",
      placeholder: "强密码建议 12+ 字符",
      type: "password",
      okText: "保存"
    });
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
    const pwd = await promptDialog({
      title: "解锁数据",
      label: "请输入主密码",
      type: "password",
      okText: "解锁"
    });
    if (!pwd) return;
    const ok = await tryUnlock(pwd);
    if (ok) { toast("已解锁", "ok"); renderDataPane(pane); onChangeCb?.(); }
    else toast("密码错误或数据损坏", "err");
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
}

// ===========================================================================
// SHARE pane (分享)
// ===========================================================================
async function renderSharePane(pane) {
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
      const records = await fetchCloudShareRecords();
      cl.innerHTML = "";
      if (!records.length) { cl.innerHTML = `<div class="empty-msg">云端暂无分享</div>`; return; }
      for (const rec of records) {
        const li = document.createElement("div");
        li.className = "list-item";
        const label = rec.label || "分享";
        const metaParts = [
          `SID: ${rec.sid}`,
          rec.projectName ? rec.projectName : "",
          rec.createdAt ? new Date(rec.createdAt).toLocaleString() : "",
        ].filter(Boolean);
        li.innerHTML = `
          <div class="li-info">
            <div class="li-title">${escapeHtml(label)}</div>
            <div class="li-sub">${escapeHtml(metaParts.join(" · "))}</div>
          </div>
          <div class="li-actions">
            <button class="btn ghost sm" data-copy>📋</button>
            <button class="btn ghost sm" data-revoke>撤销</button>
          </div>`;
        cl.appendChild(li);
        li.querySelector("[data-copy]").addEventListener("click", async () => {
          if (rec.k) {
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
  const isAdmin = !!state.adminUnlocked;
  const adminEntryVisible = isAdmin || loadAdminEntryVisible();
  pane.innerHTML = `
    <div class="section">
      <h3>关于</h3>
      <div class="section-card col gap-2">
        <div class="row between"><span class="text-sm">版本</span><span class="tag" data-act="about-version">v0.2.0</span></div>
        <div class="row between"><span class="text-sm">数据存储</span><span class="text-sm muted">localStorage + Cloudflare KV</span></div>
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
          <p>未启用同步项目时，全部数据只存储在浏览器 localStorage 中，离线可用，不会上传任何信息。</p>
          <p>启用同步后，本地用 Sync Secret 端到端加密，云端只保存密文。</p>
          <p>"全部汇总视图"是本地虚拟视图，不会访问其他用户的云端数据。</p>
        </div>
      </details>
    </div>
  `;

  bindAdminEntryReveal(pane, adminEntryVisible);

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
function renderAdminPane(pane) {
  if (!state.adminUnlocked) {
    pane.innerHTML = `
      <div class="empty-msg">
        管理员模式未解锁。
      </div>
    `;
    return;
  }

  const vaultEnabled = getVaultEnabled();
  const vaultPub = getVaultPubkey();

  pane.innerHTML = `
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
      <h3>密钥托管 (Vault)</h3>
      <div class="section-card col gap-2">
        <p class="hint">用 RSA 公钥加密 Sync Secret 后存放在云端，丢失本地数据时可用 RSA 私钥找回。</p>
        <label class="row gap-2"><input type="checkbox" id="vault-on" ${vaultEnabled ? "checked" : ""} /> <span class="text-sm">启用密钥托管功能</span></label>
        <div class="field">
          <label>RSA 公钥 (PEM / SPKI / Base64 DER)</label>
          <textarea id="vault-pub" class="input mono" placeholder="-----BEGIN PUBLIC KEY-----&#10;...">${escapeHtml(vaultPub)}</textarea>
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

  const cloudList = pane.querySelector("#cloud-list");

  async function loadCloud() {
    cloudList.innerHTML = `<div class="empty-msg">加载中…</div>`;
    try {
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
        try { await deleteCloudProject(syncId); toast("已删除", "ok"); loadCloud(); }
        catch (e) { toast(`删除失败：${e.message}`, "err"); }
      }));
    } catch (e) {
      cloudList.innerHTML = `<div class="empty-msg">加载失败：${escapeHtml(e.message)}</div>`;
    }
  }

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
    if (!aggregated.length) { toast("请先完成解密预览", "warn"); return; }
    const fmt = pane.querySelector("#bulk-fmt").value;
    const split = pane.querySelector("#bulk-split").checked;
    const onlySel = pane.querySelector("#bulk-selected").checked;
    exportDecrypted({ items: aggregated, format: fmt, split, selected: onlySel ? selected : null });
    toast("已生成下载", "ok");
  });

  // Vault
  pane.querySelector("#vault-on").addEventListener("change", (e) => {
    setVaultEnabled(e.target.checked);
    toast(e.target.checked ? "已启用密钥托管" : "已停用密钥托管", "ok");
  });
  pane.querySelector("#vault-pub").addEventListener("change", (e) => {
    setVaultPubkey(e.target.value);
    toast("公钥已保存", "ok");
  });

  pane.querySelector('[data-act="vault-escrow"]').addEventListener("click", async () => {
    if (!getVaultEnabled()) { toast("请先启用密钥托管", "warn"); return; }
    const pub = pane.querySelector("#vault-pub").value.trim();
    if (!pub) { toast("请填写 RSA 公钥", "warn"); return; }
    const secretsRaw = pane.querySelector("#bulk-secrets").value.trim();
    const secs = secretsRaw.split(/\n|,/).map(s => s.trim()).filter(Boolean);
    if (!secs.length) { toast("请在批量解密区输入 Sync Secret（取第一个用于托管）", "warn"); return; }
    const ids = selected.size ? Array.from(selected) : cloudProjects.map(p => p.syncId);
    if (!ids.length) { toast("请先加载并勾选云端项目", "warn"); return; }
    try {
      const r = await escrowSecrets({ syncIds: ids, secret: secs[0], pubKeyPem: pub });
      toast(`托管：成功 ${r.ok}，失败 ${r.fail}`, r.ok && !r.fail ? "ok" : (r.ok ? "warn" : "err"));
    } catch (e) { toast(e.message, "err"); }
  });

  pane.querySelector('[data-act="vault-recover"]').addEventListener("click", async () => {
    const pem = await promptDialog({
      title: "找回密钥", label: "粘贴管理员 RSA 私钥 (PKCS8 PEM)",
      placeholder: "-----BEGIN PRIVATE KEY-----...", multiline: true
    });
    if (!pem) return;
    const ids = selected.size ? Array.from(selected) : cloudProjects.map(p => p.syncId);
    if (!ids.length) { toast("请先加载并勾选云端项目", "warn"); return; }
    try {
      const recovered = await recoverSecrets({ syncIds: ids, privKeyPem: pem });
      if (!recovered.length) { toast("没有找回任何密钥", "warn"); return; }
      const text = recovered.map(r => `${r.id}: ${r.secret}`).join("\n") + "\n";
      const ts = Date.now();
      downloadBlobLike(`recovered-secrets-${ts}.txt`, text);
      toast(`已找回 ${recovered.length} 个密钥并下载`, "ok");
    } catch (e) { toast(e.message, "err"); }
  });

  pane.querySelector('[data-act="vault-migrate"]').addEventListener("click", async () => {
    const ids = selected.size ? Array.from(selected) : [];
    if (!ids.length) { toast("请先加载并勾选云端项目", "warn"); return; }
    const oldRaw = await promptDialog({ title: "批量密钥迁移 1/2", label: "旧 Sync Secret (可多个，换行/逗号分隔)", multiline: true });
    if (!oldRaw) return;
    const newSec = await promptDialog({ title: "批量密钥迁移 2/2", label: "新 Sync Secret", type: "password" });
    if (!newSec) return;
    const oldSecs = oldRaw.split(/\n|,/).map(s => s.trim()).filter(Boolean);
    try {
      const r = await migrateSecrets({ syncIds: ids, oldSecrets: oldSecs, newSecret: newSec });
      toast(`迁移：成功 ${r.ok}，失败 ${r.fail}`, r.ok && !r.fail ? "ok" : (r.ok ? "warn" : "err"));
    } catch (e) { toast(e.message, "err"); }
  });
}

function downloadBlobLike(filename, text) {
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}
