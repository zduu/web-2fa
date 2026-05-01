// 主页：渲染验证码网格 + tick + 点击复制 / 长按 actionsheet
// 与 storage.state 通过事件解耦，避免循环依赖

import { state, getCurrentProject, saveSyncProjects, persist } from "../core/storage.js";
import { codeForItem, formatCode, secondsLeft, buildOtpAuthUrl } from "../core/totp.js";
import { createRing } from "./ring.js";
import { createAvatar } from "./avatar.js";
import { toast, copyText, escapeHtml } from "./toast.js";
import { actionSheet, confirmDialog } from "./modal.js";

const cardMap = new Map(); // id -> { node, ring, item }
let listEl = null;

export function initHome(container) {
  container.innerHTML = `
    <div class="project-bar" id="project-bar"></div>
    <section class="code-grid" id="code-list"></section>
    <div class="empty-state hidden" id="empty-state">
      <div class="ico">🔐</div>
      <h3>还没有任何验证码</h3>
      <p>点击右下角 <strong>+</strong> 添加第一个 2FA 账户。<br>支持粘贴密钥、扫描二维码、导入 otpauth 链接。</p>
    </div>
  `;
  listEl = container.querySelector("#code-list");
}

function getDisplayItems() {
  if (state.currentProjectId === "_all_") {
    const out = [];
    state.syncProjects.forEach(p => {
      if (p && Array.isArray(p.itemsData)) {
        for (const it of p.itemsData) {
          out.push({ ...it, _projectId: p.id, _projectName: p.name || "未命名" });
        }
      }
    });
    return out;
  }
  return state.items;
}

export function renderHome() {
  if (!listEl) return;
  cardMap.clear();
  listEl.innerHTML = "";

  const empty = document.getElementById("empty-state");
  const items = getDisplayItems().filter(x => !x.deleted);

  if (!state.unlocked) {
    listEl.innerHTML = `
      <div class="empty-state">
        <div class="ico">🔒</div>
        <h3>本地数据已加密</h3>
        <p>点击右上角设置图标 → 数据 → 解锁，输入主密码后即可查看验证码。</p>
      </div>`;
    if (empty) empty.classList.add("hidden");
    return;
  }

  if (!items.length) {
    if (empty) empty.classList.remove("hidden");
    return;
  }
  if (empty) empty.classList.add("hidden");

  items
    .slice()
    .sort((a, b) => `${a.issuer}::${a.account}`.localeCompare(`${b.issuer}::${b.account}`))
    .forEach(item => listEl.appendChild(buildCard(item)));
}

function buildCard(item) {
  const isAll = state.currentProjectId === "_all_";
  const node = document.createElement("article");
  node.className = "code-card";
  node.dataset.id = item.id;
  if (item._projectId) node.dataset.projectId = item._projectId;
  if (item.type === "hotp") node.classList.add("hotp");

  const avatar = createAvatar(item.issuer, item.account, 44);

  const info = document.createElement("div");
  info.className = "info";
  info.innerHTML = `
    <div class="meta-row">
      <span class="issuer">${escapeHtml(item.issuer || "(未命名)")}</span>
    </div>
    <span class="account">${escapeHtml(item.account || "")}</span>
    <span class="code">••••••</span>
    <div class="badges">
      <span class="badge">${(item.type || "totp").toUpperCase()}</span>
      ${item.algorithm && item.algorithm !== "SHA1" ? `<span class="badge">${escapeHtml(item.algorithm)}</span>` : ""}
      ${item.digits && Number(item.digits) !== 6 ? `<span class="badge">${item.digits}位</span>` : ""}
      ${isAll && item._projectName ? `<span class="badge project">${escapeHtml(item._projectName)}</span>` : ""}
    </div>
  `;

  let ring = null;
  let extra = null;
  if (item.type === "hotp") {
    extra = document.createElement("button");
    extra.type = "button";
    extra.className = "hotp-next";
    extra.title = "下一次验证码（counter+1）";
    extra.textContent = "↻";
    extra.addEventListener("click", async (e) => {
      e.stopPropagation();
      await advanceHotp(item, node);
    });
  } else {
    ring = createRing(40);
    const wrap = document.createElement("div");
    wrap.className = "ring";
    wrap.appendChild(ring.el);
    extra = wrap;
  }

  node.appendChild(avatar);
  node.appendChild(info);
  node.appendChild(extra);

  bindCardInteractions(node, item);

  cardMap.set(item.id, { node, ring, item });
  // initial render
  refreshCard({ node, ring, item });
  return node;
}

function bindCardInteractions(node, item) {
  let pressTimer = null;
  let longPressed = false;

  const startPress = () => {
    longPressed = false;
    pressTimer = setTimeout(() => {
      longPressed = true;
      openCardSheet(item);
    }, 500);
  };
  const endPress = () => {
    if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; }
  };

  node.addEventListener("pointerdown", startPress);
  node.addEventListener("pointerup", endPress);
  node.addEventListener("pointerleave", endPress);
  node.addEventListener("pointercancel", endPress);

  node.addEventListener("click", async (e) => {
    if (longPressed) { e.preventDefault(); return; }
    if (e.target.closest(".hotp-next")) return;
    const shown = node.querySelector(".code")?.textContent?.replace(/\s+/g, "") || "";
    if (!shown || shown === "ERR" || shown.includes("•")) {
      toast("验证码尚未就绪", "warn");
      return;
    }
    const ok = await copyText(shown);
    if (ok) {
      node.classList.add("copied");
      setTimeout(() => node.classList.remove("copied"), 400);
      toast("验证码已复制", "ok");
    } else {
      toast("复制失败", "err");
    }
  });

  node.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    openCardSheet(item);
  });
}

async function openCardSheet(item) {
  const { onShare, onDelete, onEdit } = window.__cardActions || {};
  const canShare = state.adminUnlocked && typeof onShare === "function";
  const actions = [
    { label: "复制 otpauth 链接", icon: "🔗", onClick: async () => {
      const ok = await copyText(buildOtpAuthUrl(item));
      toast(ok ? "已复制 otpauth 链接" : "复制失败", ok ? "ok" : "err");
    }},
  ];
  if (typeof onEdit === "function") {
    actions.push({ label: "编辑账户", icon: "✏️", onClick: () => onEdit(item) });
  }
  if (item.type === "totp" && canShare) {
    actions.push({ label: "分享验证码", icon: "📤", onClick: () => onShare(item) });
  }
  actions.push({ label: "删除", icon: "🗑", danger: true, onClick: () => {
    if (typeof onDelete === "function") onDelete(item);
  }});
  await actionSheet({ title: `${item.issuer || ""} ${item.account ? "· " + item.account : ""}`.trim() || "操作", actions });
}

async function advanceHotp(item, node) {
  // Mutate current state.items reference. For "_all_" view we modify the source project.
  if (state.currentProjectId === "_all_") {
    const proj = state.syncProjects.find(p => p.id === item._projectId);
    if (!proj || !Array.isArray(proj.itemsData)) return;
    const target = proj.itemsData.find(x => x.id === item.id);
    if (!target) return;
    target.counter = Number(target.counter || 0) + 1;
    target.updatedAt = Date.now();
    item.counter = target.counter; // sync the displayed reference
    saveSyncProjects();
  } else {
    const target = state.items.find(x => x.id === item.id);
    if (!target) return;
    target.counter = Number(target.counter || 0) + 1;
    target.updatedAt = Date.now();
    item.counter = target.counter;
    await persist();
    const proj = getCurrentProject();
    if (proj) {
      proj.itemsData = state.items.map(x => ({ ...x }));
      saveSyncProjects();
    }
  }
  await refreshCard(cardMap.get(item.id));
  toast("已生成下一次", "ok");
  window.dispatchEvent(new CustomEvent("data-changed"));
}

async function refreshCard(entry) {
  if (!entry) return;
  const { node, ring, item } = entry;
  try {
    const code = await codeForItem(item);
    node.querySelector(".code").textContent = formatCode(code, item.digits);
  } catch {
    node.querySelector(".code").textContent = "ERR";
  }
  if (item.type === "totp" && ring) {
    const left = secondsLeft(item.period);
    ring.update(left, item.period || 30);
    if (left <= 5) node.classList.add("expiring"); else node.classList.remove("expiring");
  }
}

export async function tickHome() {
  await Promise.all(Array.from(cardMap.values()).map(refreshCard));
}

let ticker = null;
export function startTicker() {
  if (ticker) clearInterval(ticker);
  ticker = setInterval(() => tickHome(), 1000);
}
export function stopTicker() { if (ticker) { clearInterval(ticker); ticker = null; } }

export function setCardActions({ onShare, onDelete, onEdit }) {
  window.__cardActions = { onShare, onDelete, onEdit };
}

// ----- Project bar (top of home) -----
export function renderProjectBar(onSelect, onCreate) {
  const bar = document.getElementById("project-bar");
  if (!bar) return;
  bar.innerHTML = "";

  if (state.syncProjects.length === 0) {
    bar.classList.add("hidden");
    return;
  }
  bar.classList.remove("hidden");

  const allBtn = document.createElement("button");
  allBtn.className = "chip virtual" + (state.currentProjectId === "_all_" ? " active" : "");
  allBtn.innerHTML = `<span>📊</span><span>全部汇总</span>`;
  allBtn.addEventListener("click", () => onSelect("_all_"));
  bar.appendChild(allBtn);

  for (const p of state.syncProjects) {
    const chip = document.createElement("button");
    chip.className = "chip" + (p.id === state.currentProjectId ? " active" : "");
    const dot = p.id === state.currentProjectId ? '<span class="chip-dot"></span>' : "";
    chip.innerHTML = `${dot}<span>${escapeHtml(p.name || "未命名")}</span>`;
    chip.addEventListener("click", () => onSelect(p.id));
    bar.appendChild(chip);
  }
}
