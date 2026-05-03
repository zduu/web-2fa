// 主页：渲染验证码网格 + tick + 点击复制 / 长按 actionsheet
// 与 storage.state 通过事件解耦，避免循环依赖

import { state, getCurrentProject, saveSyncProjects, persist } from "../core/storage.js";
import { normalizeProjectItemOrder } from "../sync/projects.js";
import { codeForItem, formatCode, secondsLeft, buildOtpAuthUrl } from "../core/totp.js";
import { createRing } from "./ring.js";
import { createAvatar } from "./avatar.js";
import { toast, copyText, escapeHtml } from "./toast.js";
import { actionSheet, confirmDialog } from "./modal.js";
import { isLocalOnlyApp } from "../core/runtime.js";

const cardMap = new Map(); // id -> { node, ring, item }
let listEl = null;
let searchEl = null;
let searchQuery = "";
let lastProjectId = null;
let dragItemId = null;

// 9.3 HMAC 缓存：同 secret 同 counter（TOTP 同周期内）的 code 缓存
const codeCache = new Map(); // key -> { code, until }
function cacheKey(item) {
  if (item.type === "hotp") {
    return `H|${item.secret}|${item.algorithm}|${item.digits}|${item.counter || 0}`;
  }
  const step = Math.max(5, Number(item.period) || 30);
  const window = Math.floor(Date.now() / 1000 / step);
  return `T|${item.secret}|${item.algorithm}|${item.digits}|${step}|${window}`;
}
async function getCodeCached(item) {
  const key = cacheKey(item);
  const cached = codeCache.get(key);
  if (cached) return cached;
  const code = await codeForItem(item);
  codeCache.set(key, code);
  // 周期性清理，避免缓存无界增长
  if (codeCache.size > 256) {
    const it = codeCache.keys();
    for (let i = 0; i < 64; i++) codeCache.delete(it.next().value);
  }
  return code;
}

export function initHome(container) {
  container.innerHTML = `
    <div class="project-bar" id="project-bar" role="toolbar" aria-label="项目切换"></div>
    <div class="home-search">
      <input id="home-search" class="input" type="search" aria-label="搜索账户" placeholder="搜索 issuer / 账号 / 项目…" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" />
    </div>
    <section class="code-grid" id="code-list" role="listbox" aria-label="2FA 账户列表"></section>
    <div class="empty-state hidden" id="empty-state">
      <div class="ico">🔐</div>
      <h3>还没有任何验证码</h3>
      <p>点击右下角 <strong>+</strong> 添加第一个 2FA 账户。<br>支持粘贴密钥、扫描二维码、导入 otpauth 链接。</p>
    </div>
    <div class="empty-state hidden" id="empty-search">
      <div class="ico">🔎</div>
      <h3>没有匹配的账户</h3>
      <p>试试缩短关键词，或清空搜索框。</p>
    </div>
  `;
  listEl = container.querySelector("#code-list");
  searchEl = container.querySelector("#home-search");
  searchEl.addEventListener("input", () => {
    searchQuery = (searchEl.value || "").trim().toLowerCase();
    renderHome();
  });
  // `/` 全局快捷键聚焦
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
      e.preventDefault();
      searchEl.focus();
      searchEl.select();
    }
  });
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

function canReorderCards() {
  return state.currentProjectId !== "_all_" && !searchQuery;
}

function getOrderedItems(items) {
  const ordered = items.slice();
  if (state.currentProjectId === "_all_") {
    return ordered.sort(compareItemsByDisplayOrder);
  }
  const proj = getCurrentProject();
  const orderIds = normalizeProjectItemOrder(proj?.itemOrder, state.items || []);
  const orderMap = new Map(orderIds.map((id, index) => [id, index]));
  return ordered.sort((a, b) => compareItemsByDisplayOrder(a, b, orderMap));
}

function compareItemsByDisplayOrder(a, b, orderMap = null) {
  const ap = a.pinned ? 1 : 0;
  const bp = b.pinned ? 1 : 0;
  if (ap !== bp) return bp - ap;
  if (orderMap) {
    const ai = orderMap.has(a.id) ? orderMap.get(a.id) : Number.POSITIVE_INFINITY;
    const bi = orderMap.has(b.id) ? orderMap.get(b.id) : Number.POSITIVE_INFINITY;
    if (ai !== bi) return ai - bi;
  }
  return `${a.issuer || ""}::${a.account || ""}`.localeCompare(`${b.issuer || ""}::${b.account || ""}`);
}

export function renderHome() {
  if (!listEl) return;
  cardMap.clear();
  listEl.innerHTML = "";

  // 项目切换时重置搜索词
  if (state.currentProjectId !== lastProjectId) {
    lastProjectId = state.currentProjectId;
    searchQuery = "";
    if (searchEl) searchEl.value = "";
  }

  const empty = document.getElementById("empty-state");
  const emptySearch = document.getElementById("empty-search");
  const allItems = getDisplayItems().filter(x => !x.deleted);
  let items = allItems.slice();

  if (!state.unlocked) {
    listEl.innerHTML = `
      <div class="empty-state">
        <div class="ico">🔒</div>
        <h3>本地数据已加密</h3>
        <p>点击右上角设置图标 → 数据 → 解锁，输入主密码后即可查看验证码。</p>
      </div>`;
    if (empty) empty.classList.add("hidden");
    if (emptySearch) emptySearch.classList.add("hidden");
    if (searchEl) searchEl.parentElement.classList.add("hidden");
    return;
  }

  if (searchEl) searchEl.parentElement.classList.toggle("hidden", allItems.length === 0 && !searchQuery);

  // 应用搜索过滤
  const q = searchQuery;
  if (q) {
    items = items.filter(it => {
      const hay = [
        it.issuer || "",
        it.account || "",
        it._projectName || "",
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }

  if (!allItems.length) {
    if (empty) empty.classList.remove("hidden");
    if (emptySearch) emptySearch.classList.add("hidden");
    return;
  }
  if (empty) empty.classList.add("hidden");

  if (!items.length) {
    if (emptySearch) emptySearch.classList.remove("hidden");
    return;
  }
  if (emptySearch) emptySearch.classList.add("hidden");

  getOrderedItems(items).forEach(item => listEl.appendChild(buildCard(item)));
}

function buildCard(item) {
  const isAll = state.currentProjectId === "_all_";
  const node = document.createElement("article");
  node.className = "code-card";
  if (item.pinned) node.classList.add("pinned");
  node.dataset.id = item.id;
  if (item._projectId) node.dataset.projectId = item._projectId;
  if (item.type === "hotp") node.classList.add("hotp");
  const reorderable = canReorderCards();
  node.draggable = reorderable;
  node.classList.toggle("reorderable", reorderable);
  // 2.3 卡片键盘焦点
  node.tabIndex = 0;
  node.setAttribute("role", "option");
  node.setAttribute("aria-selected", "false");
  node.setAttribute("aria-label", buildCardAriaLabel(item));

  const avatar = createAvatar(item.issuer, item.account, 44);
  avatar.setAttribute("aria-hidden", "true");

  const info = document.createElement("div");
  info.className = "info";
  const initCode = item.type === "hotp" ? '<span class="hint">点击 ↻ 生成</span>' : "••••••";
  info.innerHTML = `
    <div class="meta-row">
      <span class="issuer">${escapeHtml(item.issuer || "(未命名)")}</span>
    </div>
    <span class="account">${escapeHtml(item.account || "")}</span>
    <span class="code">${initCode}</span>
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
    extra.setAttribute("aria-label", "生成下一次 HOTP 验证码");
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

  // 1.3 图钉按钮（置顶切换）
  const pinBtn = document.createElement("button");
  pinBtn.type = "button";
  pinBtn.className = "card-pin" + (item.pinned ? " active" : "");
  pinBtn.setAttribute("aria-label", item.pinned ? "取消置顶" : "置顶");
  pinBtn.title = item.pinned ? "取消置顶" : "置顶";
  pinBtn.textContent = item.pinned ? "★" : "☆";
  pinBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    await togglePin(item);
  });
  node.appendChild(pinBtn);

  // 1.12 右上角更多菜单按钮
  const moreBtn = document.createElement("button");
  moreBtn.type = "button";
  moreBtn.className = "card-more";
  moreBtn.setAttribute("aria-label", "更多操作");
  moreBtn.title = "更多";
  moreBtn.textContent = "⋯";
  moreBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    openCardSheet(item);
  });
  node.appendChild(moreBtn);

  bindCardInteractions(node, item);
  bindCardReorder(node, item);

  cardMap.set(item.id, { node, ring, item });
  // initial render
  refreshCard({ node, ring, item });
  return node;
}

async function togglePin(item) {
  if (state.currentProjectId === "_all_") {
    const proj = state.syncProjects.find(p => p.id === item._projectId);
    const target = proj?.itemsData?.find(x => x.id === item.id);
    if (target) {
      target.pinned = !target.pinned;
      target.updatedAt = Date.now();
      saveSyncProjects();
    }
    item.pinned = !!target?.pinned;
  } else {
    const target = state.items.find(x => x.id === item.id);
    if (!target) return;
    target.pinned = !target.pinned;
    target.updatedAt = Date.now();
    await persist();
    const cur = getCurrentProject();
    if (cur) { cur.itemsData = state.items.map(x => ({ ...x })); saveSyncProjects(); }
    item.pinned = target.pinned;
  }
  renderHome();
  window.dispatchEvent(new CustomEvent("data-changed"));
}

function bindCardReorder(node, item) {
  node.addEventListener("dragstart", (e) => {
    if (!canReorderCards()) {
      e.preventDefault();
      return;
    }
    dragItemId = item.id;
    node.classList.add("dragging");
    node.setAttribute("aria-grabbed", "true");
    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = "move";
      try { e.dataTransfer.setData("text/plain", item.id); } catch {}
    }
  });
  node.addEventListener("dragover", (e) => {
    if (!canDropOnItem(item)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
    applyDragMarker(node, e.clientY);
  });
  node.addEventListener("dragleave", () => {
    node.classList.remove("drag-over-before", "drag-over-after");
  });
  node.addEventListener("drop", async (e) => {
    if (!canDropOnItem(item)) return;
    e.preventDefault();
    const after = isDropAfter(node, e.clientY);
    clearDragMarkers();
    await persistDraggedOrder(item.id, after);
  });
  node.addEventListener("dragend", () => {
    dragItemId = null;
    clearDragMarkers();
  });
}

function canDropOnItem(item) {
  if (!dragItemId || dragItemId === item.id || !canReorderCards()) return false;
  const dragItem = state.items.find((entry) => entry.id === dragItemId);
  if (!dragItem) return false;
  return !!dragItem.pinned === !!item.pinned;
}

function applyDragMarker(node, clientY) {
  const after = isDropAfter(node, clientY);
  clearDragMarkers();
  node.classList.add(after ? "drag-over-after" : "drag-over-before");
}

function isDropAfter(node, clientY) {
  const rect = node.getBoundingClientRect();
  return clientY >= rect.top + rect.height / 2;
}

function clearDragMarkers() {
  listEl?.querySelectorAll(".code-card").forEach((el) => {
    el.classList.remove("drag-over-before", "drag-over-after", "dragging");
    el.setAttribute("aria-grabbed", "false");
  });
}

async function persistDraggedOrder(targetId, after) {
  const proj = getCurrentProject();
  if (!proj || !dragItemId) return;
  const ids = Array.from(listEl?.querySelectorAll(".code-card") || [])
    .map((el) => el.dataset.id)
    .filter(Boolean);
  if (!ids.length) return;
  const next = ids.filter((id) => id !== dragItemId);
  const targetIndex = next.indexOf(targetId);
  if (targetIndex === -1) return;
  next.splice(after ? targetIndex + 1 : targetIndex, 0, dragItemId);
  proj.itemOrder = normalizeProjectItemOrder(next, state.items || []);
  saveSyncProjects();
  renderHome();
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

  const handleCopy = async () => {
    const shown = node.querySelector(".code")?.textContent?.replace(/\s+/g, "") || "";
    if (!shown || shown === "ERR" || shown.includes("•") || shown.includes("点击")) {
      toast("验证码尚未就绪", "warn");
      return;
    }
    const ok = await copyText(shown);
    if (ok) {
      // 1.8 复制后倒计时反馈
      node.classList.add("copied");
      setTimeout(() => node.classList.remove("copied"), 400);
      startCopiedBadge(node);
      toast("验证码已复制", "ok");
    } else {
      toast("复制失败", "err");
    }
  };

  node.addEventListener("click", async (e) => {
    if (longPressed) { e.preventDefault(); return; }
    if (e.target.closest(".hotp-next")) return;
    if (e.target.closest(".card-more")) return;
    if (e.target.closest(".card-pin")) return;
    await handleCopy();
  });

  // 2.3 键盘：Enter / Space 复制；M 弹菜单；P 置顶；E 编辑
  node.addEventListener("keydown", async (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      await handleCopy();
    } else if (e.key.toLowerCase() === "m") {
      e.preventDefault();
      openCardSheet(item);
    } else if (e.key.toLowerCase() === "p") {
      e.preventDefault();
      await togglePin(item);
    } else if (e.key.toLowerCase() === "e") {
      e.preventDefault();
      const onEdit = window.__cardActions?.onEdit;
      if (typeof onEdit === "function") onEdit(item);
    }
  });

  node.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    openCardSheet(item);
  });
}

// 1.8 复制后倒计时角标
function startCopiedBadge(node) {
  let badge = node.querySelector(".copied-badge");
  if (!badge) {
    badge = document.createElement("div");
    badge.className = "copied-badge";
    node.appendChild(badge);
  }
  let elapsed = 0;
  const total = 5;
  badge.textContent = "✓ 已复制";
  badge.classList.add("show");
  if (node._copiedTimer) clearInterval(node._copiedTimer);
  node._copiedTimer = setInterval(() => {
    elapsed++;
    if (elapsed >= total) {
      clearInterval(node._copiedTimer);
      badge.classList.remove("show");
      return;
    }
    badge.textContent = `✓ 已复制 ${elapsed}s`;
  }, 1000);
}

async function openCardSheet(item) {
  const { onShare, onDelete, onEdit } = window.__cardActions || {};
  const canShare = !isLocalOnlyApp() && state.adminUnlocked && typeof onShare === "function";
  const actions = [
    { label: item.pinned ? "取消置顶" : "置顶", icon: item.pinned ? "★" : "☆", onClick: () => togglePin(item) },
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
  // 让 refreshCard 之后开始正常显示 code
  if (node) node.dataset.hotpShown = "1";
  await refreshCard(cardMap.get(item.id));
  toast("已生成下一次", "ok");
  window.dispatchEvent(new CustomEvent("data-changed"));
}

async function refreshCard(entry) {
  if (!entry) return;
  const { node, ring, item } = entry;
  // HOTP 卡片在用户点 ↻ 之前保持占位
  if (item.type === "hotp" && node.dataset.hotpShown !== "1") {
    return;
  }
  try {
    const code = await getCodeCached(item);
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
  if (ticker) clearTimeout(ticker);
  scheduleTick();
  // 9.2 visibility / focus 时立即对齐刷新一次
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      tickHome();
      if (ticker) clearTimeout(ticker);
      scheduleTick();
    }
  });
  window.addEventListener("focus", () => { tickHome(); });
}
function scheduleTick() {
  // 对齐到下一秒边界，最多漂移到 1000ms
  const now = Date.now();
  const delay = 1000 - (now % 1000);
  ticker = setTimeout(async () => {
    await tickHome();
    scheduleTick();
  }, Math.max(50, delay));
}
export function stopTicker() { if (ticker) { clearTimeout(ticker); ticker = null; } }

export function setCardActions({ onShare, onDelete, onEdit }) {
  window.__cardActions = { onShare, onDelete, onEdit };
}

// ----- Project bar (top of home) -----
export function renderProjectBar(onSelect, onCreate) {
  const bar = document.getElementById("project-bar");
  if (!bar) return;
  bar.innerHTML = "";

  if ((!isLocalOnlyApp() && !state.adminUnlocked) || state.syncProjects.length === 0) {
    bar.classList.add("hidden");
    return;
  }
  bar.classList.remove("hidden");

  const allBtn = document.createElement("button");
  allBtn.className = "chip virtual" + (state.currentProjectId === "_all_" ? " active" : "");
  allBtn.type = "button";
  allBtn.setAttribute("aria-pressed", state.currentProjectId === "_all_" ? "true" : "false");
  allBtn.innerHTML = `<span>📊</span><span>全部汇总</span>`;
  allBtn.addEventListener("click", () => onSelect("_all_"));
  bar.appendChild(allBtn);

  for (const p of state.syncProjects) {
    const chip = document.createElement("button");
    chip.className = "chip" + (p.id === state.currentProjectId ? " active" : "");
    chip.type = "button";
    chip.setAttribute("aria-pressed", p.id === state.currentProjectId ? "true" : "false");
    const dot = p.id === state.currentProjectId ? '<span class="chip-dot"></span>' : "";
    chip.innerHTML = `${dot}<span>${escapeHtml(p.name || "未命名")}</span>`;
    chip.addEventListener("click", () => onSelect(p.id));
    bar.appendChild(chip);
  }
}

function buildCardAriaLabel(item) {
  const bits = [
    item.issuer || "未命名账户",
    item.account || "",
    (item.type || "totp").toUpperCase(),
  ].filter(Boolean);
  if (item.type === "hotp") bits.push(`计数器 ${Number(item.counter || 0)}`);
  else bits.push(`周期 ${Number(item.period || 30)} 秒`);
  return `${bits.join("，")}。按 Enter 复制验证码。`;
}
