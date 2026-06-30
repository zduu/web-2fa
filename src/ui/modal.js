// 模态框工厂：openModal({ title, body, actions, dismissible })
// 返回 { close, root }

const FOCUSABLE_SELECTOR = [
  'button:not([disabled])',
  '[href]',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

function getFocusable(root) {
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR))
    .filter((el) => !el.hasAttribute("hidden") && el.getAttribute("aria-hidden") !== "true");
}

export function openModal({ title = "", bodyHtml = "", footerHtml = "", dismissible = true, onMount, onClose } = {}) {
  const titleId = `modal-title-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const descId = bodyHtml ? `modal-desc-${Date.now()}-${Math.random().toString(36).slice(2, 7)}` : "";
  const prevFocused = getModalPreviousFocus(document.activeElement);
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="${titleId}"${descId ? ` aria-describedby="${descId}"` : ""} tabindex="-1">
      <div class="modal-head">
        <h3 id="${titleId}">${escapeModalHtml(title)}</h3>
        ${dismissible ? '<button class="close" aria-label="关闭">✕</button>' : ""}
      </div>
      <div class="modal-body"${descId ? ` id="${descId}"` : ""}>${bodyHtml}</div>
      ${footerHtml ? `<div class="modal-foot">${footerHtml}</div>` : ""}
    </div>`;
  document.body.appendChild(backdrop);

  let closed = false;
  const root = backdrop.querySelector(".modal");

  const close = (reason = "programmatic") => {
    if (closed) return;
    closed = true;
    document.removeEventListener("keydown", onKey);
    backdrop.classList.remove("show");
    setTimeout(() => {
      backdrop.remove();
      if (prevFocused?.isConnected) prevFocused.focus();
      onClose?.(reason);
    }, 280);
  };

  const onKey = (e) => {
    if (e.key === "Escape" && dismissible) {
      e.preventDefault();
      close("escape");
      return;
    }
    if (e.key !== "Tab") return;
    const focusables = getFocusable(root);
    if (!focusables.length) {
      e.preventDefault();
      root.focus();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  document.addEventListener("keydown", onKey);
  if (dismissible) {
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close("backdrop"); });
    backdrop.querySelector(".close")?.addEventListener("click", () => close("close-button"));
  }

  // animate in
  scheduleModalFrame(() => backdrop.classList.add("show"));

  if (typeof onMount === "function") onMount(root, close);
  scheduleModalFrame(() => {
    const focusables = getFocusable(root);
    const target = focusables[0] || root;
    target.focus();
  });

  return { close, root };
}

export function confirmDialog({ title = "确认", message = "", okText = "确认", cancelText = "取消", danger = false } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (value, doClose = true) => {
      if (settled) return;
      settled = true;
      if (doClose) close();
      resolve(value);
    };
    const { close } = openModal({
      title,
      bodyHtml: `<p style="margin:0; line-height:1.6; color:var(--fg-muted);">${escapeModalHtml(message)}</p>`,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">${escapeModalHtml(cancelText)}</button>
          <button class="btn ${danger ? "danger" : ""}" data-act="ok">${escapeModalHtml(okText)}</button>
        </div>`,
      onClose: () => settle(false, false),
      onMount: (r, doClose) => {
        r.querySelector('[data-act="ok"]').addEventListener("click", () => settle(true));
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => settle(false));
      }
    });
  });
}

export function promptDialog({ title = "输入", label = "", placeholder = "", initial = "", okText = "确认", type = "text", multiline = false } = {}) {
  return new Promise((resolve) => {
    const id = "_p_" + Date.now();
    const inputType = normalizePromptInputType(type);
    const inputHtml = multiline
      ? `<textarea id="${id}" class="input mono" placeholder="${escapeModalHtml(placeholder)}" style="min-height:120px;">${escapeModalHtml(initial)}</textarea>`
      : `<input id="${id}" class="input" type="${inputType}" placeholder="${escapeModalHtml(placeholder)}" value="${escapeModalHtml(initial)}" />`;
    let settled = false;
    const settle = (value, doClose = true) => {
      if (settled) return;
      settled = true;
      if (doClose) close();
      resolve(value);
    };
    const { close } = openModal({
      title,
      bodyHtml: `
        <div class="field">
          ${label ? `<label for="${id}">${escapeModalHtml(label)}</label>` : ""}
          ${inputHtml}
        </div>`,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">取消</button>
          <button class="btn" data-act="ok">${escapeModalHtml(okText)}</button>
        </div>`,
      onClose: () => settle(null, false),
      onMount: (r, doClose) => {
        const input = r.querySelector(multiline ? "textarea" : "input");
        input.focus();
        if (!multiline) {
          input.addEventListener("keydown", (e) => { if (e.key === "Enter") settle(input.value); });
        }
        r.querySelector('[data-act="ok"]').addEventListener("click", () => settle(input.value));
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => settle(null));
      }
    });
  });
}

export function actionSheet({ title = "", actions = [] } = {}) {
  // actions: [{ label, icon, danger, onClick }]
  return new Promise((resolve) => {
    const itemsHtml = actions.map((a, i) => `
      <button class="${a.danger ? "danger" : ""}" data-i="${i}">
        ${a.icon ? `<span>${a.icon}</span>` : ""}
        <span class="grow">${escapeModalHtml(a.label)}</span>
      </button>
    `).join("");
    let settled = false;
    const settle = (value, doClose = true) => {
      if (settled) return;
      settled = true;
      if (doClose) close();
      resolve(value);
    };
    const { close } = openModal({
      title,
      bodyHtml: `<div class="actionsheet">${itemsHtml}</div>`,
      onClose: () => settle(-1, false),
      onMount: (r, doClose) => {
        r.querySelectorAll("[data-i]").forEach(btn => {
          btn.addEventListener("click", async () => {
            const i = normalizeActionSheetIndex(btn.dataset.i, actions.length);
            doClose();
            if (i >= 0) {
              try { await actions[i].onClick?.(); } catch (e) { console.error(e); }
            }
            settle(i, false);
          });
        });
      }
    });
  });
}

export function normalizeActionSheetIndex(value, length) {
  const max = Math.trunc(Number(length));
  const index = Math.trunc(Number(value));
  if (!Number.isFinite(max) || max <= 0) return -1;
  if (!Number.isFinite(index) || index < 0 || index >= max) return -1;
  return index;
}

export function normalizePromptInputType(value) {
  const type = String(value || "text").trim().toLowerCase();
  const allowed = new Set(["text", "password", "email", "number", "search", "tel", "url"]);
  return allowed.has(type) ? type : "text";
}

export function getModalPreviousFocus(activeElement, ElementCtor = globalThis.HTMLElement) {
  if (typeof ElementCtor !== "function") return null;
  try {
    return activeElement instanceof ElementCtor ? activeElement : null;
  } catch {
    return null;
  }
}

function scheduleModalFrame(callback) {
  if (typeof requestAnimationFrame === "function") {
    return requestAnimationFrame(callback);
  }
  return setTimeout(callback, 0);
}

export function escapeModalHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
