// 模态框工厂：openModal({ title, body, actions, dismissible })
// 返回 { close, root }

export function openModal({ title = "", bodyHtml = "", footerHtml = "", dismissible = true, onMount } = {}) {
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true">
      <div class="modal-head">
        <h3>${escape(title)}</h3>
        ${dismissible ? '<button class="close" aria-label="关闭">✕</button>' : ""}
      </div>
      <div class="modal-body">${bodyHtml}</div>
      ${footerHtml ? `<div class="modal-foot">${footerHtml}</div>` : ""}
    </div>`;
  document.body.appendChild(backdrop);

  let closed = false;
  const close = () => {
    if (closed) return; closed = true;
    backdrop.classList.remove("show");
    setTimeout(() => backdrop.remove(), 280);
  };

  const onKey = (e) => { if (e.key === "Escape" && dismissible) close(); };

  if (dismissible) {
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
    backdrop.querySelector(".close")?.addEventListener("click", close);
    document.addEventListener("keydown", onKey, { once: false });
  }

  // animate in
  requestAnimationFrame(() => backdrop.classList.add("show"));

  const root = backdrop.querySelector(".modal");
  if (typeof onMount === "function") onMount(root, close);

  // intercept close to also remove keydown listener
  const origClose = close;
  const wrappedClose = () => {
    document.removeEventListener("keydown", onKey);
    origClose();
  };
  return { close: wrappedClose, root };
}

export function confirmDialog({ title = "确认", message = "", okText = "确认", cancelText = "取消", danger = false } = {}) {
  return new Promise((resolve) => {
    const { close, root } = openModal({
      title,
      bodyHtml: `<p style="margin:0; line-height:1.6; color:var(--fg-muted);">${escape(message)}</p>`,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">${escape(cancelText)}</button>
          <button class="btn ${danger ? "danger" : ""}" data-act="ok">${escape(okText)}</button>
        </div>`,
      onMount: (r, doClose) => {
        r.querySelector('[data-act="ok"]').addEventListener("click", () => { doClose(); resolve(true); });
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => { doClose(); resolve(false); });
      }
    });
    // close on backdrop also resolves false
    root.parentElement.addEventListener("click", (e) => {
      if (e.target === root.parentElement) resolve(false);
    });
  });
}

export function promptDialog({ title = "输入", label = "", placeholder = "", initial = "", okText = "确认", type = "text", multiline = false } = {}) {
  return new Promise((resolve) => {
    const id = "_p_" + Date.now();
    const inputHtml = multiline
      ? `<textarea id="${id}" class="input mono" placeholder="${escape(placeholder)}" style="min-height:120px;">${escape(initial)}</textarea>`
      : `<input id="${id}" class="input" type="${type}" placeholder="${escape(placeholder)}" value="${escape(initial)}" />`;
    const { close, root } = openModal({
      title,
      bodyHtml: `
        <div class="field">
          ${label ? `<label for="${id}">${escape(label)}</label>` : ""}
          ${inputHtml}
        </div>`,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">取消</button>
          <button class="btn" data-act="ok">${escape(okText)}</button>
        </div>`,
      onMount: (r, doClose) => {
        const input = r.querySelector(multiline ? "textarea" : "input");
        input.focus();
        if (!multiline) {
          input.addEventListener("keydown", (e) => { if (e.key === "Enter") { doClose(); resolve(input.value); } });
        }
        r.querySelector('[data-act="ok"]').addEventListener("click", () => { doClose(); resolve(input.value); });
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => { doClose(); resolve(null); });
      }
    });
    root.parentElement.addEventListener("click", (e) => {
      if (e.target === root.parentElement) resolve(null);
    });
  });
}

export function actionSheet({ title = "", actions = [] } = {}) {
  // actions: [{ label, icon, danger, onClick }]
  return new Promise((resolve) => {
    const itemsHtml = actions.map((a, i) => `
      <button class="${a.danger ? "danger" : ""}" data-i="${i}">
        ${a.icon ? `<span>${a.icon}</span>` : ""}
        <span class="grow">${escape(a.label)}</span>
      </button>
    `).join("");
    const { close, root } = openModal({
      title,
      bodyHtml: `<div class="actionsheet">${itemsHtml}</div>`,
      onMount: (r, doClose) => {
        r.querySelectorAll("[data-i]").forEach(btn => {
          btn.addEventListener("click", async () => {
            const i = Number(btn.dataset.i);
            doClose();
            try { await actions[i].onClick?.(); } catch (e) { console.error(e); }
            resolve(i);
          });
        });
      }
    });
    root.parentElement.addEventListener("click", (e) => {
      if (e.target === root.parentElement) resolve(-1);
    });
  });
}

function escape(s) {
  const div = document.createElement("div");
  div.textContent = String(s ?? "");
  return div.innerHTML;
}
