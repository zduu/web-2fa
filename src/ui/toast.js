// 集中的 Toast / 复制 / 通用辅助
// toast(msg, level, ms, { action: { label, onClick } })

let toastTimer = null;
let toastEl = null;

function ensureToast() {
  if (
    typeof document === "undefined" ||
    typeof document.createElement !== "function" ||
    !document.body ||
    typeof document.body.appendChild !== "function"
  ) {
    return null;
  }
  if (toastEl) return toastEl;
  toastEl = document.createElement("div");
  toastEl.className = "toast";
  toastEl.setAttribute("role", "status");
  toastEl.setAttribute("aria-live", "polite");
  document.body.appendChild(toastEl);
  return toastEl;
}

export function toast(msg, level = "ok", ms = 1800, opts = {}) {
  const el = ensureToast();
  if (!el) return false;
  const ico = level === "ok" ? "✓" : level === "warn" ? "⚠" : level === "err" ? "✕" : "";
  const action = opts && opts.action;

  let html = "";
  if (ico) html += `<span class="ico">${ico}</span>`;
  html += `<span class="msg">${escapeHtml(msg)}</span>`;
  if (action && typeof action.label === "string") {
    html += `<button class="toast-action" type="button">${escapeHtml(action.label)}</button>`;
  }
  el.innerHTML = html;
  el.classList.remove("ok", "warn", "err");
  if (level) el.classList.add(level);
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), ms);

  if (action && typeof action.onClick === "function") {
    const btn = el.querySelector(".toast-action");
    btn?.addEventListener("click", (ev) => {
      ev.preventDefault();
      try { action.onClick(); } catch (e) { console.error(e); }
      if (toastTimer) clearTimeout(toastTimer);
      el.classList.remove("show");
    }, { once: true });
  }
  return true;
}

export async function copyText(text) {
  try {
    const clipboard = globalThis.navigator?.clipboard;
    const secure = !!globalThis.window?.isSecureContext;
    if (clipboard && secure && typeof clipboard.writeText === "function") {
      await clipboard.writeText(String(text));
      return true;
    }
    throw new Error("no-clipboard");
  } catch {
    let ta = null;
    try {
      if (typeof document === "undefined" || typeof document.createElement !== "function") return false;
      ta = document.createElement("textarea");
      ta.value = String(text);
      ta.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;padding:0;border:0;opacity:0;pointer-events:none;";
      ta.setAttribute("readonly", "");
      ta.setAttribute("aria-hidden", "true");
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      return !!document.execCommand("copy");
    } catch {
      return false;
    } finally {
      try { if (ta?.parentNode) ta.parentNode.removeChild(ta); }
      catch {}
    }
  }
}

export function escapeHtml(str) {
  if (typeof document === "undefined" || typeof document.createElement !== "function") {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  const div = document.createElement("div");
  div.textContent = String(str ?? "");
  return div.innerHTML;
}

export function downloadBlob(filename, blob) {
  if (typeof URL === "undefined" || typeof URL.createObjectURL !== "function") return false;
  if (typeof document === "undefined" || typeof document.createElement !== "function") return false;
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    return true;
  } catch {
    return false;
  } finally {
    try { URL.revokeObjectURL(url); } catch {}
  }
}

export function sanitizeFilePart(name) {
  const cleaned = String(name || "")
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .slice(0, 64);
  return /[A-Za-z0-9]/.test(cleaned) ? cleaned : "part";
}
