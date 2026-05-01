// 集中的 Toast / 复制 / 通用辅助

let toastTimer = null;
let toastEl = null;

function ensureToast() {
  if (toastEl) return toastEl;
  toastEl = document.createElement("div");
  toastEl.className = "toast";
  toastEl.setAttribute("role", "status");
  toastEl.setAttribute("aria-live", "polite");
  document.body.appendChild(toastEl);
  return toastEl;
}

export function toast(msg, level = "ok", ms = 1800) {
  const el = ensureToast();
  const ico = level === "ok" ? "✓" : level === "warn" ? "⚠" : level === "err" ? "✕" : "";
  el.innerHTML = ico ? `<span class="ico">${ico}</span><span>${escapeHtml(msg)}</span>` : escapeHtml(msg);
  el.classList.remove("ok", "warn", "err");
  if (level) el.classList.add(level);
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), ms);
}

export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(String(text));
      return true;
    }
    throw new Error("no-clipboard");
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = String(text);
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      ta.style.pointerEvents = "none";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

export function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str ?? "");
  return div.innerHTML;
}

export function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function sanitizeFilePart(name) {
  return String(name || "part").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 64);
}
