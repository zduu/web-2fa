// 共享验证码查看页：从 URL fragment 取密钥 → 拉取密文 → 解密 → 持续渲染
// 复用 src/core/totp.js 的算法实现，避免与主端不一致

import { totp, secondsLeft, formatCode } from "./src/core/totp.js";
import { fromB64url } from "./src/core/crypto.js";
import { unwrapShareKeyWithPassword } from "./src/core/share-password.js";
import { initTheme } from "./src/ui/theme.js";
import { apiUrl, isLocalOnlyApp } from "./src/core/runtime.js";

async function decryptPayload(payload, keyB64url) {
  const iv = fromB64url(payload.iv);
  const ct = fromB64url(payload.ct);
  const raw = fromB64url(keyB64url);
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function main() {
  initTheme();
  if (isLocalOnlyApp()) {
    setLabel("本地 APK 版不支持云分享页");
    return;
  }
  const params = new URLSearchParams(location.search);
  const sid = params.get("sid");
  const frag = new URL(location.href).hash.replace(/^#/, "");
  const fragParams = new URLSearchParams(frag);
  const kParam = fragParams.get("k");
  const wrappedKey = fragParams.get("wk")
    ? {
        wk: fragParams.get("wk"),
        iv: fragParams.get("iv"),
        s: fragParams.get("s"),
        iter: Number(fragParams.get("iter") || 0) || undefined,
      }
    : null;
  if (!sid || (!kParam && !wrappedKey)) { setLabel("缺少参数"); return; }

  const res = await fetch(apiUrl(`/api/share/${encodeURIComponent(sid)}`));
  if (res.status === 410) { setLabel("分享已达访问上限，已失效"); return; }
  if (res.status === 404) { setLabel("分享不存在或已过期"); return; }
  if (!res.ok) { setLabel("分享不存在或已过期"); return; }
  const remaining = res.headers.get("X-Access-Remaining");
  let payload;
  try { payload = await res.json(); } catch { setLabel("数据错误"); return; }

  if (wrappedKey) {
    showPasswordGate(payload, wrappedKey, remaining);
    return;
  }

  let data;
  try { data = await decryptPayload(payload, kParam); } catch { setLabel("解密失败"); return; }
  startShareView(data, remaining);
}

function setLabel(t) { const el = document.getElementById("lbl"); if (el) el.textContent = t; }

function showPasswordGate(payload, wrappedKey, remaining) {
  const gate = document.getElementById("password-gate");
  const content = document.getElementById("share-content");
  const input = document.getElementById("share-pass");
  const button = document.getElementById("unlock-share");
  if (gate) gate.style.display = "";
  if (content) content.style.display = "none";
  setLabel("需要访问口令");
  const unlock = async () => {
    const password = input?.value || "";
    if (!password.trim()) {
      toast("请输入访问口令", "warn");
      input?.focus();
      return;
    }
    if (button) button.disabled = true;
    try {
      const raw = await unwrapShareKeyWithPassword(wrappedKey, password);
      const data = await decryptPayload(payload, toB64url(raw));
      if (gate) gate.style.display = "none";
      if (content) content.style.display = "";
      if (input) input.value = "";
      startShareView(data, remaining);
      toast("已解锁分享", "ok");
    } catch {
      toast("口令错误或链接损坏", "err");
      input?.focus();
      input?.select?.();
    } finally {
      if (button) button.disabled = false;
    }
  };
  button?.addEventListener("click", unlock);
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") unlock();
  });
  input?.focus();
}

function startShareView(data, remaining) {
  const label = data.label || "共享验证码";
  setLabel(label);
  document.getElementById("algo").textContent = `${(data.algorithm || "SHA1").toUpperCase()} · ${data.digits || 6}位 · ${data.period || 30}s`;
  const periodInfo = document.getElementById("period-info");
  if (periodInfo) periodInfo.textContent = `周期 ${data.period || 30}s`;
  if (typeof data.note === "string" && data.note.trim()) {
    const noteEl = document.getElementById("note");
    if (noteEl) {
      noteEl.textContent = data.note;
      noteEl.style.display = "";
    }
  }
  if (remaining && remaining !== "∞") {
    const periodInfo2 = document.getElementById("period-info");
    if (periodInfo2) periodInfo2.textContent = `${periodInfo2.textContent} · 剩余 ${remaining} 次访问`;
  }

  async function renderOnce() {
    try {
      const code = await totp(data.secret, data);
      document.getElementById("code").textContent = formatCode(code, data.digits);
    } catch {
      document.getElementById("code").textContent = "ERR";
    }
    const left = secondsLeft(data.period);
    document.querySelector(".left").textContent = String(left);
    const pct = (left / Math.max(5, data.period || 30)) * 100;
    const bar = document.querySelector(".bar");
    if (bar) {
      bar.style.width = pct + "%";
      bar.style.background = left <= 5
        ? "linear-gradient(90deg, #ef4444, #f59e0b)"
        : left <= 10
          ? "linear-gradient(90deg, #f59e0b, #fbbf24)"
          : "linear-gradient(90deg, var(--ok), var(--primary))";
    }
  }
  renderOnce();
  const ticker = setInterval(renderOnce, 1000);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") renderOnce();
  });
  window.addEventListener("beforeunload", () => clearInterval(ticker));

  document.getElementById("copy").addEventListener("click", async () => {
    const shown = document.getElementById("code")?.textContent?.replace(/\s+/g, "") || "";
    if (!shown || shown === "ERR") { toast("验证码尚未就绪", "warn"); return; }
    const ok = await copyText(shown);
    toast(ok ? "已复制验证码" : "复制失败", ok ? "ok" : "err");
  }, { once: true });
  document.getElementById("copy-link")?.addEventListener("click", async () => {
    const ok = await copyText(location.href);
    toast(ok ? "已复制链接" : "复制失败", ok ? "ok" : "err");
  }, { once: true });
}

function toB64url(bytes) {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

main();

let toastTimer = null;
function toast(msg, level = "ok") {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("ok", "warn", "err");
  if (level) el.classList.add(level);
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 1800);
}

async function copyText(text) {
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
      ta.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;padding:0;border:0;opacity:0;pointer-events:none;";
      ta.setAttribute("readonly", "");
      ta.setAttribute("aria-hidden", "true");
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}
