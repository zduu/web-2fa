// 共享验证码查看页
// 安全模式（默认，#ck=）：服务端解密+计算验证码，接收方拿不到 secret
// 完整模式（#k=）：客户端解密，接收方能拿到完整 secret

import { totp, secondsLeft, formatCode } from "./src/core/totp.js";
import { fromB64url } from "./src/core/crypto.js";
import { unwrapShareKeyWithPassword } from "./src/core/share-password.js";
import { initTheme } from "./src/ui/theme.js";
import { apiUrl, isLocalOnlyApp } from "./src/core/runtime.js";

// 客户端解密（完整模式用）
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

  // 安全模式：#ck=codeKey（默认，接收方拿不到 secret）
  const codeKey = fragParams.get("ck");
  // 完整模式：#k=key（旧链接，接收方能拿到 secret）
  const kParam = fragParams.get("k");
  // 口令保护
  const wrappedKey = fragParams.get("wk")
    ? {
        wk: fragParams.get("wk"),
        iv: fragParams.get("iv"),
        s: fragParams.get("s"),
        iter: Number(fragParams.get("iter") || 0) || undefined,
      }
    : null;

  if (!sid) { setLabel("缺少参数"); return; }

  // 安全模式：服务端计算，不需要本地密钥
  if (codeKey) {
    startCodeModeView(sid, codeKey);
    return;
  }

  if (kParam || wrappedKey) {
    startLegacyModeView(sid, kParam, wrappedKey);
    return;
  }

  setLabel("链接不完整，缺少密钥参数");
}

// ---- 安全模式（服务端计算验证码）----
function startCodeModeView(sid, codeKey) {
  setLabel("加载中…");
  let ticker = null;
  let expiresAt = 0;

  async function fetchCode() {
    try {
      const res = await fetch(apiUrl(`/api/share-code/${encodeURIComponent(sid)}?k=${encodeURIComponent(codeKey)}`));
      if (res.status === 410) { stopTicker(); setLabel("分享已失效"); return null; }
      if (res.status === 404) { stopTicker(); setLabel("分享不存在或已过期"); return null; }
      if (!res.ok) { stopTicker(); setLabel("加载失败"); return null; }
      const data = await res.json();
      return data;
    } catch {
      return null;
    }
  }

  function stopTicker() {
    if (ticker) { clearInterval(ticker); ticker = null; }
  }

  function renderCountdown() {
    const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    const leftEl = document.querySelector(".left");
    if (leftEl) leftEl.textContent = String(left);
    const periodText = document.getElementById("algo")?.textContent || "";
    const periodMatch = periodText.match(/(\d+)s$/);
    const period = periodMatch ? Number(periodMatch[1]) : 30;
    const pct = (left / Math.max(1, period)) * 100;
    const bar = document.querySelector(".bar");
    if (bar) {
      bar.style.width = pct + "%";
      bar.style.background = left <= 5
        ? "linear-gradient(90deg, #ef4444, #f59e0b)"
        : left <= 10
          ? "linear-gradient(90deg, #f59e0b, #fbbf24)"
          : "linear-gradient(90deg, var(--ok), var(--primary))";
    }
    if (left <= 0) {
      stopTicker();
      const codeEl = document.getElementById("code");
      if (codeEl) codeEl.textContent = "已过期";
      const note = document.getElementById("note");
      if (note) {
        note.textContent = "此验证码已过期。安全模式不会继续生成后续验证码，请让分享方重新生成链接。";
        note.style.display = "";
      }
    }
  }

  async function renderInitial() {
    const data = await fetchCode();
    if (!data) return;
    setLabel(data.label || "共享验证码");
    document.getElementById("code").textContent = formatCode(data.code, data.digits);
    const algoEl = document.getElementById("algo");
    if (algoEl) algoEl.textContent = `${data.algorithm} · ${data.digits}位 · ${data.period}s`;
    const periodInfo = document.getElementById("period-info");
    if (periodInfo) periodInfo.textContent = `周期 ${data.period}s`;
    // Update subtitle to indicate safe mode
    const subEl = document.querySelector(".share-head .sub");
    if (subEl) subEl.textContent = "安全模式 · 仅展示验证码，不含 Secret";
    expiresAt = Date.now() + Math.max(0, Number(data.secondsLeft) || 0) * 1000;
    const note = document.getElementById("note");
    if (note) {
      note.textContent = typeof data.note === "string" && data.note.trim()
        ? data.note
        : "安全模式：仅展示当前验证码，接收方无法获取密钥，也不会继续生成后续验证码。";
      note.style.display = "";
    }
    renderCountdown();
    ticker = setInterval(renderCountdown, 1000);
  }

  renderInitial();
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && expiresAt) renderCountdown();
  });
  window.addEventListener("beforeunload", () => stopTicker());

  bindCopyActions();
}

// ---- 完整模式（客户端解密，旧链接兼容）----
function startLegacyModeView(sid, kParam, wrappedKey) {
  const frag = new URL(location.href).hash.replace(/^#/, "");
  const fragParams = new URLSearchParams(frag);
  const isCodeMode = fragParams.get("cm") === "1";
  if (wrappedKey && isCodeMode) {
    showPasswordGate(null, wrappedKey, null);
    return;
  }

  (async () => {
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
    startLegacyShareView(data, remaining);
  })();
}

function showPasswordGate(payload, wrappedKey, remaining) {
  const gate = document.getElementById("password-gate");
  const content = document.getElementById("share-content");
  const input = document.getElementById("share-pass");
  const button = document.getElementById("unlock-share");
  if (gate) gate.style.display = "";
  if (content) content.style.display = "none";
  setLabel("需要访问口令");

  // 用 cm=1 片段标记区分安全模式+口令 vs 完整模式+口令
  const frag = new URL(location.href).hash.replace(/^#/, "");
  const fragParams = new URLSearchParams(frag);
  const codeKey = fragParams.get("ck");
  const kParam = fragParams.get("k");
  const isCodeMode = fragParams.get("cm") === "1" || !!codeKey;
  const sid = new URLSearchParams(location.search).get("sid");

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
      const keyB64 = toB64url(raw);

      if (gate) gate.style.display = "none";
      if (content) content.style.display = "";
      if (input) input.value = "";

      if (isCodeMode) {
        startCodeModeView(sid, keyB64);
      } else {
        const data = await decryptPayload(payload, keyB64);
        startLegacyShareView(data, remaining);
      }
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

function startLegacyShareView(data, remaining) {
  const label = data.label || "共享验证码";
  setLabel(label);
  document.getElementById("algo").textContent = `${(data.algorithm || "SHA1").toUpperCase()} · ${data.digits || 6}位 · ${data.period || 30}s`;
  const periodInfo = document.getElementById("period-info");
  if (periodInfo) periodInfo.textContent = `周期 ${data.period || 30}s`;
  const subEl = document.querySelector(".share-head .sub");
  if (subEl) subEl.textContent = "完整模式 · 含 Secret · 可导入验证器";
  const secretPanel = document.getElementById("secret-panel");
  const secretInput = document.getElementById("secret-value");
  if (secretPanel && secretInput) {
    secretInput.value = String(data.secret || "");
    secretPanel.style.display = secretInput.value ? "" : "none";
  }
  if (typeof data.note === "string" && data.note.trim()) {
    const noteEl = document.getElementById("note");
    if (noteEl) {
      noteEl.textContent = data.note;
      noteEl.style.display = "";
    }
  }
  if (remaining && remaining !== "unlimited") {
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

  bindCopyActions();
}

function bindCopyActions() {
  document.getElementById("copy")?.addEventListener("click", async () => {
    const shown = document.getElementById("code")?.textContent?.replace(/\s+/g, "") || "";
    if (!/^\d{4,10}$/.test(shown)) { toast("验证码尚未就绪或已过期", "warn"); return; }
    const ok = await copyText(shown);
    toast(ok ? "已复制验证码" : "复制失败", ok ? "ok" : "err");
  });
  document.getElementById("copy-secret")?.addEventListener("click", async () => {
    const secret = document.getElementById("secret-value")?.value?.trim() || "";
    if (!secret) { toast("Secret 不可用", "warn"); return; }
    const ok = await copyText(secret);
    toast(ok ? "已复制 Secret" : "复制失败", ok ? "ok" : "err");
  });
  document.getElementById("copy-link")?.addEventListener("click", async () => {
    const ok = await copyText(location.href);
    toast(ok ? "已复制链接" : "复制失败", ok ? "ok" : "err");
  });
}

function setLabel(t) { const el = document.getElementById("lbl"); if (el) el.textContent = t; }

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
