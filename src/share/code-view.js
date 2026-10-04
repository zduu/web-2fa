import { apiUrl } from "../core/runtime.js";
import { formatCode } from "../core/totp.js";

// Only the server sees the OTP Secret. Fetch a new code when the current one ends.
export function startCodeShareView(sid, codeKey) {
  let expiresAt = 0;
  let period = 30;
  let retryAt = 0;
  let fetching = false;
  let stopped = false;
  let canRefresh = true;
  let controller = null;
  let requestTimeout = null;
  const element = (id) => document.getElementById(id);
  const setLabel = (text) => { if (element("lbl")) element("lbl").textContent = text; };
  const setCode = (text) => { if (element("code")) element("code").textContent = text; };
  const setNote = (text) => {
    const note = element("note");
    if (note) { note.textContent = text; note.style.display = ""; }
  };
  setLabel("加载中…");
  // Safe mode must not display any Secret left by another view.
  const secretPanel = element("secret-panel");
  if (secretPanel) secretPanel.style.display = "none";
  if (element("secret-value")) element("secret-value").value = "";

  function dispose() {
    stopped = true;
    clearInterval(ticker);
    clearTimeout(requestTimeout);
    controller?.abort();
    document.removeEventListener("visibilitychange", onVisibilityChange);
    window.removeEventListener("beforeunload", dispose);
  }

  function finish(label, code = "已失效") {
    dispose();
    setLabel(label);
    setCode(code);
    setNote("分享已失效，请联系分享方重新生成链接。");
  }

  async function refreshCode() {
    if (stopped || fetching) return;
    fetching = true;
    const requestedAt = Date.now();
    controller = new AbortController();
    const requestController = controller;
    requestTimeout = setTimeout(() => requestController.abort(), 15_000);
    try {
      const response = await fetch(apiUrl(`/api/share-code/${encodeURIComponent(sid)}`), {
        headers: { "X-Share-Code-Key": codeKey },
        cache: "no-store",
        signal: controller.signal,
      });
      if (stopped) return;
      if (response.status === 404 || response.status === 410) {
        finish(response.headers.get("X-Share-Reason") === "max-access-exceeded"
          ? "分享已达访问上限" : "分享不存在或已过期");
        return;
      }
      if (!response.ok) throw new Error("share-code-unavailable");
      const data = await response.json();
      if (stopped) return;
      if (!/^\d{4,10}$/.test(String(data.code || ""))) throw new Error("invalid-code");
      const validForMs = Number.isFinite(data.validForMs)
        ? data.validForMs : Number(data.secondsLeft) * 1000;
      // Start at request time: network delay must not extend a code's lifetime.
      expiresAt = requestedAt + Math.max(0, validForMs);
      canRefresh = response.headers.get("X-Access-Remaining") !== "0";
      if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
        if (!canRefresh) { finish("分享已达访问上限", "已过期"); return; }
        throw new Error("expired-code");
      }
      period = Math.max(5, Number(data.period) || 30);
      retryAt = 0;
      setLabel(data.label || "共享验证码");
      setCode(formatCode(String(data.code), data.digits));
      if (element("algo")) element("algo").textContent = `${data.algorithm} · ${data.digits}位 · ${period}s`;
      if (element("period-info")) {
        const remaining = response.headers.get("X-Access-Remaining");
        element("period-info").textContent = `${period}s${remaining && remaining !== "unlimited" ? ` · 剩余 ${remaining} 次取码` : ""}`;
      }
      const subtitle = document.querySelector(".share-head .sub");
      if (subtitle) subtitle.textContent = "安全模式 · 自动更新验证码 · 不含 Secret";
      setNote(typeof data.note === "string" && data.note.trim()
        ? data.note : "分享有效期内自动更新验证码，接收方无法获取 Secret。");
      renderCountdown();
    } catch (error) {
      if (stopped) return;
      setLabel("暂时无法获取验证码");
      setCode("正在重试…");
      setNote("连接暂时不可用，将自动重试。");
      retryAt = Date.now() + (error?.message === "expired-code" ? 1000 : 5000);
    } finally {
      clearTimeout(requestTimeout);
      requestTimeout = null;
      fetching = false;
    }
  }

  function renderCountdown() {
    if (stopped) return;
    const left = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    const leftElement = document.querySelector(".left");
    if (leftElement) leftElement.textContent = String(left);
    const bar = document.querySelector(".bar");
    if (bar) {
      bar.style.width = `${Math.min(100, left / period * 100)}%`;
      bar.style.background = left <= 5
        ? "linear-gradient(90deg, #ef4444, #f59e0b)"
        : left <= 10 ? "linear-gradient(90deg, #f59e0b, #fbbf24)"
          : "linear-gradient(90deg, var(--ok), var(--primary))";
    }
    if (left <= 0 && expiresAt) {
      if (!canRefresh) { finish("分享已达访问上限", "已过期"); return; }
      if (!retryAt) setCode("刷新中…");
    }
    if (left <= 0 && Date.now() >= retryAt && document.visibilityState !== "hidden") {
      void refreshCode();
    }
  }

  function onVisibilityChange() {
    if (document.visibilityState === "visible") renderCountdown();
  }

  const ticker = setInterval(renderCountdown, 1000);
  document.addEventListener("visibilitychange", onVisibilityChange);
  window.addEventListener("beforeunload", dispose);
  void refreshCode();
  return dispose;
}
