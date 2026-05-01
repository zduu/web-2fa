// 二维码扫描：摄像头 + 图片文件
// 摄像头：浏览器原生 BarcodeDetector
// 图片：原生不可用时回退到 vendored 的 jsQR

import { parseOtpAuth, parseOtpAuthMigration } from "../core/totp.js";
import { toast } from "./toast.js";
import {
  decodeQrFromFile,
  decodeQrFromSource,
  isLiveScanSupported,
} from "../core/qrdecode.js";

let mediaStream = null;
let scanTimer = null;

export function attachScanner(rootEl, doCloseModal, onResult) {
  const video = rootEl.querySelector("#scan-video");
  const fileInput = rootEl.querySelector("#scan-file");
  const startBtn = rootEl.querySelector("#scan-start");
  const stopBtn = rootEl.querySelector("#scan-stop");
  const hint = rootEl.querySelector("#scan-hint");

  const liveSupported = isLiveScanSupported();
  if (!liveSupported) {
    hint.textContent = "当前浏览器不支持原生实时识别，可使用 “选择图片” 上传截图或用 “从链接” 标签粘贴 otpauth。";
    if (startBtn) startBtn.disabled = true;
  }

  async function start() {
    if (!liveSupported) return;
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" }, audio: false
      });
      video.srcObject = mediaStream;
      await video.play();
      hint.textContent = "对准二维码，自动识别...";
      scanTimer = setInterval(async () => {
        try {
          const r = await detector.detect(video);
          if (r && r.length) {
            const txt = r[0]?.rawValue || "";
            if (handleResult(txt)) stop();
          }
        } catch {}
      }, 250);
    } catch (e) {
      console.error(e);
      hint.textContent = "无法访问摄像头：" + (e.message || "权限被拒绝");
    }
  }

  function stop() {
    if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
    try { video.pause(); } catch {}
    if (video) video.srcObject = null;
    if (mediaStream) {
      mediaStream.getTracks().forEach(t => t.stop());
      mediaStream = null;
    }
  }

  function handleResult(txt) {
    if (!txt) return false;
    if (txt.startsWith("otpauth-migration://")) {
      const items = parseOtpAuthMigration(txt);
      if (!items.length) { toast("未解析到迁移数据", "err"); return false; }
      onResult(items);
      doCloseModal();
      return true;
    }
    if (txt.startsWith("otpauth://")) {
      const item = parseOtpAuth(txt);
      if (!item || !item.secret) { toast("无效的 otpauth 链接", "err"); return false; }
      onResult([item]);
      doCloseModal();
      return true;
    }
    toast("不是 otpauth 二维码", "warn");
    return false;
  }

  async function fromImage(file) {
    try {
      const txt = await decodeQrFromFile(file);
      if (!txt) {
        toast("图片中未识别到二维码", "warn");
        return;
      }
      if (!handleResult(txt)) {
        // handleResult 已经在内部抛出错误提示
      }
    } catch (e) {
      console.error(e);
      toast("识别失败，请换一张更清晰的截图，或改用 “从链接” 粘贴", "err", 3200);
    }
  }

  startBtn?.addEventListener("click", start);
  stopBtn?.addEventListener("click", stop);
  fileInput?.addEventListener("change", (e) => {
    const f = e.target.files?.[0];
    if (f) fromImage(f);
    // 允许重复选择同一文件
    try { e.target.value = ""; } catch {}
  });

  // 仅当原生实时扫描可用时自动启动摄像头
  if (liveSupported) start();

  // cleanup when host element leaves the DOM
  const cleanup = () => stop();
  if (typeof window.ResizeObserver === "function") {
    // Use a single requestAnimationFrame loop to detect detach without observing the whole body subtree
    const check = () => {
      if (!document.body.contains(rootEl)) { cleanup(); return; }
      requestAnimationFrame(check);
    };
    requestAnimationFrame(check);
  } else {
    const obs = new MutationObserver(() => {
      if (!document.body.contains(rootEl)) { cleanup(); obs.disconnect(); }
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }
}

// 暴露给单元测试（视频/Canvas 源都可用）
export { decodeQrFromSource };
