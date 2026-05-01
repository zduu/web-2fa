// 二维码扫描：摄像头 + 图片文件
// 使用浏览器原生 BarcodeDetector

import { parseOtpAuth, parseOtpAuthMigration } from "../core/totp.js";
import { toast } from "./toast.js";

let mediaStream = null;
let scanTimer = null;

export function attachScanner(rootEl, doCloseModal, onResult) {
  const video = rootEl.querySelector("#scan-video");
  const fileInput = rootEl.querySelector("#scan-file");
  const startBtn = rootEl.querySelector("#scan-start");
  const stopBtn = rootEl.querySelector("#scan-stop");
  const hint = rootEl.querySelector("#scan-hint");

  const supported = "BarcodeDetector" in window;
  if (!supported) {
    hint.textContent = "当前浏览器不支持原生二维码识别，请使用 “选择图片” 或 “从链接” 标签。";
    startBtn.disabled = true;
  }

  async function start() {
    if (!supported) return;
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
    if (!supported) {
      toast("浏览器不支持原生识别，请改用 “从链接” 粘贴 otpauth", "warn");
      return;
    }
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const img = await createImageBitmap(file);
      const r = await detector.detect(img);
      if (r && r.length) {
        if (!handleResult(r[0]?.rawValue || "")) {
          // not handled but show hint
        }
      } else {
        toast("图片中未识别到二维码", "warn");
      }
    } catch (e) {
      console.error(e);
      toast("识别失败", "err");
    }
  }

  startBtn?.addEventListener("click", start);
  stopBtn?.addEventListener("click", stop);
  fileInput?.addEventListener("change", (e) => {
    const f = e.target.files?.[0];
    if (f) fromImage(f);
  });

  // auto start when supported
  if (supported) start();

  // cleanup on modal close
  const cleanup = () => stop();
  // Observe DOM removal for cleanup
  const obs = new MutationObserver(() => {
    if (!document.body.contains(rootEl)) { cleanup(); obs.disconnect(); }
  });
  obs.observe(document.body, { childList: true, subtree: true });
}
