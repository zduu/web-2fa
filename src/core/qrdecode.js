// 统一二维码解码入口：优先使用浏览器原生 BarcodeDetector，
// 不可用时回退到本地 vendored 的 jsQR（按需加载）。

let _jsqrPromise = null;
function loadJsQR() {
  if (!_jsqrPromise) {
    _jsqrPromise = import("./qrdecode-vendor.js").then((m) => m.default);
  }
  return _jsqrPromise;
}

/**
 * 检查是否有任何可用的 QR 解码后端（原生或 fallback）。
 * 因为 jsQR 是 vendored 的，理论上一直可用，所以这里返回 true。
 */
export function isQrDecodeSupported() {
  return true;
}

/**
 * 是否能从摄像头实时识别（依赖 BarcodeDetector）。
 * jsQR fallback 也能扫描摄像头，但帧解码慢，先保留原生路径。
 */
export function isLiveScanSupported() {
  return typeof window !== "undefined" && "BarcodeDetector" in window;
}

/**
 * 从 ImageBitmap / HTMLVideoElement / HTMLCanvasElement 等可绘制源中识别二维码。
 * 返回首个识别到的字符串；找不到时返回 null。
 */
export async function decodeQrFromSource(source) {
  if (!source) return null;
  // 1) 尝试原生 BarcodeDetector
  if (typeof window !== "undefined" && "BarcodeDetector" in window) {
    try {
      const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
      const r = await detector.detect(source);
      if (r && r.length) return r[0]?.rawValue || null;
    } catch {
      // fallthrough to jsQR
    }
  }
  // 2) jsQR fallback —— 通过 canvas 取像素
  const { width, height, data } = await sourceToImageData(source);
  if (!width || !height) return null;
  const jsQR = await loadJsQR();
  if (!jsQR) return null;
  const result = jsQR(data, width, height, { inversionAttempts: "attemptBoth" });
  return result?.data || null;
}

/**
 * 从用户上传的图片 File / Blob 解码二维码。
 */
export async function decodeQrFromFile(file) {
  if (!file) return null;
  let bitmap = null;
  try {
    if (typeof createImageBitmap === "function") {
      bitmap = await createImageBitmap(file);
    }
  } catch {
    bitmap = null;
  }
  if (bitmap) {
    try {
      return await decodeQrFromSource(bitmap);
    } finally {
      try { bitmap.close?.(); } catch {}
    }
  }
  // 退回：用 <img> 加载
  const url = URL.createObjectURL(file);
  try {
    const img = await loadHtmlImage(url);
    return await decodeQrFromSource(img);
  } finally {
    URL.revokeObjectURL(url);
  }
}

function loadHtmlImage(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = (e) => reject(e || new Error("image-load-failed"));
    img.src = src;
  });
}

async function sourceToImageData(source) {
  // HTMLImageElement / HTMLCanvasElement / HTMLVideoElement / ImageBitmap
  let width = source.naturalWidth || source.videoWidth || source.width || 0;
  let height = source.naturalHeight || source.videoHeight || source.height || 0;
  if (!width || !height) return { width: 0, height: 0, data: null };
  // 限制最大尺寸，避免超大图片导致内存爆掉
  const MAX = 1600;
  let drawW = width, drawH = height;
  if (width > MAX || height > MAX) {
    const scale = Math.min(MAX / width, MAX / height);
    drawW = Math.max(1, Math.floor(width * scale));
    drawH = Math.max(1, Math.floor(height * scale));
  }
  const canvas = (typeof OffscreenCanvas === "function")
    ? new OffscreenCanvas(drawW, drawH)
    : Object.assign(document.createElement("canvas"), { width: drawW, height: drawH });
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return { width: 0, height: 0, data: null };
  ctx.drawImage(source, 0, 0, drawW, drawH);
  const imgData = ctx.getImageData(0, 0, drawW, drawH);
  return { width: drawW, height: drawH, data: imgData.data };
}
