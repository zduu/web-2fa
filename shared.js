// Minimal shared code viewer: decrypts data client-side and displays TOTP

function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4; if (pad) s += "===".slice(pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function toB64(arr) { return btoa(String.fromCharCode.apply(null, Array.from(arr))); }
function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = (input || "").toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0, value = 0; const out = [];
  for (const c of clean) {
    const idx = alphabet.indexOf(c); if (idx === -1) continue;
    value = (value << 5) | idx; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function hotp(secretBytes, counter, algo = "SHA-1", digits = 6) {
  const counterBuf = new ArrayBuffer(8); const view = new DataView(counterBuf);
  const hi = Math.floor(counter / 2 ** 32); const lo = counter >>> 0; view.setUint32(0, hi); view.setUint32(4, lo);
  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: { name: algo } }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuf));
  const offset = sig[sig.length - 1] & 0xf;
  const code = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  const mod = 10 ** digits; return (code % mod).toString().padStart(digits, "0");
}
async function totpB32(secretBase32, { algorithm = "SHA1", digits = 6, period = 30 } = {}) {
  const algo = algorithm.toUpperCase(); const hash = algo === "SHA256" ? "SHA-256" : algo === "SHA512" ? "SHA-512" : "SHA-1";
  const step = Math.max(5, Number(period) || 30);
  const counter = Math.floor(Date.now() / 1000 / step);
  const secretBytes = base32Decode(secretBase32);
  return hotp(secretBytes, counter, hash, Number(digits) || 6);
}
function secondsLeft(period = 30) { const step = Math.max(5, Number(period) || 30); const s = Math.floor(Date.now() / 1000); return step - (s % step); }
function formatCode(s, digits) { s = String(s || ""); if ((digits || s.length) >= 8 && s.length >= 8) return s.slice(0,4)+" "+s.slice(4,8); if (s.length>=6) return s.slice(0,3)+" "+s.slice(3,6); return s; }

async function decryptPayload(payload, keyB64url) {
  const iv = fromB64url(payload.iv); const ct = fromB64url(payload.ct);
  const raw = fromB64url(keyB64url);
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function main() {
  const params = new URLSearchParams(location.search);
  const sid = params.get('sid');
  const frag = new URL(location.href).hash.replace(/^#/, '');
  const kParam = new URLSearchParams(frag).get('k');
  if (!sid || !kParam) { document.getElementById('lbl').textContent = '缺少参数'; return; }
  const res = await fetch(`/api/share/${encodeURIComponent(sid)}`);
  if (!res.ok) { document.getElementById('lbl').textContent = '分享不存在或已过期'; return; }
  let payload; try { payload = await res.json(); } catch { document.getElementById('lbl').textContent = '数据错误'; return; }
  let data; try { data = await decryptPayload(payload, kParam); } catch { document.getElementById('lbl').textContent = '解密失败'; return; }
  const label = (data.label || '共享验证码');
  document.getElementById('lbl').textContent = label;
  document.getElementById('algo').textContent = `${(data.algorithm||'SHA1').toUpperCase()} · ${data.digits||6}位 · ${data.period||30}s`;
  async function renderOnce() {
    try {
      const code = await totpB32(data.secret, data);
      document.getElementById('code').textContent = formatCode(code, data.digits);
    } catch { document.getElementById('code').textContent = 'ERR'; }
    const left = secondsLeft(data.period);
    document.querySelector('.left').textContent = String(left);
    const pct = (left / Math.max(5, data.period || 30)) * 100;
    document.querySelector('.bar').style.background = `linear-gradient(90deg, var(--ok) ${pct}%, #1a1f25 ${pct}%)`;
  }
  renderOnce(); setInterval(renderOnce, 1000);
  document.getElementById('copy').addEventListener('click', async () => {
    try { const code = await totpB32(data.secret, data); const ok = await copyText(code); toast(ok ? '已复制验证码' : '复制失败', ok ? 'ok' : 'err'); } catch { toast('复制失败', 'err'); }
  });
  const copyLinkBtn = document.getElementById('copy-link');
  if (copyLinkBtn) {
    copyLinkBtn.addEventListener('click', async () => {
      try { const ok = await copyText(location.href); toast(ok ? '已复制链接' : '复制失败', ok ? 'ok' : 'err'); } catch { toast('复制失败', 'err'); }
    });
  }
}

main();

// Toast helper
let toastTimer = null;
function toast(msg, level = 'ok') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('ok','warn','err');
  if (level) el.classList.add(level);
  el.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>{ el.classList.remove('show'); }, 1800);
}

// Clipboard fallback (Safari-friendly)
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(String(text));
      return true;
    }
    throw new Error('no-clipboard');
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = String(text);
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      ta.style.pointerEvents = 'none';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}
