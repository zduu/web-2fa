// Web 2FA Authenticator (TOTP) – compatible with otpauth links used by Google/Microsoft Authenticator

const state = {
  items: [], // {id, type, issuer, account, secret, algorithm, digits, period, counter, updatedAt, deleted}
  ticking: null,
  unlocked: true,
  encMeta: null, // {saltB64} when encrypted
  key: null, // CryptoKey for AES-GCM
  sync: { id: "", secret: "", token: "", auto: false, lastSyncedAt: 0 },
  syncProjects: [], // [{id, name, syncId, secret, token, auto, lastSyncedAt, itemsData}]
  currentProjectId: null,
  globalToken: "",
  gateRequired: false,
  cloudProjects: [],
};

// ---------- Utils ----------
const $ = (q) => document.querySelector(q);
const $$ = (q) => Array.from(document.querySelectorAll(q));
const byId = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Clipboard helper with Safari fallback
async function copyTextToClipboard(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
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

// Backward-compatible alias used by some handlers
async function copyText(text) {
  return copyTextToClipboard(String(text));
}

function base32Decode(input) {
  // RFC 4648 Base32 (upper/lower + ignore padding/whitespace)
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = (input || "").toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0, value = 0, index = 0;
  const out = [];
  for (const c of clean) {
    const idx = alphabet.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    index++;
  }
  return new Uint8Array(out);
}

function base32Encode(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  let bits = 0, value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out; // no padding
}

function toB64(arr) {
  return btoa(String.fromCharCode.apply(null, Array.from(arr)));
}
function fromB64(b64) {
  const bin = atob(b64 || "");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------- TOTP ----------
async function hotp(secretBytes, counter, algo = "SHA-1", digits = 6) {
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // 64-bit BE counter
  const hi = Math.floor(counter / 2 ** 32);
  const lo = counter >>> 0;
  view.setUint32(0, hi);
  view.setUint32(4, lo);

  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: { name: algo } },
    false,
    ["sign"]
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counterBuf)
  );

  const offset = sig[sig.length - 1] & 0xf;
  const code =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const mod = 10 ** digits;
  const val = (code % mod).toString().padStart(digits, "0");
  return val;
}

async function totp(secretBase32, {
  algorithm = "SHA1",
  digits = 6,
  period = 30,
} = {}) {
  const algo = algorithm.toUpperCase();
  const hash = algo === "SHA256" ? "SHA-256" : algo === "SHA512" ? "SHA-512" : "SHA-1";
  const step = Math.max(5, Number(period) || 30);
  const counter = Math.floor(Date.now() / 1000 / step);
  const secretBytes = base32Decode(secretBase32);
  return hotp(secretBytes, counter, hash, Number(digits) || 6);
}

function secondsLeft(period = 30) {
  const step = Math.max(5, Number(period) || 30);
  const s = Math.floor(Date.now() / 1000);
  return step - (s % step);
}

// ---------- otpauth parsing ----------
function parseOtpAuth(uri) {
  // otpauth://totp/Issuer:Account?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
  try {
    if (!uri || !uri.startsWith("otpauth://")) return null;
    const u = new URL(uri);
    const type = u.hostname; // totp/hotp
    const label = decodeURIComponent(u.pathname.replace(/^\//, ""));
    let issuer = u.searchParams.get("issuer") || "";
    let account = label;
    if (label.includes(":")) {
      const [maybeIssuer, acct] = label.split(":");
      if (!issuer) issuer = maybeIssuer;
      account = acct;
    }
    const secret = (u.searchParams.get("secret") || "").replace(/\s+/g, "");
    const algorithm = (u.searchParams.get("algorithm") || "SHA1").toUpperCase();
    const digits = Number(u.searchParams.get("digits") || 6);
    const period = Number(u.searchParams.get("period") || 30);
    const counter = Number(u.searchParams.get("counter") || 0);
    return { type, issuer, account, secret, algorithm, digits, period, counter };
  } catch (e) {
    console.error(e);
    return null;
  }
}

// ---------- otpauth-migration parsing (protobuf) ----------
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4; if (pad) s += "===".slice(pad);
  return fromB64(s);
}

function readVarint(buf, p) {
  let x = 0n, s = 0n; let i = p;
  while (i < buf.length) {
    const b = BigInt(buf[i++]);
    x |= (b & 0x7fn) << s;
    if ((b & 0x80n) === 0n) break;
    s += 7n;
  }
  return { value: x, pos: i };
}

function readBytes(buf, p) {
  const { value: lenBig, pos } = readVarint(buf, p);
  const len = Number(lenBig);
  const start = pos; const end = start + len;
  return { bytes: buf.slice(start, end), pos: end };
}

function parseOtpParameters(bytes) {
  const out = { secret: null, name: "", issuer: "", algorithm: 1, digits: 1, type: 2, counter: 0 };
  let p = 0;
  while (p < bytes.length) {
    const { value: keyBig, pos: p1 } = readVarint(bytes, p); p = p1;
    const key = Number(keyBig);
    const tag = key >>> 3; const wt = key & 7;
    if (tag === 1 && wt === 2) { // secret
      const r = readBytes(bytes, p); p = r.pos; out.secret = r.bytes;
    } else if (tag === 2 && wt === 2) { // name
      const r = readBytes(bytes, p); p = r.pos; out.name = new TextDecoder().decode(r.bytes);
    } else if (tag === 3 && wt === 2) { // issuer
      const r = readBytes(bytes, p); p = r.pos; out.issuer = new TextDecoder().decode(r.bytes);
    } else if (tag === 4 && wt === 0) { // algorithm
      const r = readVarint(bytes, p); p = r.pos; out.algorithm = Number(r.value);
    } else if (tag === 5 && wt === 0) { // digits
      const r = readVarint(bytes, p); p = r.pos; out.digits = Number(r.value);
    } else if (tag === 6 && wt === 0) { // type
      const r = readVarint(bytes, p); p = r.pos; out.type = Number(r.value);
    } else if (tag === 7 && wt === 0) { // counter
      const r = readVarint(bytes, p); p = r.pos; out.counter = Number(r.value);
    } else {
      // skip unknown
      if (wt === 2) { const r = readBytes(bytes, p); p = r.pos; } else if (wt === 0) { const r = readVarint(bytes, p); p = r.pos; } else { break; }
    }
  }
  return out;
}

function parseMigrationPayload(buf) {
  const items = [];
  let p = 0;
  while (p < buf.length) {
    const { value: keyBig, pos: p1 } = readVarint(buf, p); p = p1;
    const key = Number(keyBig);
    const tag = key >>> 3; const wt = key & 7;
    if (tag === 1 && wt === 2) { // otp_parameters
      const r = readBytes(buf, p); p = r.pos;
      const param = parseOtpParameters(r.bytes);
      // map enums
      const algo = param.algorithm === 2 ? "SHA256" : param.algorithm === 3 ? "SHA512" : "SHA1";
      const digits = param.digits === 2 ? 8 : 6;
      const type = param.type === 1 ? "hotp" : "totp";
      if (!param.secret) continue;
      const secretB32 = base32Encode(param.secret);
      items.push({ type, issuer: param.issuer || "", account: param.name || "", secret: secretB32, algorithm: algo, digits, period: 30, counter: param.counter || 0 });
    } else if (wt === 2) {
      const r = readBytes(buf, p); p = r.pos; // ignore other fields
    } else if (wt === 0) {
      const r = readVarint(buf, p); p = r.pos; // ignore ints
    } else {
      break;
    }
  }
  return items;
}

function parseOtpAuthMigration(uriOrData) {
  try {
    let dataParam = "";
    if (uriOrData.startsWith("otpauth-migration://")) {
      const u = new URL(uriOrData);
      dataParam = u.searchParams.get("data") || "";
    } else {
      dataParam = uriOrData.trim();
    }
    if (!dataParam) return [];
    const bytes = b64urlToBytes(dataParam);
    return parseMigrationPayload(bytes);
  } catch (e) {
    console.error(e);
    return [];
  }
}

// ---------- Storage (localStorage, optional AES-GCM) ----------
const LS_KEY = "authenticator.v1";
const LS_META = "authenticator.v1.meta";

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function setPassword() {
  return new Promise((resolve) => {
    const modal = byId("password-modal");
    const titleEl = byId("password-modal-title");
    const hintEl = byId("password-modal-hint");
    const input = byId("password-input");
    const msgEl = byId("password-msg");

    titleEl.textContent = "设置主密码";
    hintEl.textContent = "数据将使用 AES-GCM 加密存储在本地浏览器中";
    input.value = "";
    msgEl.textContent = "";

    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    input.focus();

    const onConfirm = async () => {
      const pwd = input.value.trim();
      if (!pwd) {
        msgEl.textContent = "请输入密码";
        return;
      }

      try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        state.key = await deriveKey(pwd, salt);
        state.encMeta = { saltB64: toB64(salt) };
        await persist();
        cleanup();
        toast("主密码已设置并加密", 'ok');
        resolve(true);
      } catch (e) {
        msgEl.textContent = "设置失败：" + e.message;
      }
    };

    const onCancel = () => {
      cleanup();
      resolve(false);
    };

    const onBackdrop = (e) => {
      if (e.target === modal) onCancel();
    };

    const onKeydown = (e) => {
      if (e.key === 'Enter') onConfirm();
      if (e.key === 'Escape') onCancel();
    };

    const cleanup = () => {
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
      byId("password-confirm").removeEventListener("click", onConfirm);
      byId("password-cancel").removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
      input.removeEventListener("keydown", onKeydown);
    };

    byId("password-confirm").addEventListener("click", onConfirm);
    byId("password-cancel").addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    input.addEventListener("keydown", onKeydown);
  });
}

async function unlock() {
  const metaStr = localStorage.getItem(LS_META);
  const data = localStorage.getItem(LS_KEY);
  if (!metaStr || !data) { state.unlocked = true; return; }
  const meta = JSON.parse(metaStr);

  return new Promise((resolve) => {
    const modal = byId("password-modal");
    const titleEl = byId("password-modal-title");
    const hintEl = byId("password-modal-hint");
    const input = byId("password-input");
    const msgEl = byId("password-msg");

    titleEl.textContent = "解锁数据";
    hintEl.textContent = "检测到加密数据，请输入主密码以解锁";
    input.value = "";
    msgEl.textContent = "";

    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    input.focus();

    const onConfirm = async () => {
      const pwd = input.value.trim();
      if (!pwd) {
        msgEl.textContent = "请输入密码";
        return;
      }

      try {
        const salt = fromB64(meta.saltB64);
        state.key = await deriveKey(pwd, salt);
        state.encMeta = meta;

        let txt;
        try {
          const parsed = JSON.parse(data);
          const iv = fromB64(parsed.iv);
          const ct = fromB64(parsed.ct);
          const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, ct);
          txt = new TextDecoder().decode(new Uint8Array(plain));
        } catch (_) {
          // 兼容旧版格式
          const iv = fromB64(meta.ivB64 || "");
          if (!iv.length) throw new Error('no-iv');
          const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.key, fromB64(data));
          txt = new TextDecoder().decode(new Uint8Array(plain));
        }

        const parsed = JSON.parse(txt);
        state.items = (parsed.items || []).map(ensureItemDefaults);
        state.unlocked = true;
        cleanup();
        render();
        toast('已解锁', 'ok');
        resolve(true);
      } catch (e) {
        console.error(e);
        msgEl.textContent = "解锁失败，密码错误或数据损坏";
        resolve(false);
      }
    };

    const onCancel = () => {
      cleanup();
      resolve(false);
    };

    const onBackdrop = (e) => {
      if (e.target === modal) onCancel();
    };

    const onKeydown = (e) => {
      if (e.key === 'Enter') onConfirm();
      if (e.key === 'Escape') onCancel();
    };

    const cleanup = () => {
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
      byId("password-confirm").removeEventListener("click", onConfirm);
      byId("password-cancel").removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
      input.removeEventListener("keydown", onKeydown);
    };

    byId("password-confirm").addEventListener("click", onConfirm);
    byId("password-cancel").addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    input.addEventListener("keydown", onKeydown);
  });
}

async function persist() {
  const payload = JSON.stringify({ items: state.items });
  if (state.key && state.encMeta) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, state.key, new TextEncoder().encode(payload));
    const packed = { v: 2, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
    localStorage.setItem(LS_KEY, JSON.stringify(packed));
    localStorage.setItem(LS_META, JSON.stringify(state.encMeta));
  } else {
    localStorage.setItem(LS_KEY, payload);
    localStorage.removeItem(LS_META);
  }
}

function load() {
  const metaStr = localStorage.getItem(LS_META);
  const data = localStorage.getItem(LS_KEY);
  if (!data) { state.items = []; state.unlocked = true; return; }
  try {
    if (metaStr) {
      // encrypted, require unlock
      state.unlocked = false;
    } else {
      const parsed = JSON.parse(data);
      state.items = (parsed.items || []).map(ensureItemDefaults);
      state.unlocked = true;
    }
  } catch (e) {
    console.error(e);
    state.items = [];
    state.unlocked = true;
  }
}

function exportData() {
  const blob = new Blob([
    localStorage.getItem(LS_META) ? JSON.stringify({
      encrypted: true,
      meta: JSON.parse(localStorage.getItem(LS_META) || "{}"),
      data: localStorage.getItem(LS_KEY),
    }, null, 2) : JSON.stringify({ encrypted: false, data: JSON.parse(localStorage.getItem(LS_KEY) || "{}") }, null, 2)
  ], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `authenticator-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function importData() {
  const input = document.createElement("input");
  input.type = "file"; input.accept = "application/json";
  input.onchange = async (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    const text = await file.text();
    try {
      const obj = JSON.parse(text);
      if (obj.encrypted) {
        localStorage.setItem(LS_META, JSON.stringify(obj.meta || {}));
        localStorage.setItem(LS_KEY, obj.data || "");
        state.key = null; state.encMeta = null; state.unlocked = false; state.items = [];
        toast("已导入加密数据，点击‘密码/解锁’解锁", 'ok');
      } else {
        localStorage.setItem(LS_KEY, JSON.stringify(obj.data || { items: [] }));
        localStorage.removeItem(LS_META);
        state.items = ((obj.data || {}).items || []).map(ensureItemDefaults);
        state.unlocked = true;
        toast("数据已导入", 'ok');
      }
      render();
    } catch (e) {
      console.error(e);
      alert("导入失败：文件格式不正确。");
      toast('导入失败', 'err');
    }
  };
  input.click();
}

function ensureItemDefaults(it) {
  const out = { ...it };
  out.secret = (out.secret || '').replace(/\s+/g, '').toUpperCase();
  out.type = out.type || 'totp';
  out.algorithm = (out.algorithm || 'SHA1').toUpperCase();
  out.digits = Number(out.digits || 6);
  out.period = Number(out.period || 30);
  if (out.type === 'hotp') out.counter = Number(out.counter || 0);
  out.updatedAt = Number(out.updatedAt || Date.now());
  out.deleted = !!out.deleted;
  if (Array.isArray(out.shares)) {
    out.shares = out.shares.map((s) => {
      if (typeof s === 'string') return { sid: s };
      if (s && typeof s.sid === 'string') return { sid: s.sid, k: (typeof s.k === 'string' && s.k) ? s.k : undefined };
      return null;
    }).filter(Boolean);
  } else {
    out.shares = [];
  }
  return out;
}

// ---------- UI ----------
function updateStatusIndicators() {
  // Storage status
  const storageEl = byId('storage-status');
  if (storageEl) {
    const hasProject = state.syncProjects && state.syncProjects.length > 0;
    if (hasProject) {
      storageEl.textContent = '本地 + 云端同步';
      storageEl.classList.add('active');
      storageEl.classList.remove('warning');
    } else {
      storageEl.textContent = '仅本地';
      storageEl.classList.remove('active');
      storageEl.classList.add('warning');
    }
  }

  // Token status
  const tokenEl = byId('token-status-display');
  if (tokenEl) {
    const hasToken = !!(state.globalToken || loadGlobalToken());
    if (hasToken) {
      tokenEl.textContent = '已设置';
      tokenEl.classList.add('active');
      tokenEl.classList.remove('warning');
    } else {
      tokenEl.textContent = '未设置（三击标题设置）';
      tokenEl.classList.remove('active');
      tokenEl.classList.add('warning');
    }
  }

  // Project status
  const projectEl = byId('project-status');
  if (projectEl) {
    if (!state.currentProjectId) {
      projectEl.textContent = '无项目（点击"同步"创建）';
      projectEl.classList.remove('active');
      projectEl.classList.add('warning');
    } else if (state.currentProjectId === '_all_') {
      projectEl.textContent = '📊 全部项目（汇总视图）';
      projectEl.classList.add('active');
      projectEl.classList.remove('warning');
    } else {
      const project = getCurrentProject();
      if (project) {
        projectEl.textContent = project.name || '未命名项目';
        projectEl.classList.add('active');
        projectEl.classList.remove('warning');
      }
    }
  }
}

function toggleAddForm(show) {
  byId("add-form").classList.toggle("hidden", !show);
  if (show) {
    try { byId("type").dispatchEvent(new Event('change')); } catch {}
  }
}

function toggleScanForm(show) {
  byId("scan-form").classList.toggle("hidden", !show);
}

function hideAllForms() {
  byId("add-form").classList.add("hidden");
  byId("scan-form").classList.add("hidden");
  byId("sync-form").classList.add("hidden");
  byId("shares-form").classList.add("hidden");
}

function clearAddInputs() {
  byId("otpauth-input").value = "";
  byId("type").value = "totp";
  byId("issuer").value = "";
  byId("account").value = "";
  byId("secret").value = "";
  byId("algorithm").value = "SHA1";
  byId("digits").value = "6";
  byId("period").value = "30";
  byId("counter").value = "0";
  try { byId("type").dispatchEvent(new Event('change')); } catch {}
}

function addItemFromFields() {
  const uri = byId("otpauth-input").value.trim();
  if (uri) {
    if (uri.startsWith("otpauth-migration://") || /^[A-Za-z0-9_\-]+=*$/.test(uri)) {
      // migration link or raw base64 data
      const items = parseOtpAuthMigration(uri);
      if (!items.length) { alert("未解析到迁移数据。"); return; }
      for (const it of items) addNewItem(it);
      persist();
      scheduleAutoPush();
      toggleAddForm(false);
      clearAddInputs();
      render();
      alert(`已导入 ${items.length} 个账户。`);
      return;
    }
  }
  let item = uri ? parseOtpAuth(uri) : null;
  if (!item) {
    const type = byId("type").value || 'totp';
    const issuer = byId("issuer").value.trim();
    const account = byId("account").value.trim();
    const secret = byId("secret").value.trim();
    const algorithm = byId("algorithm").value.trim() || "SHA1";
    const digits = Number(byId("digits").value || 6);
    const period = Number(byId("period").value || 30);
    const counter = Number(byId("counter").value || 0);
    if (!secret) { alert("请填写 secret 或粘贴 otpauth 链接。"); return; }
    item = type === 'hotp'
      ? { type: "hotp", issuer, account, secret, algorithm, digits, counter }
      : { type: "totp", issuer, account, secret, algorithm, digits, period };
  }
  if (!item.secret) { alert("无效 secret。"); return; }
  addNewItem(item);
  persist();
  scheduleAutoPush();
  toggleAddForm(false);
  clearAddInputs();
  render();
  toast('已添加账户', 'ok');
}

function addNewItem(item) {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const base = {
    id,
    type: item.type || 'totp',
    issuer: item.issuer || "",
    account: item.account || "",
    secret: (item.secret || '').replace(/\s+/g, '').toUpperCase(),
    algorithm: (item.algorithm || "SHA1").toUpperCase(),
    digits: item.digits || 6,
    period: item.period || 30,
    counter: item.counter || 0,
    deleted: false,
    updatedAt: Date.now(),
    shares: [],
  };
  state.items.push(base);
}

function removeItem(id) {
  const it = state.items.find(x => x.id === id);
  if (!it) return;
  it.deleted = true;
  it.updatedAt = Date.now();
  persist();
  scheduleAutoPush();
  render();
  toast('已删除', 'ok');
  if (Array.isArray(it.shares) && it.shares.length) {
    const headers = {};
    if (state.sync?.token) headers['X-Token'] = state.sync.token;
    it.shares.forEach(async (entry) => {
      const sid = typeof entry === 'string' ? entry : entry?.sid;
      if (!sid) return;
      try { await fetch(`/api/share/${encodeURIComponent(sid)}`, { method:'DELETE', headers }); } catch {}
    });
  }
}

async function codeForItem(item) {
  if (item.type === 'hotp') {
    const secretBytes = base32Decode(item.secret);
    return hotp(secretBytes, item.counter || 0, item.algorithm === 'SHA512' ? 'SHA-512' : item.algorithm === 'SHA256' ? 'SHA-256' : 'SHA-1', item.digits || 6);
  }
  return totp(item.secret, item);
}

function formatCode(text, digits) {
  const s = String(text || "");
  if ((digits || s.length) >= 8 && s.length >= 8) return s.slice(0, 4) + " " + s.slice(4, 8);
  if (s.length >= 6) return s.slice(0, 3) + " " + s.slice(3, 6);
  return s;
}

async function renderItem(el, item) {
  el.querySelector(".issuer").textContent = item.issuer || "(无 issuer)";
  el.querySelector(".account").textContent = item.account || "";
  // badge
  let badge = el.querySelector('.badge');
  if (!badge) {
    badge = document.createElement('span');
    badge.className = 'badge';
    el.querySelector('.meta').prepend(badge);
  }
  badge.textContent = (item.type || 'totp').toUpperCase();
  try {
    const code = await codeForItem(item);
    el.querySelector(".code").textContent = formatCode(code, item.digits);
  } catch (e) {
    el.querySelector(".code").textContent = "ERR";
  }
  if (item.type === 'hotp') {
    el.classList.add('hotp');
    el.querySelector('.next').classList.remove('hidden');
    const sb = el.querySelector('.share'); if (sb) sb.classList.add('hidden');
  } else {
    el.classList.remove('hotp'); el.classList.add('totp');
    el.querySelector('.next').classList.add('hidden');
    const sb = el.querySelector('.share'); if (sb) sb.classList.remove('hidden');
    const left = secondsLeft(item.period);
    el.querySelector(".left").textContent = String(left);
    const pct = (left / Math.max(5, item.period || 30)) * 100;
    el.querySelector(".bar").style.setProperty("--w", `${pct}%`);
    // animate with width via style
    el.querySelector(".bar").style.background = `linear-gradient(90deg, var(--ok) ${pct}%, #1a1f25 ${pct}%)`;
    if (left <= 5) el.classList.add('expiring'); else el.classList.remove('expiring');
  }
}

async function tick() {
  // Update all
  await Promise.all($$(".item").map(async (node) => {
    const id = node.dataset.id;
    const item = state.items.find((x) => x.id === id);
    if (item) await renderItem(node, item);
  }));
}

function render() {
  const list = byId("list");
  list.innerHTML = "";
  if (!state.unlocked) {
    const div = document.createElement("div");
    div.className = "card";
    div.textContent = "已检测到加密数据。点击右上角'密码/解锁'按钮输入主密码以解锁。";
    list.appendChild(div);
    return;
  }

  // Update status indicators
  updateStatusIndicators();

  // Show project tag for items in "all" view
  const isAllView = state.currentProjectId === '_all_';

  const tpl = byId("tpl-item");
  const items = state.items.filter(x => !x.deleted).sort((a,b) => `${a.issuer}\u0000${a.account}`.localeCompare(`${b.issuer}\u0000${b.account}`));
  for (const item of items) {
    const node = tpl.content.firstElementChild.cloneNode(true);
    node.dataset.id = item.id;

    // Add project badge in "all" view
    if (isAllView && item._projectName) {
      const meta = node.querySelector('.meta');
      if (meta) {
        const projectBadge = document.createElement('span');
        projectBadge.className = 'badge project-tag';
        projectBadge.textContent = item._projectName;
        projectBadge.style.fontSize = '10px';
        projectBadge.style.marginLeft = '8px';
        meta.appendChild(projectBadge);
      }
    }

    renderItem(node, item);
    node.querySelector(".copy").addEventListener("click", async () => {
      try {
        const code = await codeForItem(item);
        const ok = await copyTextToClipboard(code);
        toast(ok ? '已复制验证码' : '复制失败', ok ? 'ok' : 'err');
      } catch (e) { toast('复制失败', 'err'); }
    });
    node.querySelector('.next').addEventListener('click', async () => {
      if (item.type !== 'hotp') return;
      item.counter = Number(item.counter || 0) + 1;
      item.updatedAt = Date.now();
      await persist();
      scheduleAutoPush();
      await renderItem(node, item);
      toast('已生成下一次');
    });
    node.querySelector('.share').addEventListener('click', async () => {
      try {
        const qs = await chooseShareTTL();
        const url = await shareItem(item, qs);
        const ok = await copyTextToClipboard(url);
        toast(ok ? '分享链接已复制' : '复制失败', ok ? 'ok' : 'err');
      } catch (e) {
        console.error(e); toast(`分享失败${e.status?('：'+e.status):''}`, 'err');
      }
    });
    node.querySelector(".remove").addEventListener("click", () => {
      if (isAllView) {
        toast('汇总视图不可删除，请切换到具体项目', 'warn');
        return;
      }
      removeItem(item.id);
    });
    list.appendChild(node);
  }
}

// ---------- QR scan (BarcodeDetector + getUserMedia, fallback to file) ----------
let mediaStream = null;
let scanTimer = null;

async function scanFrame(detector) {
  const video = byId("video");
  if (video.readyState < 2) return; // not enough data
  try {
    const results = await detector.detect(video);
    if (results && results.length) {
      const txt = results[0]?.rawValue || "";
      if (txt.startsWith("otpauth://") || txt.startsWith("otpauth-migration://")) {
        stopScan();
      if (txt.startsWith("otpauth-migration://")) {
          const items = parseOtpAuthMigration(txt);
          for (const it of items) addNewItem(it);
          await persist();
          scheduleAutoPush();
          render();
          alert(`已导入 ${items.length} 个账户。`);
        } else {
          const item = parseOtpAuth(txt);
          if (item && item.secret) {
            addNewItem(item);
            await persist();
            scheduleAutoPush();
            render();
            alert("已导入账户。");
          } else {
            alert("二维码不是 TOTP otpauth 链接。");
          }
        }
      }
    }
  } catch (e) {
    // ignore
  }
}

async function startScan() {
  const support = ("BarcodeDetector" in window);
  byId("scan-support").textContent = support ? "已检测到原生二维码识别支持。" : "当前浏览器缺少原生扫码支持，可使用‘选择图片’或粘贴 otpauth 链接。";
  if (!support) return;
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  try {
    mediaStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
  } catch (e) {
    alert("无法访问摄像头。");
    return;
  }
  const video = byId("video");
  video.srcObject = mediaStream;
  await video.play();
  scanTimer = setInterval(() => scanFrame(detector), 300);
  toast('已启动扫码');
}

function stopScan() {
  if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
  const video = byId("video");
  if (video) { try { video.pause(); } catch {}
    video.srcObject = null; }
  if (mediaStream) {
    mediaStream.getTracks().forEach(t => t.stop());
    mediaStream = null;
  }
}

async function scanImageFile(file) {
  if (!("BarcodeDetector" in window)) { alert("此浏览器不支持原生识别，请粘贴 otpauth 链接。"); return; }
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  const img = await createImageBitmap(await fileToBlob(file));
  const res = await detector.detect(img);
  if (res && res.length) {
    const txt = res[0]?.rawValue || "";
  if (txt.startsWith("otpauth://") || txt.startsWith("otpauth-migration://")) {
      if (txt.startsWith("otpauth-migration://")) {
        const items = parseOtpAuthMigration(txt);
        for (const it of items) addNewItem(it);
        await persist();
        scheduleAutoPush();
        render();
        toast(`已导入 ${items.length} 个账户`, 'ok');
      } else {
        const item = parseOtpAuth(txt);
        if (item && item.secret) {
          addNewItem(item);
          await persist();
          scheduleAutoPush();
          render();
          toast("已导入账户", 'ok');
        }
      }
    } else {
      toast("未识别为 otpauth 链接", 'warn');
    }
  } else {
    toast("未识别到二维码", 'warn');
  }
}

function fileToBlob(file) { return file.slice(0, file.size, file.type || "image/*"); }

// ---------- Cloud Browse (Admin) ----------
async function loadCloudProjects() {
  const adminKey = byId("kv-admin-key-input").value.trim();
  const msgEl = byId("cloud-browse-msg");
  const resultEl = byId("cloud-browse-result");
  const listEl = byId("cloud-projects-list");
  const totalEl = byId("cloud-total");

  msgEl.textContent = "";
  resultEl.classList.add("hidden");

  if (!adminKey) {
    msgEl.textContent = "请输入 KV Admin Key";
    return;
  }

  try {
    const res = await fetch("/api/admin/list-all", {
      method: "POST",
      headers: {
        "X-KV-Admin-Key": adminKey,
        "Content-Type": "application/json"
      }
    });

    if (res.status === 401) {
      msgEl.textContent = "KV Admin Key 无效";
      return;
    }

    if (res.status === 500) {
      msgEl.textContent = "服务器未配置 Admin Key 或发生错误";
      return;
    }

    if (!res.ok) {
      msgEl.textContent = `加载失败：${res.status}`;
      return;
    }

    const data = await res.json();
    if (!data.success) {
      msgEl.textContent = data.error || "加载失败";
      return;
    }

    // Display results
    totalEl.textContent = String(data.total || 0);
    listEl.innerHTML = "";

    state.cloudProjects = Array.isArray(data.projects) ? data.projects : [];
    if (!state.cloudProjects || state.cloudProjects.length === 0) {
      listEl.innerHTML = '<div style="text-align:center; color:var(--muted); padding:20px;">云端暂无同步项目</div>';
    } else {
      for (const proj of state.cloudProjects) {
        const item = document.createElement("div");
        item.className = "cloud-project-item";

        const header = document.createElement("div");
        header.className = "cloud-project-header";

        const idEl = document.createElement("div");
        idEl.className = "cloud-project-id";
        idEl.textContent = proj.syncId || "未知";

        const actionsEl = document.createElement("div");
        actionsEl.className = "cloud-project-actions";

        const importBtn = document.createElement("button");
        importBtn.className = "btn-small secondary";
        importBtn.textContent = "导入为新项目";
        importBtn.addEventListener("click", () => {
          importCloudProject(proj.syncId);
        });

        actionsEl.appendChild(importBtn);
        header.appendChild(idEl);
        header.appendChild(actionsEl);

        const metaEl = document.createElement("div");
        metaEl.className = "cloud-project-meta";
        metaEl.textContent = `版本: v${proj.metadata?.version || 1} | 加密: ${proj.metadata?.hasData ? '是' : '否'}`;

        item.appendChild(header);
        item.appendChild(metaEl);
        listEl.appendChild(item);
      }
    }

    resultEl.classList.remove("hidden");
    toast("云端项目加载成功", "ok");
    // Auto render all codes if opted in
    const showAll = byId('cloud-browse-show-all');
    if (showAll && showAll.checked) {
      renderAllCloudCodes();
    } else {
      const block = byId('cloud-allcodes'); if (block) block.classList.add('hidden');
    }
  } catch (e) {
    console.error(e);
    msgEl.textContent = "网络错误，请重试";
  }
}

function importCloudProject(syncId) {
  if (!syncId) return;

  // Check if project already exists
  const exists = state.syncProjects.some(p => p.syncId === syncId);
  if (exists) {
    toast("项目已存在", "warn");
    return;
  }

  // Auto-fill sync ID and open new project form
  byId("sync-project-name").value = `云端项目-${syncId}`;
  byId("sync-id").value = syncId;
  byId("sync-secret").value = "";
  byId("sync-auto").checked = false;

  byId("sync-config-panel").classList.remove("hidden");
  byId("sync-config-panel").dataset.editingProjectId = "";

  // Close cloud browse modal
  const modal = byId("cloud-browse-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
  }

  toast("请输入 Sync Secret 以解密云端数据", "ok");
}

// ---------- Events ----------
function bindEvents() {
  byId("btn-add").addEventListener("click", () => { hideAllForms(); toggleAddForm(true); });
  byId("btn-scan").addEventListener("click", () => { hideAllForms(); toggleScanForm(true); });
  byId("btn-import").addEventListener("click", importData);
  byId("btn-export").addEventListener("click", () => { exportData(); toast('已触发下载'); });
  byId("btn-sync").addEventListener("click", () => {
    hideAllForms();
    byId("sync-form").classList.remove("hidden");
    loadSyncProjects();
    renderSyncProjects();
  });
  byId("btn-shares").addEventListener("click", () => {
    hideAllForms();
    byId("shares-form").classList.remove("hidden");
  });
  byId("btn-password").addEventListener("click", async () => {
    if (!state.unlocked) {
      await unlock();
      return;
    }

    // Show confirmation modal for setting password
    const modal = byId("password-modal");
    const titleEl = byId("password-modal-title");
    const hintEl = byId("password-modal-hint");
    const input = byId("password-input");
    const msgEl = byId("password-msg");

    titleEl.textContent = "设置/重置主密码";
    hintEl.textContent = "确定要设置/重置主密码并加密本地数据？";
    input.value = "";
    msgEl.textContent = "";

    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    input.focus();

    const onConfirm = async () => {
      const pwd = input.value.trim();
      if (!pwd) {
        msgEl.textContent = "请输入密码";
        return;
      }

      try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        state.key = await deriveKey(pwd, salt);
        state.encMeta = { saltB64: toB64(salt) };
        await persist();
        cleanup();
        toast("主密码已设置并加密", 'ok');
      } catch (e) {
        msgEl.textContent = "设置失败：" + e.message;
      }
    };

    const onCancel = () => {
      cleanup();
    };

    const onBackdrop = (e) => {
      if (e.target === modal) onCancel();
    };

    const onKeydown = (e) => {
      if (e.key === 'Enter') onConfirm();
      if (e.key === 'Escape') onCancel();
    };

    const cleanup = () => {
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
      byId("password-confirm").removeEventListener("click", onConfirm);
      byId("password-cancel").removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
      input.removeEventListener("keydown", onKeydown);
    };

    byId("password-confirm").addEventListener("click", onConfirm);
    byId("password-cancel").addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    input.addEventListener("keydown", onKeydown);
  });

  byId("add-confirm").addEventListener("click", addItemFromFields);
  byId("add-cancel").addEventListener("click", () => { toggleAddForm(false); clearAddInputs(); });
  byId("type").addEventListener("change", () => {
    const isHotp = byId("type").value === 'hotp';
    byId("counter-row").classList.toggle('hidden', !isHotp);
    byId("period-row").classList.toggle('hidden', isHotp);
  });
  byId("scan-start").addEventListener("click", startScan);
  byId("scan-stop").addEventListener("click", () => { stopScan(); toast('已停止扫码'); });
  byId("file-input").addEventListener("change", (e) => { const f = e.target.files?.[0]; if (f) scanImageFile(f); });

  // Sync
  byId("sync-close").addEventListener("click", () => {
    saveCurrentProjectItems();
    byId("sync-form").classList.add("hidden");
  });
  byId("sync-push").addEventListener("click", syncPush);
  byId("sync-pull").addEventListener("click", syncPull);
  byId("sync-clean").addEventListener("click", syncClean);
  byId("share-revoke").addEventListener("click", revokeShare);
  const autoEl = byId('sync-auto');
  if (autoEl) autoEl.addEventListener('change', () => {
    state.sync.auto = autoEl.checked; saveSyncConfig();
    if (state.sync.auto) startAutoSync(); else stopAutoSync();
  });

  // Sync Projects
  const syncProjectAdd = byId("sync-project-add");
  if (syncProjectAdd) syncProjectAdd.addEventListener("click", createNewProject);

  const syncSaveProject = byId("sync-save-project");
  if (syncSaveProject) syncSaveProject.addEventListener("click", saveProjectConfig);

  const syncDeleteProject = byId("sync-delete-project");
  if (syncDeleteProject) syncDeleteProject.addEventListener("click", deleteCurrentEditingProject);

  const syncCancelEdit = byId("sync-cancel-edit");
  if (syncCancelEdit) syncCancelEdit.addEventListener("click", () => {
    byId("sync-config-panel").classList.add("hidden");
  });

  // Global Token - Triple click on title
  let titleClickCount = 0;
  let titleClickTimer = null;
  const appTitle = byId("app-title");
  if (appTitle) {
    appTitle.addEventListener("click", () => {
      titleClickCount++;
      if (titleClickTimer) clearTimeout(titleClickTimer);

      if (titleClickCount === 3) {
        openGlobalTokenModal();
        titleClickCount = 0;
      } else {
        titleClickTimer = setTimeout(() => {
          titleClickCount = 0;
        }, 500);
      }
    });
  }

  // Global Token Modal
  const globalTokenSave = byId("global-token-save");
  if (globalTokenSave) {
    globalTokenSave.addEventListener("click", () => {
      const token = byId("global-token-input").value;
      saveGlobalToken(token);
      state.globalToken = token;
      byId("global-token-modal").classList.add("hidden");
      toast(token ? 'Global Server Token 已保存' : 'Global Server Token 已清除', 'ok');
    });
  }

  const globalTokenClear = byId("global-token-clear");
  if (globalTokenClear) {
    globalTokenClear.addEventListener("click", () => {
      byId("global-token-input").value = "";
      byId("global-token-status").textContent = "";
    });
  }

  const globalTokenCancel = byId("global-token-cancel");
  if (globalTokenCancel) {
    globalTokenCancel.addEventListener("click", () => {
      byId("global-token-modal").classList.add("hidden");
    });
  }

  const globalTokenToggle = byId("global-token-toggle");
  const globalTokenInput = byId("global-token-input");
  const globalTokenStatus = byId("global-token-status");
  if (globalTokenToggle && globalTokenInput) {
    globalTokenToggle.addEventListener("click", () => {
      const isPassword = globalTokenInput.type === "password";
      globalTokenInput.type = isPassword ? "text" : "password";
      globalTokenToggle.textContent = isPassword ? "🙈" : "👁️";
    });
    globalTokenInput.addEventListener("input", () => {
      if (globalTokenInput.value) {
        globalTokenStatus.textContent = "已设置";
      } else {
        globalTokenStatus.textContent = "";
      }
    });
  }

  // Password toggle for password modal
  const passwordToggle = byId("password-toggle");
  const passwordInput = byId("password-input");
  if (passwordToggle && passwordInput) {
    passwordToggle.addEventListener("click", () => {
      const isPassword = passwordInput.type === "password";
      passwordInput.type = isPassword ? "text" : "password";
      passwordToggle.textContent = isPassword ? "🙈" : "👁️";
    });
  }

  // Cloud Browse (Admin)
  const cloudBrowseBtn = byId("cloud-browse-btn");
  if (cloudBrowseBtn) {
    cloudBrowseBtn.addEventListener("click", () => {
      const modal = byId("cloud-browse-modal");
      if (modal) {
        modal.classList.remove("hidden");
        modal.setAttribute("aria-hidden", "false");
      }
    });
  }

  const cloudBrowseClose = byId("cloud-browse-close");
  if (cloudBrowseClose) {
    cloudBrowseClose.addEventListener("click", () => {
      const modal = byId("cloud-browse-modal");
      if (modal) {
        modal.classList.add("hidden");
        modal.setAttribute("aria-hidden", "true");
      }
    });
  }

  const kvAdminKeyToggle = byId("kv-admin-key-toggle");
  const kvAdminKeyInput = byId("kv-admin-key-input");
  if (kvAdminKeyToggle && kvAdminKeyInput) {
    kvAdminKeyToggle.addEventListener("click", () => {
      const isPassword = kvAdminKeyInput.type === "password";
      kvAdminKeyInput.type = isPassword ? "text" : "password";
      kvAdminKeyToggle.textContent = isPassword ? "🙈" : "👁️";
    });
  }

  const cloudBrowseLoad = byId("cloud-browse-load");
  if (cloudBrowseLoad) {
    cloudBrowseLoad.addEventListener("click", loadCloudProjects);
  }

  // Cloud browse: show-all toggle + secret reveal
  const cloudShowAll = byId('cloud-browse-show-all');
  const cloudSecret = byId('cloud-browse-secret');
  const cloudSecretToggle = byId('cloud-browse-secret-toggle');
  if (cloudShowAll) cloudShowAll.addEventListener('change', () => { if (cloudShowAll.checked) renderAllCloudCodes(); else { const b=byId('cloud-allcodes'); if (b) b.classList.add('hidden'); } });
  if (cloudSecret) cloudSecret.addEventListener('change', () => { if (cloudShowAll && cloudShowAll.checked) renderAllCloudCodes(); });
  if (cloudSecretToggle && cloudSecret) cloudSecretToggle.addEventListener('click', () => { const isPwd = cloudSecret.type === 'password'; cloudSecret.type = isPwd ? 'text' : 'password'; cloudSecretToggle.textContent = isPwd ? '🙈' : '👁️'; });

  // Shares
  const sharesClose = byId("shares-close");
  if (sharesClose) sharesClose.addEventListener("click", () => byId("shares-form").classList.add("hidden"));

  // Cloud Shares (list + refresh)
  const cloudLoadBtn = byId('cloud-load');
  const cloudReloadBtn = byId('cloud-reload');
  if (cloudLoadBtn) cloudLoadBtn.addEventListener('click', loadCloudShares);
  if (cloudReloadBtn) cloudReloadBtn.addEventListener('click', loadCloudShares);

  // Token toggle
  const tokenToggle = byId('token-toggle');
  const tokenInput = byId('sync-token');
  const tokenStatus = byId('token-status');
  if (tokenToggle && tokenInput) {
    tokenToggle.addEventListener('click', () => {
      const isPassword = tokenInput.type === 'password';
      tokenInput.type = isPassword ? 'text' : 'password';
      tokenToggle.textContent = isPassword ? '🙈' : '👁️';
    });
    // Update status on input
    tokenInput.addEventListener('input', () => {
      if (tokenInput.value) {
        tokenStatus.textContent = '已设置';
      } else {
        tokenStatus.textContent = '';
      }
    });
  }
}

// ---------- Init ----------
function startTicker() {
  if (state.ticking) clearInterval(state.ticking);
  state.ticking = setInterval(tick, 1000);
}

function init() {
  loadSyncProjects();
  load();
  bindEvents();
  render();
  startTicker();
  // Load global token
  state.globalToken = loadGlobalToken();
  // Update status indicators on init
  updateStatusIndicators();
  // Register SW
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
  if (state.sync && state.sync.auto) startAutoSync();
  // Server-side gate
  gateCheck();
}

window.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") tick();
});

init();

// ---------- Sync (E2E) ----------
const LS_SYNC = "authenticator.v1.sync";
const LS_SYNC_PROJECTS = "authenticator.v1.syncProjects";
const LS_GLOBAL_TOKEN = "authenticator.v1.globalToken";

// Global Server Token Management
function loadGlobalToken() {
  try {
    return localStorage.getItem(LS_GLOBAL_TOKEN) || "";
  } catch {
    return "";
  }
}

function saveGlobalToken(token) {
  if (token) {
    localStorage.setItem(LS_GLOBAL_TOKEN, token);
  } else {
    localStorage.removeItem(LS_GLOBAL_TOKEN);
  }
  updateStatusIndicators();
}

function getGlobalToken() {
  return state.globalToken || loadGlobalToken();
}

function openGlobalTokenModal() {
  const modal = byId("global-token-modal");
  const input = byId("global-token-input");
  const status = byId("global-token-status");

  input.value = loadGlobalToken();
  if (input.value) {
    status.textContent = "已设置";
  } else {
    status.textContent = "";
  }

  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

// Sync Projects Management
function loadSyncProjects() {
  try {
    const projects = JSON.parse(localStorage.getItem(LS_SYNC_PROJECTS) || "[]");
    state.syncProjects = projects;
    state.currentProjectId = localStorage.getItem("authenticator.v1.currentProjectId") || null;
  } catch {
    state.syncProjects = [];
    state.currentProjectId = null;
  }
}

function saveSyncProjects() {
  localStorage.setItem(LS_SYNC_PROJECTS, JSON.stringify(state.syncProjects));
  if (state.currentProjectId) {
    localStorage.setItem("authenticator.v1.currentProjectId", state.currentProjectId);
  }
  updateStatusIndicators();
}

function getCurrentProject() {
  if (!state.currentProjectId) return null;
  return state.syncProjects.find(p => p.id === state.currentProjectId) || null;
}

function renderSyncProjects() {
  const list = byId("sync-projects-list");
  if (!list) return;

  // Create virtual "All Projects" entry
  const allProjectsEntry = {
    id: '_all_',
    name: '全部项目（汇总视图）',
    syncId: '-',
    isVirtual: true
  };

  const allProjects = [allProjectsEntry, ...state.syncProjects];

  if (state.syncProjects.length === 0) {
    list.innerHTML = '';
    return;
  }

  list.innerHTML = allProjects.map(project => {
    const isActive = project.id === state.currentProjectId;
    const isVirtual = project.isVirtual;

    return `
    <div class="sync-project-item ${isActive ? 'active' : ''} ${isVirtual ? 'virtual-project' : ''}" data-project-id="${project.id}">
      <div class="project-info">
        <div class="project-name">${isVirtual ? '📊 ' : ''}${escapeHtml(project.name || '未命名项目')}</div>
        <div class="project-id">${isVirtual ? '只读视图，显示所有项目的验证码' : 'ID: ' + escapeHtml(project.syncId || '-')}</div>
      </div>
      ${isActive ? '<span class="project-badge">当前</span>' : ''}
      ${!isVirtual ? `
      <div class="project-actions">
        <button class="btn-icon project-edit" data-project-id="${project.id}" title="编辑">✏️</button>
      </div>
      ` : ''}
    </div>
  `}).join('');

  // Bind click events
  $$('.sync-project-item').forEach(el => {
    const projectId = el.dataset.projectId;
    el.addEventListener('click', (e) => {
      if (!e.target.classList.contains('btn-icon') && !e.target.closest('.btn-icon')) {
        switchToProject(projectId);
      }
    });
  });

  $$('.project-edit').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      editProject(btn.dataset.projectId);
    });
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function switchToProject(projectId) {
  const project = state.syncProjects.find(p => p.id === projectId);
  if (!project) return;

  // Save current project items before switching
  saveCurrentProjectItems();

  // Switch to new project
  state.currentProjectId = projectId;

  // Special handling for "all" project
  if (projectId === '_all_') {
    // Merge all projects' items
    state.items = [];
    state.syncProjects.forEach(p => {
      if (p.id !== '_all_' && p.itemsData) {
        state.items = state.items.concat(p.itemsData.map(item => ({
          ...item,
          _projectName: p.name || '未命名项目'
        })));
      }
    });
  } else {
    state.items = project.itemsData || [];
  }

  // Update sync config
  state.sync = {
    id: project.syncId || "",
    secret: project.secret || "",
    token: project.token || "",
    auto: !!project.auto,
    lastSyncedAt: project.lastSyncedAt || 0
  };

  saveSyncProjects();
  render();
  renderSyncProjects();
  toast(`已切换到项目：${project.name || '未命名项目'}`, 'ok');
}

function saveCurrentProjectItems() {
  if (!state.currentProjectId) return;
  const project = getCurrentProject();
  if (project) {
    project.itemsData = state.items;
    saveSyncProjects();
  }
}

function editProject(projectId) {
  const project = state.syncProjects.find(p => p.id === projectId);
  if (!project) return;

  byId("sync-project-name").value = project.name || "";
  byId("sync-id").value = project.syncId || "";
  byId("sync-secret").value = project.secret || "";
  byId("sync-auto").checked = !!project.auto;

  byId("sync-config-panel").classList.remove("hidden");
  byId("sync-config-panel").dataset.editingProjectId = projectId;
}

function createNewProject() {
  byId("sync-project-name").value = "";
  byId("sync-id").value = "";
  byId("sync-secret").value = "";
  byId("sync-auto").checked = false;

  byId("sync-config-panel").classList.remove("hidden");
  byId("sync-config-panel").dataset.editingProjectId = "";
}

function saveProjectConfig() {
  const editingId = byId("sync-config-panel").dataset.editingProjectId;
  const name = byId("sync-project-name").value.trim();
  const syncId = byId("sync-id").value.trim();
  const secret = byId("sync-secret").value;
  const auto = byId("sync-auto").checked;

  if (!name || !syncId || !secret) {
    alert("请填写项目名称、Sync ID 和 Sync Secret");
    return;
  }

  if (editingId) {
    // Update existing project
    const project = state.syncProjects.find(p => p.id === editingId);
    if (project) {
      project.name = name;
      project.syncId = syncId;
      project.secret = secret;
      project.auto = auto;
    }
  } else {
    // Create new project
    const newProject = {
      id: `proj_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name,
      syncId,
      secret,
      auto,
      lastSyncedAt: 0,
      itemsData: []
    };
    state.syncProjects.push(newProject);
  }

  saveSyncProjects();
  renderSyncProjects();
  byId("sync-config-panel").classList.add("hidden");
  toast(editingId ? '项目已更新' : '项目已创建', 'ok');
}

function deleteCurrentEditingProject() {
  const editingId = byId("sync-config-panel").dataset.editingProjectId;
  if (!editingId) return;

  if (!confirm("确定要删除此项目？项目中的数据将会丢失。")) return;

  state.syncProjects = state.syncProjects.filter(p => p.id !== editingId);

  if (state.currentProjectId === editingId) {
    state.currentProjectId = null;
    state.items = [];
    render();
  }

  saveSyncProjects();
  renderSyncProjects();
  byId("sync-config-panel").classList.add("hidden");
  toast('项目已删除', 'ok');
}

function saveSyncConfig() {
  state.sync.id = byId("sync-id").value.trim();
  state.sync.secret = byId("sync-secret").value;
  state.sync.token = getGlobalToken(); // Use global token
  const autoEl = byId('sync-auto');
  if (autoEl) state.sync.auto = !!autoEl.checked;
  localStorage.setItem(LS_SYNC, JSON.stringify(state.sync));
}

function loadSyncConfig() {
  try {
    const s = JSON.parse(localStorage.getItem(LS_SYNC) || "{}");
    state.sync = { id: s.id || "", secret: s.secret || "", token: getGlobalToken(), auto: !!s.auto, lastSyncedAt: s.lastSyncedAt || 0 };
    byId("sync-id").value = state.sync.id;
    byId("sync-secret").value = state.sync.secret;
    const autoEl = byId('sync-auto'); if (autoEl) autoEl.checked = !!state.sync.auto;
  } catch {}
}

async function deriveSyncKey(secret, id) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  const salt = enc.encode(`sync:${id}`);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" }, baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

// ---------- Toast ----------
let toastTimer = null;
function toast(msg, level = 'ok') {
  const el = byId('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('ok','warn','err');
  if (level) el.classList.add(level);
  el.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.remove('show');
  }, 2000);
}

async function syncEncrypt(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
  return { v: 1, iv: toB64(iv), ct: toB64(ct) };
}

async function syncDecrypt(payload, key) {
  const iv = fromB64(payload.iv);
  const ct = fromB64(payload.ct);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

function getSyncEndpoint(id) {
  // Pages Functions route
  return `/api/sync/${encodeURIComponent(id)}`;
}

async function syncPush() {
  saveSyncConfig();
  const { id, secret, token } = state.sync;
  if (!id || !secret) { alert("请填写 Sync ID 与 Sync Secret。"); return; }
  const key = await deriveSyncKey(secret, id);
  const payload = await syncEncrypt({ items: state.items }, key);
  const res = await fetch(getSyncEndpoint(id), { method: "PUT", headers: { "Content-Type": "application/json", ...(token ? { "X-Token": token } : {}) }, body: JSON.stringify(payload) });
  if (!res.ok) { alert(`推送失败：${res.status}`); updateSyncStatus('推送失败', 'err'); toast('推送失败', 'err'); return; }
  state.sync.lastSyncedAt = Date.now();
  localStorage.setItem(LS_SYNC, JSON.stringify(state.sync));
  updateSyncStatus('已推送', 'ok');
  toast('已推送', 'ok');
}

async function syncPull() {
  saveSyncConfig();
  const { id, secret, token } = state.sync;
  if (!token) { alert('请先设置 Server Token（点击标题 3 次）'); return; }
  if (!id || !secret) { alert("请填写 Sync ID 与 Sync Secret。"); return; }
  const key = await deriveSyncKey(secret, id);
  const res = await fetch(getSyncEndpoint(id), { headers: { ...(token ? { "X-Token": token } : {}) } });
  if (res.status === 404) { alert("云端暂无数据。"); updateSyncStatus('云端暂无', 'warn'); return; }
  if (!res.ok) { alert(`拉取失败：${res.status}`); updateSyncStatus('拉取失败', 'err'); toast('拉取失败', 'err'); return; }
  const payload = await res.json();
  try {
    const obj = await syncDecrypt(payload, key);
    const remote = (obj.items || []).map(ensureItemDefaults);
    state.items = mergeItems(state.items, remote);
    await persist();
    render();
    state.sync.lastSyncedAt = Date.now();
    localStorage.setItem(LS_SYNC, JSON.stringify(state.sync));
    updateSyncStatus('已同步', 'ok');
    toast('已同步', 'ok');
  } catch (e) {
    console.error(e);
    alert("解密失败，请检查 Sync Secret 是否一致。");
    updateSyncStatus('解密失败', 'err');
    toast('解密失败', 'err');
  }
}

// load sync config at startup
loadSyncConfig();

// ---------- Cloud browse: aggregate codes ----------
async function renderAllCloudCodes() {
  const container = byId('cloud-allcodes');
  const list = byId('cloud-allcodes-list');
  const msg = byId('cloud-allcodes-msg');
  if (!container || !list || !msg) return;
  const token = getGlobalToken();
  if (!token) { container.classList.remove('hidden'); list.innerHTML=''; msg.textContent='请先设置 Server Token（点击标题 3 次）'; return; }
  const secret = (byId('cloud-browse-secret')?.value || '').trim();
  if (!secret) { container.classList.remove('hidden'); list.innerHTML=''; msg.textContent='请输入默认 Sync Secret 以尝试解密'; return; }
  const projects = state.cloudProjects || [];
  if (!projects.length) { container.classList.add('hidden'); return; }
  container.classList.remove('hidden');
  list.innerHTML = '<div style="text-align:center; color: var(--muted); padding: 8px;">加载中…</div>';
  msg.textContent = '';
  const aggregated = [];
  let failed = 0;
  for (const proj of projects) {
    const id = proj.syncId;
    try {
      const res = await fetch(getSyncEndpoint(id), { headers: { 'X-Token': token, 'Cache-Control': 'no-cache' } });
      if (!res.ok) { failed++; continue; }
      const payload = await res.json();
      const key = await deriveSyncKey(secret, id);
      const obj = await syncDecrypt(payload, key);
      const items = (obj.items || []).map(ensureItemDefaults).map(it => ({ ...it, _projectName: id }));
      aggregated.push(...items);
    } catch { failed++; }
  }
  if (!aggregated.length) {
    list.innerHTML = '<div class="card">无法解密任何项目，请检查 Sync Secret 是否正确。</div>';
    msg.textContent = failed ? `有 ${failed} 个项目加载或解密失败` : '';
    return;
  }
  // Render simple list of codes
  list.innerHTML = '';
  for (const item of aggregated.slice(0, 200)) { // cap to avoid extreme DOM
    const row = document.createElement('div');
    row.className = 'card';
    row.style.display = 'flex'; row.style.justifyContent='space-between'; row.style.alignItems='center';
    const left = document.createElement('div');
    left.innerHTML = `<div style="font-weight:600;">${escapeHtml(item.issuer||'')} ${item.account?('· '+escapeHtml(item.account)) : ''}</div><div class=\"hint\">项目: ${escapeHtml(item._projectName||'-')}</div>`;
    const right = document.createElement('div');
    right.className = 'mono'; right.style.minWidth='96px'; right.textContent = '••••••';
    row.appendChild(left); row.appendChild(right);
    list.appendChild(row);
    // compute code once
    codeForItem(item).then(c => { right.textContent = formatCode(c, item.digits); }).catch(()=>{ right.textContent='ERR'; });
  }
  msg.textContent = failed ? `有 ${failed} 个项目加载或解密失败（其余已显示）` : '';
}

// ---------- Merge (conflict resolution) ----------
function itemKey(it) {
  // Prefer stable id, fallback to signature
  return it.id || `${it.type}|${(it.secret||'').replace(/\s+/g,'').toUpperCase()}|${it.issuer||''}|${it.account||''}`;
}

function pickLatest(a, b) {
  if (!a) return b; if (!b) return a;
  const at = Number(a.updatedAt || 0); const bt = Number(b.updatedAt || 0);
  return at >= bt ? a : b;
}

function mergeItems(local, remote) {
  const map = new Map();
  for (const it of local.map(ensureItemDefaults)) {
    map.set(itemKey(it), it);
  }
  for (const it of remote.map(ensureItemDefaults)) {
    const k = itemKey(it);
    const merged = pickLatest(map.get(k), it);
    const a = (map.get(k)?.shares) || [];
    const b = (it.shares) || [];
    // Merge shares by sid, preserve key if present
    const bySid = new Map();
    for (const s of [...a, ...b]) {
      const entry = (typeof s === 'string') ? { sid: s } : (s && typeof s.sid === 'string' ? { sid: s.sid, k: s.k } : null);
      if (!entry) continue;
      if (!bySid.has(entry.sid)) bySid.set(entry.sid, entry);
      else {
        const prev = bySid.get(entry.sid);
        if (!prev.k && entry.k) prev.k = entry.k;
      }
    }
    merged.shares = Array.from(bySid.values());
    map.set(k, merged);
  }
  // Return array; keep deleted tombstones to sync, but render() filters them out
  return Array.from(map.values());
}

// ---------- Share single TOTP ----------
function b64url(bytes) {
  return toB64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function chooseShareTTL() {
  const modal = byId('share-modal');
  if (!modal) return '';
  modal.classList.remove('hidden'); modal.setAttribute('aria-hidden','false');
  return new Promise((resolve, reject) => {
    const onCancel = () => { cleanup(); resolve(''); };
    const onConfirm = () => {
      const val = (document.querySelector('input[name="share-ttl"]:checked')||{}).value || 'default';
      let qs = '';
      if (val === '1h') qs = '?ttl=3600';
      else if (val === '24h') qs = '?ttl=86400';
      else if (val === 'perm') qs = '?ttl=perm';
      else if (val === 'custom') {
        const hours = Number(byId('share-custom-hours').value || '0');
        if (Number.isFinite(hours) && hours > 0) qs = `?ttl=${Math.round(hours*3600)}`;
      } // default => ''
      cleanup(); resolve(qs);
    };
    function onBackdrop(e){ if(e.target===modal) onCancel(); }
    const cleanup = () => {
      modal.classList.add('hidden'); modal.setAttribute('aria-hidden','true');
      byId('share-confirm').removeEventListener('click', onConfirm);
      byId('share-cancel').removeEventListener('click', onCancel);
      modal.removeEventListener('click', onBackdrop);
    };
    byId('share-confirm').addEventListener('click', onConfirm);
    byId('share-cancel').addEventListener('click', onCancel);
    modal.addEventListener('click', onBackdrop);
  });
}

async function shareItem(item, qs='') {
  if ((item.type || 'totp') !== 'totp') throw new Error('仅支持分享 TOTP');
  // Build minimal payload
  const payloadObj = {
    type: 'totp',
    secret: (item.secret||'').replace(/\s+/g,'').toUpperCase(),
    algorithm: (item.algorithm||'SHA1').toUpperCase(),
    digits: Number(item.digits||6),
    period: Number(item.period||30),
    label: `${item.issuer||''}${item.account?(' · '+item.account):''}`.trim()
  };
  const pt = new TextEncoder().encode(JSON.stringify(payloadObj));
  const keyRaw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', keyRaw, { name:'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, pt));

  // generate id
  const sidBytes = crypto.getRandomValues(new Uint8Array(12));
  const sid = b64url(sidBytes);
  const body = JSON.stringify({ v:1, iv: b64url(iv), ct: b64url(ct) });
  const headers = { 'Content-Type': 'application/json' };
  if (state.sync?.token) headers['X-Token'] = state.sync.token;
  const res = await fetch(`/api/share/${encodeURIComponent(sid)}${qs}`, { method:'PUT', headers, body });
  if (!res.ok) { const err = new Error('server'); err.status = res.status; throw err; }
  // Store share key server-side (optional), requires Server Token
  try {
    if (state.sync?.token) {
      await fetch(`/api/sharekey/${encodeURIComponent(sid)}${qs}`, { method:'PUT', headers: { 'Content-Type':'application/json', 'X-Token': state.sync.token }, body: JSON.stringify({ k: b64url(keyRaw) }) });
    }
  } catch {}
  const link = `${location.origin}/shared.html?sid=${encodeURIComponent(sid)}#k=${b64url(keyRaw)}`;
  if (!Array.isArray(item.shares)) item.shares = [];
  if (!item.shares.some((x)=> (typeof x==='string'? x===sid : x.sid===sid))) item.shares.push({ sid, k: b64url(keyRaw) });
  item.updatedAt = Date.now();
  await persist();
  scheduleAutoPush();
  return link;
}

async function revokeShare() {
  const inp = prompt('粘贴分享链接或输入SID以撤销：');
  if (!inp) return;
  let sid = inp.trim();
  try {
    if (sid.includes('sid=')) {
      const u = new URL(sid, location.origin);
      sid = u.searchParams.get('sid') || sid;
    } else if (sid.startsWith('http')) {
      const u = new URL(sid);
      sid = u.searchParams.get('sid') || sid;
    }
  } catch {}
  if (!sid || /[^A-Za-z0-9_-]/.test(sid)) { toast('SID 无效', 'err'); return; }
  const headers = {};
  if (state.sync?.token) headers['X-Token'] = state.sync.token;
  const res = await fetch(`/api/share/${encodeURIComponent(sid)}`, { method:'DELETE', headers });
  if (res.ok) { toast('已撤销分享', 'ok'); }
  else { toast(`撤销失败：${res.status}`, 'err'); }
}

// ---------- Cloud Shares (KV) ----------
async function loadCloudShares() {
  const listEl = byId('cloud-shares-list');
  if (!listEl) return;
  listEl.innerHTML = '<div style="text-align:center; color: var(--muted); padding: 12px;">加载中…</div>';

  const token = getGlobalToken();
  if (!token) {
    listEl.innerHTML = '<div class="card">需要先设置 Global Server Token（点击标题 3 次）</div>';
    return;
  }
  try {
    const res = await fetch('/api/share/list', { headers: { 'X-Token': token, 'Cache-Control': 'no-cache' } });
    if (!res.ok) {
      listEl.innerHTML = `<div class="card">加载失败：${res.status}</div>`;
      return;
    }
    const data = await res.json().catch(() => ({ sids: [] }));
    const sids = Array.isArray(data.sids) ? data.sids : [];
    if (!sids.length) {
      listEl.innerHTML = '<div class="card">云端暂无分享</div>';
      return;
    }
    listEl.innerHTML = '';
    for (const sid of sids) {
      // Try fetch stored key
      let keyStr = '';
      try {
        const kr = await fetch(`/api/sharekey/${encodeURIComponent(sid)}`, { headers: { 'X-Token': token, 'Cache-Control': 'no-cache' } });
        if (kr.ok) { const j = await kr.json(); if (j && typeof j.k === 'string') keyStr = j.k; }
      } catch {}

      const item = document.createElement('div');
      item.className = 'share-item';
      item.innerHTML = `
        <div class="share-info">
          <div class="share-name">分享</div>
          <div class="share-sid">SID: ${sid}</div>
        </div>
        <div class="share-actions">
          <button class="secondary copy">复制链接</button>
          <button class="secondary revoke">撤销</button>
        </div>
      `;
      listEl.appendChild(item);

      const onCopy = async () => {
        if (keyStr) {
          const ok = await copyTextToClipboard(`${location.origin}/shared.html?sid=${encodeURIComponent(sid)}#k=${keyStr}`);
          toast(ok ? '已复制链接' : '复制失败', ok ? 'ok' : 'err');
        } else {
          const ok = await copyTextToClipboard(sid);
          toast(ok ? '未保存密钥，已复制 SID' : '复制失败', ok ? 'warn' : 'err');
        }
      };
      const onRevoke = async () => {
        try {
          const r = await fetch(`/api/share/${encodeURIComponent(sid)}`, { method:'DELETE', headers: { 'X-Token': token } });
          if (r.ok) {
            // Best-effort delete saved key
            try { await fetch(`/api/sharekey/${encodeURIComponent(sid)}`, { method:'DELETE', headers: { 'X-Token': token } }); } catch {}
            item.remove();
            toast('已撤销分享', 'ok');
          } else {
            toast(`撤销失败：${r.status}`,'err');
          }
        } catch {
          toast('网络错误','err');
        }
      };
      item.querySelector('.copy').addEventListener('click', onCopy);
      item.querySelector('.revoke').addEventListener('click', onRevoke);
    }
  } catch (e) {
    listEl.innerHTML = '<div class="card">网络错误，请重试</div>';
  }
}

// ---------- Auto Sync helpers ----------
let pullTimer = null;
let pushTimer = null;

function updateSyncStatus(text, level = '') {
  const el = byId('sync-status');
  if (!el) return;
  el.textContent = text + (state.sync.lastSyncedAt ? ` · ${new Date(state.sync.lastSyncedAt).toLocaleTimeString()}` : '');
  el.classList.remove('ok','warn','err');
  if (level) el.classList.add(level);
}

function startAutoSync() {
  stopAutoSync();
  // initial pull
  syncPull().catch(() => {});
  pullTimer = setInterval(() => {
    syncPull().catch(() => {});
  }, 60_000);
}

function stopAutoSync() {
  if (pullTimer) clearInterval(pullTimer); pullTimer = null;
  if (pushTimer) clearTimeout(pushTimer); pushTimer = null;
}

function scheduleAutoPush() {
  if (!state.sync.auto) return;
  if (pushTimer) clearTimeout(pushTimer);
  pushTimer = setTimeout(() => { syncPush().catch(() => {}); }, 1500);
}

async function syncClean() {
  const count = state.items.filter(x => x.deleted).length;
  if (!count) { alert('没有可清理的删除条目。'); return; }
  if (!confirm(`将彻底移除 ${count} 个已删除条目。确保所有设备已同步再执行。继续？`)) return;
  state.items = state.items.filter(x => !x.deleted);
  await persist();
  render();
  scheduleAutoPush();
  alert('已清理。');
}

// ---------- Global Gate (ACCESS_GATE) ----------
async function gateCheck() {
  try {
    const res = await fetch('/api/gate', { method: 'GET', headers: { 'Cache-Control': 'no-cache' } });
    if (res.status === 403) showGateModal();
  } catch {}
}

function showGateModal() {
  const modal = byId('gate-modal'); if (!modal) return;
  state.gateRequired = true;
  modal.classList.remove('hidden'); modal.setAttribute('aria-hidden','false');
  const btn = byId('gate-submit'); const pass = byId('gate-pass'); const msg = byId('gate-msg');
  const onSubmit = async () => {
    const pw = pass.value;
    if (!pw) { msg.textContent = '请输入访问口令'; return; }
    try {
      const res = await fetch('/api/gate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) });
      if (res.ok) {
        modal.classList.add('hidden'); modal.setAttribute('aria-hidden','true');
        state.gateRequired = false; toast('已通过访问验证', 'ok');
      } else { msg.textContent = '口令错误，请重试'; }
    } catch { msg.textContent = '网络错误，请重试'; }
  };
  btn.addEventListener('click', onSubmit, { once: false });
  pass.addEventListener('keydown', (e)=>{ if (e.key==='Enter') onSubmit(); });
}
