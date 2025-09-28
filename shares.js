// Share Manager: lists local-known shares and lets you revoke

const LS_KEY = 'authenticator.v1';
const LS_META = 'authenticator.v1.meta';
const LS_SYNC = 'authenticator.v1.sync';

const $ = (q) => document.querySelector(q);
function toB64(arr){return btoa(String.fromCharCode.apply(null, Array.from(arr)));}
function fromB64(b64){const bin=atob(b64||'');const out=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);return out;}

async function deriveKey(password, salt){
  const enc=new TextEncoder();
  const baseKey=await crypto.subtle.importKey('raw', enc.encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'}, baseKey,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}

let gKeyCache = null;

async function loadItems(password){
  const metaStr = localStorage.getItem(LS_META);
  const data = localStorage.getItem(LS_KEY);
  if (!data) return [];
  if (!metaStr){
    try { const parsed = JSON.parse(data); return (parsed.items||[]); } catch { return []; }
  }
  if (!password) throw new Error('需要主密码解锁');
  const meta = JSON.parse(metaStr);
  const key = await deriveKey(password, fromB64(meta.saltB64));
  gKeyCache = { key, meta };
  let txt;
  try {
    const packed = JSON.parse(data);
    const iv = fromB64(packed.iv); const ct = fromB64(packed.ct);
    const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv}, key, ct);
    txt = new TextDecoder().decode(new Uint8Array(plain));
  } catch (_) {
    const iv = fromB64(meta.ivB64||'');
    if (!iv.length) throw new Error('unlock-failed');
    const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv}, key, fromB64(data));
    txt = new TextDecoder().decode(new Uint8Array(plain));
  }
  const parsed = JSON.parse(txt);
  return (parsed.items||[]);
}

async function saveItems(items){
  const metaStr = localStorage.getItem(LS_META);
  const payload = JSON.stringify({ items });
  if (!metaStr){
    localStorage.setItem(LS_KEY, payload);
    return;
  }
  if (!gKeyCache) throw new Error('need-unlock');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv}, gKeyCache.key, new TextEncoder().encode(payload)));
  const packed = { v:2, iv: toB64(iv), ct: toB64(ct) };
  localStorage.setItem(LS_KEY, JSON.stringify(packed));
}

let gItems = [];

function renderList(items){
  gItems = items;
  const list = $('#list'); list.innerHTML='';
  const shares = [];
  for (const it of items){
    const sids = Array.isArray(it.shares)?it.shares:[];
    for (const sid of sids){ shares.push({ sid, label: `${it.issuer||''}${it.account?(' · '+it.account):''}`, id: it.id }); }
  }
  if (!shares.length){
    const div = document.createElement('div'); div.className='card'; div.textContent='暂无分享记录'; list.appendChild(div); return;
  }
  for (const s of shares){
    const card = document.createElement('div'); card.className='card';
    card.innerHTML = `
      <div class="rowx" style="justify-content:space-between">
        <div>
          <div>${s.label||'(未命名)'}</div>
          <div class="sid mono">SID: ${s.sid}</div>
        </div>
        <div class="rowx">
          <span class="status">检查中…</span>
          <button class="copy secondary">复制链接</button>
          <button class="bind secondary">绑定密钥</button>
          <button class="revoke secondary">撤销</button>
        </div>
      </div>`;
    list.appendChild(card);
    const statusEl = card.querySelector('.status');
    // check existence via HEAD
    checkHead(s.sid).then(async ok=>{
      if (ok){
        statusEl.textContent = '可用'; statusEl.className = 'status status-ok';
      } else {
        statusEl.textContent = '不存在/已过期'; statusEl.className = 'status status-miss';
        // 直接删除本地引用（兼容 string 或 {sid,k}）
        const item = gItems.find(x=>x.id===s.id);
        if (item && Array.isArray(item.shares)){
          item.shares = item.shares.filter(x=> (typeof x==='string'? x!==s.sid : x?.sid!==s.sid));
          try { await saveItems(gItems); } catch {}
          // remove card UI
          card.remove();
        }
      }
    }).catch(()=>{ statusEl.textContent='错误'; });
    card.querySelector('.copy').addEventListener('click', async ()=>{
      const it = gItems.find(x=>x.id===s.id);
      let entry = it && Array.isArray(it.shares) ? it.shares.find(e => (typeof e==='string'? e===s.sid : e?.sid===s.sid)) : null;
      let k = (entry && typeof entry !== 'string' && entry.k) ? entry.k : '';
      if (!k) {
        toast('此分享缺少本地密钥，请先绑定', 'warn');
        return;
      }
      const link = `${location.origin}/shared.html?sid=${encodeURIComponent(s.sid)}#k=${k}`;
      const ok = await copyText(link);
      toast(ok ? '已复制链接' : '复制失败', ok ? 'ok' : 'err');
    });

    card.querySelector('.bind').addEventListener('click', async () => {
      const val = prompt('粘贴完整分享链接（包含 #k=...）以绑定密钥：');
      if (!val) return;
      try {
        const u = new URL(val, location.origin);
        const sid2 = u.searchParams.get('sid');
        const k2 = new URLSearchParams(u.hash.replace(/^#/, '')).get('k');
        if (!sid2 || !k2) { alert('链接缺少 sid 或 k'); return; }
        if (sid2 !== s.sid) { alert('链接 SID 与当前不匹配'); return; }
        const it = gItems.find(x=>x.id===s.id);
        if (!it) { alert('未找到本地条目'); return; }
        if (!Array.isArray(it.shares)) it.shares = [];
        const idx = it.shares.findIndex(e => (typeof e==='string'? e===s.sid : e?.sid===s.sid));
        if (idx >= 0) {
          const existed = it.shares[idx];
          if (typeof existed === 'string') it.shares[idx] = { sid: s.sid, k: k2 };
          else it.shares[idx] = { sid: s.sid, k: k2 };
        } else {
          it.shares.push({ sid: s.sid, k: k2 });
        }
        await saveItems(gItems);
        alert('已绑定密钥，现在可复制完整链接');
      } catch { alert('解析失败，请检查链接格式'); }
    });
    card.querySelector('.revoke').addEventListener('click', async ()=>{
      const token = ($('#server-token').value || getSyncToken() || '').trim();
      const headers = token? { 'X-Token': token } : {};
      const res = await fetch(`/api/share/${encodeURIComponent(s.sid)}`, { method:'DELETE', headers });
      if (res.ok){ statusEl.textContent='已撤销'; statusEl.className='status status-miss'; }
      else { alert('撤销失败：'+res.status); }
    });
    // 重新分享按钮（生成新 SID + k，并复制完整链接）
    const reBtn = card.querySelector('.reshare');
    if (reBtn) reBtn.addEventListener('click', async ()=>{
      try {
        const it = gItems.find(x=>x.id===s.id);
        if (!it) { alert('未找到本地条目'); return; }
        const token = ($('#server-token').value || getSyncToken() || '').trim();
        const result = await createShareForItem(it, token);
        // 替换本地记录
        if (!Array.isArray(it.shares)) it.shares = [];
        const idx = it.shares.findIndex(e => (typeof e==='string'? e===s.sid : e?.sid===s.sid));
        if (idx >= 0) it.shares[idx] = { sid: result.sid, k: result.k };
        else it.shares.push({ sid: result.sid, k: result.k });
        await saveItems(gItems);
        // 尝试撤销旧 SID（若有 Token）
        if (token) { try { await fetch(`/api/share/${encodeURIComponent(s.sid)}`, { method:'DELETE', headers: { 'X-Token': token } }); } catch {} }
        // 更新 UI
        card.querySelector('.sid').textContent = 'SID: ' + result.sid;
        const ok = await copyText(result.link);
        toast(ok ? '已复制新链接' : '复制失败', ok ? 'ok' : 'err');
      } catch (e) { alert('重新分享失败'); }
    });
  }
}

async function checkHead(sid){
  const res = await fetch(`/api/share/${encodeURIComponent(sid)}`, { method:'HEAD' });
  return res.status === 200;
}

async function main(){
  // Prefill Server Token from app sync config
  try { const conf = JSON.parse(localStorage.getItem(LS_SYNC)||'{}'); if (conf && conf.token) $('#server-token').value = conf.token; } catch {}
  $('#unlock-btn').addEventListener('click', async ()=>{
    try{
      const items = await loadItems($('#unlock-pass').value);
      renderList(items);
    }catch(e){ alert('解锁失败或数据不可用'); }
  });
  $('#refresh').addEventListener('click', async ()=>{
    try{ const items = await loadItems($('#unlock-pass').value); renderList(items); }catch(e){}
  });
  $('#clean-missing').addEventListener('click', async ()=>{
    const items = await loadItems($('#unlock-pass').value);
    let changed = false;
    for (const it of items){
      if (Array.isArray(it.shares) && it.shares.length){
        const kept = [];
        for (const entry of it.shares){
          const sid = (typeof entry==='string') ? entry : entry?.sid;
          if (!sid) continue;
          if (await checkHead(sid)) kept.push(entry); else changed = true;
        }
        it.shares = kept;
      }
    }
    if (changed){
      try { await saveItems(items); alert('已清理无效引用'); } catch { alert('请先解锁再清理'); }
      renderList(items);
    } else { alert('没有无效引用'); }
  });
  // Cloud list
  async function loadCloud(){
    const token = ($('#server-token').value || getSyncToken() || '').trim();
    if (!token){ alert('需要 Server Token'); return; }
    const res = await fetch('/api/share/list', { headers: { 'X-Token': token } });
    if (!res.ok){ alert('加载失败：'+res.status); return; }
    const data = await res.json();
    const sids = data.sids || [];
    const container = document.querySelector('#cloud-list');
    container.innerHTML = '';
    if (!sids.length){ const d=document.createElement('div');d.className='card';d.textContent='云端暂无分享';container.appendChild(d); return; }
    for (const sid of sids){
      const card = document.createElement('div'); card.className='card';
      card.innerHTML = `
        <div class="rowx" style="justify-content:space-between">
          <div class="mono">SID: ${sid}</div>
          <div class="rowx">
            <button class="copy secondary">复制链接</button>
            <button class="revoke secondary">撤销</button>
          </div>
        </div>`;
      container.appendChild(card);
      // Try fetch key from server vault to build full link
      let keyStr = '';
      try {
        const kr = await fetch(`/api/sharekey/${encodeURIComponent(sid)}`, { headers: { 'X-Token': token } });
        if (kr.ok) { const j = await kr.json(); if (j && j.k) keyStr = j.k; }
      } catch {}
      card.querySelector('.copy').addEventListener('click', async ()=>{
        if (keyStr) {
          const ok = await copyText(`${location.origin}/shared.html?sid=${encodeURIComponent(sid)}#k=${keyStr}`);
          toast(ok ? '已复制链接' : '复制失败', ok ? 'ok' : 'err');
        } else {
          const ok = await copyText(sid);
          toast(ok ? '未保存密钥，已复制 SID' : '复制失败', ok ? 'warn' : 'err');
        }
      });
      card.querySelector('.revoke').addEventListener('click', async ()=>{
        const headers = token? { 'X-Token': token } : {};
        const res = await fetch(`/api/share/${encodeURIComponent(sid)}`, { method:'DELETE', headers });
        if (res.ok){
          card.remove();
          // 同步移除本地条目中的引用
          try{
            const items = await loadItems($('#unlock-pass').value);
            let changed=false; for (const it of items){ if (Array.isArray(it.shares)){ const n=it.shares.length; it.shares=it.shares.filter(x=> (typeof x==='string'? x!==sid : x?.sid!==sid)); if (it.shares.length!==n) changed=true; } }
            if (changed) await saveItems(items);
            // also delete server-side stored key
            try { await fetch(`/api/sharekey/${encodeURIComponent(sid)}`, { method:'DELETE', headers }); } catch {}
          }catch{}
        } else { alert('撤销失败：'+res.status); }
      });
    }
  }
  $('#cloud-load').addEventListener('click', loadCloud);
  $('#cloud-reload').addEventListener('click', loadCloud);
  // Auto try without password if not encrypted
  if (!localStorage.getItem(LS_META)){
    try{ const items = await loadItems(''); renderList(items); }catch(e){}
  }
}

function getSyncToken(){
  try{ const conf = JSON.parse(localStorage.getItem(LS_SYNC)||'{}'); return conf.token || ''; } catch { return ''; }
}

// Persist typed Server Token so it does not need re-entry
document.addEventListener('DOMContentLoaded', () => {
  const inp = document.getElementById('server-token');
  if (!inp) return;
  inp.addEventListener('change', () => {
    try{
      const conf = JSON.parse(localStorage.getItem(LS_SYNC)||'{}');
      conf.token = inp.value || '';
      localStorage.setItem(LS_SYNC, JSON.stringify(conf));
    }catch{}
  });
});

// Toast + clipboard helpers
let __toastTimer = null;
function toast(msg, level='ok'){
  const el = document.getElementById('toast'); if (!el) return;
  el.textContent = msg; el.classList.remove('ok','warn','err'); if (level) el.classList.add(level);
  el.classList.add('show'); if (__toastTimer) clearTimeout(__toastTimer); __toastTimer = setTimeout(()=>{ el.classList.remove('show'); }, 1800);
}

async function copyText(text){
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(String(text)); return true; }
    throw new Error('no-clipboard');
  } catch {
    try {
      const ta = document.createElement('textarea'); ta.value = String(text);
      ta.style.position='fixed'; ta.style.opacity='0'; ta.style.pointerEvents='none'; document.body.appendChild(ta);
      ta.focus(); ta.select(); const ok = document.execCommand('copy'); document.body.removeChild(ta); return ok;
    } catch { return false; }
  }
}

// Helpers for re-share
function b64url(bytes){
  return btoa(String.fromCharCode.apply(null, Array.from(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function createShareForItem(item, token){
  if ((item.type||'totp') !== 'totp') throw new Error('仅支持 TOTP 重新分享');
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
  const sidBytes = crypto.getRandomValues(new Uint8Array(12));
  const sid = b64url(sidBytes);
  const body = JSON.stringify({ v:1, iv: b64url(iv), ct: b64url(ct) });
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['X-Token'] = token;
  let qs = '';
  const sel = prompt('有效期：输入小时数字，perm 为永久，留空后端默认');
  if (sel){ const t = sel.trim().toLowerCase(); if (t==='perm'||t==='0') qs='?ttl=perm'; else { const n=Number(t); if (Number.isFinite(n)&&n>0) qs='?ttl='+Math.round(n*3600); } }
  const res = await fetch(`/api/share/${encodeURIComponent(sid)}${qs}`, { method:'PUT', headers, body });
  if (!res.ok) throw new Error('server');
  // store key to server vault if token given
  if (token) {
    try { await fetch(`/api/sharekey/${encodeURIComponent(sid)}${qs}`, { method:'PUT', headers: { 'Content-Type':'application/json', 'X-Token': token }, body: JSON.stringify({ k: b64url(keyRaw) }) }); } catch {}
  }
  const link = `${location.origin}/shared.html?sid=${encodeURIComponent(sid)}#k=${b64url(keyRaw)}`;
  return { link, sid, k: b64url(keyRaw) };
}

main();
