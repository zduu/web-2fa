// 导入/导出（明文 + 加密包），从原 app.js exportData / importData 移植
import { state, getCurrentProject, persist, ensureItemDefaults, saveSyncProjects } from "../core/storage.js";
import { deriveKey, toB64, fromB64 } from "../core/crypto.js";
import { itemKey } from "../sync/sync.js";
import { downloadBlob } from "../ui/toast.js";
import { promptDialog, openModal } from "../ui/modal.js";
import { toast, escapeHtml } from "../ui/toast.js";

export async function exportCurrent() {
  if (!state.currentProjectId || state.currentProjectId === "_all_") {
    toast("请先切换到具体项目再导出。汇总视图请使用管理员面板的全部解密导出。", "warn");
    return;
  }
  const proj = getCurrentProject();
  if (!proj) { toast("未找到当前项目", "err"); return; }
  const items = Array.isArray(proj.itemsData) ? proj.itemsData.slice() : [];
  const map = new Map();
  for (const it of items) {
    if (it.deleted) continue;
    const k = itemKey(it);
    const prev = map.get(k);
    if (!prev || (Number(it.updatedAt || 0) >= Number(prev.updatedAt || 0))) map.set(k, it);
  }
  const cleaned = Array.from(map.values());
  const data = { items: cleaned };
  const pass = await promptDialog({
    title: "导出",
    label: "可选：输入密码以加密导出（留空 = 明文导出）",
    placeholder: "导出包密码",
    type: "password",
    okText: "导出"
  });
  if (pass === null) return; // user cancelled
  const ts = Date.now();
  if (pass && pass.trim()) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pass.trim(), salt, 200000);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = new TextEncoder().encode(JSON.stringify({ encrypted: false, data }));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
    const payload = {
      encrypted: true, v: 3, kdf: "PBKDF2-SHA256-200k",
      saltB64: toB64(salt), iv: toB64(iv), ct: toB64(ct),
      meta: { project: proj.syncId || "" }
    };
    downloadBlob(`authenticator-encrypted-${proj.syncId || "project"}-${ts}.json`,
      new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    toast("已导出加密包", "ok");
  } else {
    downloadBlob(`authenticator-${proj.syncId || "project"}-${ts}.json`,
      new Blob([JSON.stringify({ encrypted: false, data }, null, 2)], { type: "application/json" }));
    toast("已导出", "ok");
  }
}

export async function importFromFile() {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "application/json";
    input.onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) { resolve(false); return; }
      const text = await file.text();
      try {
        const obj = JSON.parse(text);
        // encrypted v3 package
        if (obj && obj.encrypted === true && obj.ct && obj.iv && obj.saltB64) {
          if (!state.currentProjectId || state.currentProjectId === "_all_") {
            toast("请切换到具体项目后再导入加密包", "warn"); resolve(false); return;
          }
          await openImportEncrypted(obj);
          resolve(true); return;
        }
        if (obj && obj.encrypted === false && obj.data) {
          if (!state.currentProjectId || state.currentProjectId === "_all_") {
            toast("请切换到具体项目后再导入", "warn"); resolve(false); return;
          }
          const items = (obj.data.items || []).map(ensureItemDefaults);
          const stat = await mergeIntoCurrent(items, "overwrite");
          toast(`导入完成：新增 ${stat.added}，更新 ${stat.updated}`, "ok");
          resolve(true); return;
        }
        // legacy full-store encrypted
        if (obj && obj.encrypted && obj.meta && obj.data) {
          localStorage.setItem("authenticator.v1.meta", JSON.stringify(obj.meta || {}));
          localStorage.setItem("authenticator.v1", obj.data || "");
          state.key = null; state.encMeta = null; state.unlocked = false; state.items = [];
          toast('已导入加密数据，请在"数据"页解锁', "ok");
          resolve(true); return;
        }
        toast("文件格式不支持", "err");
        resolve(false);
      } catch (e) {
        console.error(e);
        toast("导入失败：文件格式不正确", "err");
        resolve(false);
      }
    };
    input.click();
  });
}

async function openImportEncrypted(pkg) {
  return new Promise((resolve) => {
    const { close, root } = openModal({
      title: "导入加密包",
      bodyHtml: `
        <p class="hint mb-2">输入导出包密码，并选择合并策略。导入目标为当前项目。</p>
        <div class="field">
          <label>导出包密码</label>
          <input id="ip-pass" class="input" type="password" placeholder="请输入密码" />
        </div>
        <div class="field mt-3">
          <label>合并策略</label>
          <div class="row gap-3">
            <label class="row gap-1"><input type="radio" name="ip-merge" value="overwrite" checked /> 覆盖重复</label>
            <label class="row gap-1"><input type="radio" name="ip-merge" value="skip" /> 跳过重复</label>
            <label class="row gap-1"><input type="radio" name="ip-merge" value="keepboth" /> 保留两者</label>
          </div>
        </div>
        <div class="section-card mt-3">
          <h3 class="text-sm" style="margin:0 0 8px;">预检查摘要</h3>
          <div id="ip-summary" class="hint">尚未解密，请点击"预检查/解密"。</div>
          <div id="ip-preview" class="list mt-2"></div>
        </div>
      `,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">取消</button>
          <button class="btn ghost" data-act="check">预检查/解密</button>
          <button class="btn" data-act="ok" disabled>导入</button>
        </div>
      `,
      onMount: (r, doClose) => {
        let items = [];
        r.querySelector('[data-act="cancel"]').addEventListener("click", () => { doClose(); resolve(false); });
        r.querySelector('[data-act="check"]').addEventListener("click", async () => {
          const pass = r.querySelector("#ip-pass").value.trim();
          if (!pass) { toast("请输入密码", "warn"); return; }
          let iter = 200000;
          if (typeof pkg.kdf === "string") { const m = pkg.kdf.match(/(\d+)/); if (m) iter = Number(m[1]) || iter; }
          try {
            const key = await deriveKey(pass, fromB64(pkg.saltB64), iter);
            const iv = fromB64(pkg.iv); const ct = fromB64(pkg.ct);
            const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
            const inner = JSON.parse(new TextDecoder().decode(pt));
            const arr = ((inner && inner.data) ? inner.data.items : inner.items) || [];
            items = arr.map(ensureItemDefaults);
            const proj = getCurrentProject(); if (!proj) { toast("未找到当前项目", "err"); return; }
            const existing = proj.itemsData || [];
            const existingKeys = new Set(existing.map(itemKey));
            let dup = 0, fresh = 0;
            for (const it of items) { if (existingKeys.has(itemKey(it))) dup++; else fresh++; }
            r.querySelector("#ip-summary").textContent =
              `待导入 ${items.length} 条；新增 ${fresh}，可能重复 ${dup}。`;
            const preview = r.querySelector("#ip-preview"); preview.innerHTML = "";
            for (const it of items.slice(0, 8)) {
              const div = document.createElement("div");
              div.className = "list-item";
              div.innerHTML = `
                <div class="li-info">
                  <div class="li-title">${escapeHtml(it.issuer || "")} ${it.account ? "· " + escapeHtml(it.account) : ""}</div>
                  <div class="li-sub">${(it.type || "totp").toUpperCase()} · ${(it.algorithm || "SHA1").toUpperCase()} · ${it.digits || 6}位</div>
                </div>`;
              preview.appendChild(div);
            }
            r.querySelector('[data-act="ok"]').disabled = false;
            toast("解密成功，可点击导入", "ok");
          } catch {
            r.querySelector("#ip-summary").textContent = "解密失败，请检查密码后重试。";
          }
        });
        r.querySelector('[data-act="ok"]').addEventListener("click", async () => {
          if (!items.length) { toast("请先预检查/解密", "warn"); return; }
          const strat = r.querySelector('input[name="ip-merge"]:checked')?.value || "overwrite";
          const stat = await mergeIntoCurrent(items, strat);
          toast(`导入完成：新增 ${stat.added}，更新 ${stat.updated}，跳过 ${stat.kept}`, "ok");
          doClose();
          resolve(true);
        });
      }
    });
  });
}

async function mergeIntoCurrent(rawItems, strategy = "overwrite") {
  const proj = getCurrentProject();
  if (!proj) return { added: 0, updated: 0, kept: 0 };
  const items = proj.itemsData || [];
  const existingByKey = new Map(items.map(it => [itemKey(it), it]));
  const impMap = new Map();
  for (const it of rawItems) {
    const k = itemKey(it);
    const prev = impMap.get(k);
    if (!prev || Number(it.updatedAt || 0) >= Number(prev.updatedAt || 0)) impMap.set(k, it);
  }
  let added = 0, updated = 0, kept = 0;
  for (const [k, it] of impMap.entries()) {
    const exist = existingByKey.get(k);
    if (!exist) {
      const copy = { ...it, id: it.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, deleted: !!it.deleted };
      items.push(copy); added++;
    } else {
      if (strategy === "skip") { kept++; continue; }
      if (strategy === "keepboth") {
        const copy = { ...it, id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}` };
        items.push(copy); added++; continue;
      }
      // overwrite
      const sharesA = Array.isArray(exist.shares) ? exist.shares : [];
      const sharesB = Array.isArray(it.shares) ? it.shares : [];
      const bySid = new Map();
      for (const s of [...sharesA, ...sharesB]) {
        const entry = (typeof s === "string") ? { sid: s } : (s && typeof s.sid === "string" ? { sid: s.sid, k: s.k } : null);
        if (!entry) continue;
        if (!bySid.has(entry.sid)) bySid.set(entry.sid, entry);
        else { const prev = bySid.get(entry.sid); if (!prev.k && entry.k) prev.k = entry.k; }
      }
      exist.type = it.type;
      exist.issuer = it.issuer;
      exist.account = it.account;
      exist.password = typeof it.password === "string" ? it.password : (exist.password || "");
      exist.secret = (it.secret || "").replace(/\s+/g, "").toUpperCase();
      exist.algorithm = (it.algorithm || "SHA1").toUpperCase();
      exist.digits = Number(it.digits || 6);
      exist.period = Number(it.period || 30);
      exist.counter = Number(it.counter || 0);
      exist.deleted = !!it.deleted;
      exist.updatedAt = Number(it.updatedAt || Date.now());
      exist.shares = Array.from(bySid.values());
      updated++;
    }
  }
  proj.itemsData = items;
  saveSyncProjects();
  if (state.currentProjectId === proj.id) state.items = items.map(it => ({ ...it }));
  await persist();
  return { added, updated, kept };
}
