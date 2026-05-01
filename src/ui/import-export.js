// 导入/导出（明文 + 加密包），从原 app.js exportData / importData 移植
import { state, getCurrentProject, persist, ensureItemDefaults, saveSyncProjects } from "../core/storage.js";
import { deriveKey, toB64, fromB64 } from "../core/crypto.js";
import { buildMigrationUrls } from "../core/totp.js";
import { detectMigrationFile, decryptAndParseAndOtpBackup } from "../core/migration-formats.js";
import { renderQrSvg } from "../core/qrgen.js";
import { itemKey } from "../sync/sync.js";
import { downloadBlob } from "../ui/toast.js";
import { promptDialog, openModal, confirmDialog } from "../ui/modal.js";
import { toast, escapeHtml } from "../ui/toast.js";

// 访客模式 = 没有任何同步项目（包含未登录管理员、纯本地用户）。
// 访客的 2FA 账户直接保存在 state.items 中（落地到 LS_KEY），
// 不属于任何 syncProjects，因此导入/导出需要直接读写 state.items。
function isGuestMode() {
  return !Array.isArray(state.syncProjects) || state.syncProjects.length === 0;
}

// 当前导入/导出的目标作用域。返回值含义：
// - kind = "project"：写入指定 syncProject 的 itemsData
// - kind = "guest"  ：写入 state.items（直接 persist）
// - kind = "none"   ：当前作用域不可写（汇总视图等）
function activeScope() {
  if (state.currentProjectId === "_all_") return { kind: "none", reason: "汇总视图为只读" };
  const proj = getCurrentProject();
  if (proj) return { kind: "project", proj };
  if (isGuestMode()) return { kind: "guest" };
  return { kind: "none", reason: "请切换到具体项目" };
}

export async function exportCurrent() {
  const { scope, cleaned, sourceLabel } = collectCurrentProjectExportItems();
  if (!scope) return;
  if (!cleaned.length) {
    toast(scope.kind === "guest" ? "本地暂无可导出的账户" : "当前项目没有可导出的账户", "warn");
    return;
  }
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
  const projectTag = scope.kind === "project"
    ? (scope.proj.syncId || scope.proj.id || "project")
    : "guest-local";
  if (pass && pass.trim()) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pass.trim(), salt, 200000);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = new TextEncoder().encode(JSON.stringify({ encrypted: false, data }));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
    const payload = {
      encrypted: true, v: 3, kdf: "PBKDF2-SHA256-200k",
      saltB64: toB64(salt), iv: toB64(iv), ct: toB64(ct),
      meta: {
        project: scope.kind === "project" ? (scope.proj.syncId || "") : "",
        source: sourceLabel,
      }
    };
    downloadBlob(`authenticator-encrypted-${projectTag}-${ts}.json`,
      new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    toast("已导出加密包", "ok");
  } else {
    // 3.1 明文导出二次确认
    const ok = await confirmDialog({
      title: "确定导出明文？",
      message: `将以明文 JSON 导出 ${cleaned.length} 个 2FA Secret。任何拿到该文件的人都能直接生成验证码。强烈建议返回上一步并设置密码。`,
      danger: true,
      okText: "我已理解，导出明文",
      cancelText: "返回",
    });
    if (!ok) { toast("已取消明文导出", "warn"); return; }
    downloadBlob(`authenticator-${projectTag}-${ts}.json`,
      new Blob([JSON.stringify({ encrypted: false, data }, null, 2)], { type: "application/json" }));
    toast("已导出明文文件，请妥善保管", "warn", 3200);
  }
}

export async function exportCurrentMigrationQrs() {
  const { scope, cleaned } = collectCurrentProjectExportItems();
  if (!scope) return;
  if (!cleaned.length) {
    toast(scope.kind === "guest" ? "本地暂无可导出的账户" : "当前项目没有可导出的账户", "warn");
    return;
  }
  const groups = [];
  for (let i = 0; i < cleaned.length; i += 10) {
    const items = cleaned.slice(i, i + 10);
    const url = buildMigrationUrls(items, 10)[0];
    if (!url) continue;
    groups.push({ index: groups.length + 1, items, url });
  }
  if (!groups.length) {
    toast("没有可生成二维码的账户", "warn");
    return;
  }

  const projectTag = scope.kind === "project"
    ? (scope.proj.syncId || scope.proj.name || "project")
    : "guest-local";

  openModal({
    title: "批量迁移二维码",
    bodyHtml: `
      <div class="col gap-2">
        <div class="section-card">
          <div class="text-sm" style="font-weight:600; margin-bottom:6px;">Google Authenticator / 支持 otpauth-migration 的应用可逐张扫码导入</div>
          <div class="hint" style="line-height:1.7;">
            本次共 ${cleaned.length} 条账户，已按每张最多 10 条拆成 ${groups.length} 张二维码。请按顺序扫描，不要跳过中间批次。
          </div>
        </div>
        <div id="migration-qr-list" class="col gap-2"></div>
      </div>
    `,
    footerHtml: `
      <div class="btn-row right">
        <button class="btn ghost" data-act="close">完成</button>
      </div>
    `,
    onMount: (root, close) => {
      root.querySelector('[data-act="close"]')?.addEventListener("click", () => close("done"));
      const list = root.querySelector("#migration-qr-list");
      for (const group of groups) {
        const names = group.items.slice(0, 3)
          .map((it) => `${it.issuer || ""}${it.account ? ` · ${it.account}` : ""}`.trim() || "未命名")
          .join(" / ");
        const card = document.createElement("div");
        card.className = "migration-qr-card";
        card.innerHTML = `
          <div class="migration-qr-head">
            <div>
              <div class="migration-qr-title">第 ${group.index} / ${groups.length} 张</div>
              <div class="migration-qr-sub">${group.items.length} 条账户${names ? ` · ${escapeHtml(names)}` : ""}</div>
            </div>
            <div class="btn-row">
              <button class="btn ghost sm" data-act="copy">复制 URI</button>
              <button class="btn ghost sm" data-act="download">下载 SVG</button>
            </div>
          </div>
          <div class="migration-qr-stage center"></div>
        `;
        const stage = card.querySelector(".migration-qr-stage");
        const svg = renderQrSvg(group.url, { pixelSize: 6 });
        stage.innerHTML = svg;
        stage.querySelector("svg")?.setAttribute("aria-label", `迁移二维码第 ${group.index} 张`);
        card.querySelector('[data-act="copy"]')?.addEventListener("click", async () => {
          try {
            const { copyText } = await import("../ui/toast.js");
            const ok = await copyText(group.url);
            toast(ok ? `已复制第 ${group.index} 张 URI` : "复制失败", ok ? "ok" : "err");
          } catch {
            toast("复制失败", "err");
          }
        });
        card.querySelector('[data-act="download"]')?.addEventListener("click", () => {
          downloadBlob(
            `migration-${sanitizeFileName(projectTag)}-${group.index}.svg`,
            new Blob([svg], { type: "image/svg+xml;charset=utf-8" })
          );
        });
        list.appendChild(card);
      }
    }
  });
}

export async function importFromFile() {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,.csv,.aes,application/json,text/csv,application/octet-stream";
    input.onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) { resolve(false); return; }
      const ok = await importFromFileHandle(file);
      resolve(ok);
    };
    input.click();
  });
}

// 3.3 通用文件入口（拖拽或选择）
export async function importFromFileHandle(file) {
  if (!file) return false;
  try {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const text = new TextDecoder().decode(bytes);
    let obj = null;
    try { obj = JSON.parse(text); } catch {}
    // encrypted v3 package
    if (obj && obj.encrypted === true && obj.ct && obj.iv && obj.saltB64) {
      if (!ensureWritableScope("加密包")) return false;
      await openImportEncrypted(obj);
      return true;
    }
    if (obj && obj.encrypted === false && obj.data) {
      if (!ensureWritableScope()) return false;
      const items = (obj.data.items || []).map(ensureItemDefaults);
      const stat = await mergeIntoCurrent(items, "overwrite");
      toast(`导入完成：新增 ${stat.added}，更新 ${stat.updated}`, "ok");
      return true;
    }
    // legacy full-store encrypted
    if (obj && obj.encrypted && obj.meta && obj.data) {
      localStorage.setItem("authenticator.v1.meta", JSON.stringify(obj.meta || {}));
      localStorage.setItem("authenticator.v1", obj.data || "");
      state.key = null; state.encMeta = null; state.unlocked = false; state.items = [];
      toast('已导入加密数据，请在"数据"页解锁', "ok");
      return true;
    }
    const migration = detectMigrationFile({ fileName: file.name || "", text, bytes, json: obj });
    if (migration) {
      if (!ensureWritableScope()) return false;
      if (migration.kind === "unsupported") {
        toast(migration.error || "文件格式暂不支持", "warn", 3600);
        return false;
      }
      if (migration.kind === "andotp-encrypted") {
        const pass = await promptDialog({
          title: "导入 andOTP 加密备份",
          label: "请输入 andOTP 备份密码",
          placeholder: "备份密码",
          type: "password",
          okText: "解密"
        });
        if (pass === null) return false;
        try {
          const parsed = await decryptAndParseAndOtpBackup(bytes, pass.trim());
          if (!parsed.items.length) {
            toast(parsed.warnings?.[0] || "未发现可导入的 2FA 账户", "warn");
            return false;
          }
          return await openImportPreview(parsed);
        } catch (e) {
          toast(e?.message || "andOTP 备份解密失败", "err");
          return false;
        }
      }
      if (!migration.items.length) {
        toast(migration.warnings?.[0] || "未发现可导入的 2FA 账户", "warn");
        return false;
      }
      return await openImportPreview(migration);
    }
    toast("文件格式不支持", "err");
    return false;
  } catch (e) {
    console.error(e);
    toast("导入失败：文件格式不正确", "err");
    return false;
  }
}

// 检查当前是否处于可写作用域。汇总视图返回 false；
// 普通项目或访客模式（无项目）均允许写入。
function ensureWritableScope(label = "") {
  const scope = activeScope();
  if (scope.kind === "none") {
    const tip = label ? `请切换到具体项目后再导入${label}` : (scope.reason || "请切换到具体项目后再导入");
    toast(tip, "warn");
    return false;
  }
  return true;
}

async function openImportEncrypted(pkg) {
  return new Promise((resolve) => {
    const { close, root } = openModal({
      title: "导入加密包",
      bodyHtml: `
        <p class="hint mb-2">输入导出包密码，并选择合并策略。导入目标为${state.syncProjects?.length ? "当前项目" : "本地账户库"}。</p>
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
            const existing = currentScopeItems();
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

async function openImportPreview(result) {
  return new Promise((resolve) => {
    const { items, format, total = 0, imported = items.length, skipped = Math.max(0, total - items.length), warnings = [] } = result || {};
    const summary = `检测到 ${format}：共 ${total} 条记录，可导入 ${imported} 条，跳过 ${skipped} 条。`;
    const warningHtml = warnings.length
      ? `<div class="section-card mt-2"><div class="text-sm" style="font-weight:600; margin-bottom:6px;">注意</div><ul class="hint" style="margin:0; padding-left:18px;">${warnings.map((msg) => `<li>${escapeHtml(msg)}</li>`).join("")}</ul></div>`
      : "";

    openModal({
      title: `导入 ${format}`,
      bodyHtml: `
        <p class="hint mb-2">${escapeHtml(summary)}</p>
        <div class="field mt-3">
          <label>合并策略</label>
          <div class="row gap-3">
            <label class="row gap-1"><input type="radio" name="ip-merge" value="overwrite" checked /> 覆盖重复</label>
            <label class="row gap-1"><input type="radio" name="ip-merge" value="skip" /> 跳过重复</label>
            <label class="row gap-1"><input type="radio" name="ip-merge" value="keepboth" /> 保留两者</label>
          </div>
        </div>
        ${warningHtml}
        <div class="section-card mt-3">
          <h3 class="text-sm" style="margin:0 0 8px;">预览</h3>
          <div id="ip-preview" class="list"></div>
        </div>
      `,
      footerHtml: `
        <div class="btn-row right">
          <button class="btn ghost" data-act="cancel">取消</button>
          <button class="btn" data-act="ok">导入</button>
        </div>
      `,
      onMount: (r, doClose) => {
        const preview = r.querySelector("#ip-preview");
        for (const it of items.slice(0, 12)) {
          const div = document.createElement("div");
          div.className = "list-item";
          div.innerHTML = `
            <div class="li-info">
              <div class="li-title">${escapeHtml(it.issuer || "")}${it.account ? ` · ${escapeHtml(it.account)}` : ""}</div>
              <div class="li-sub">${(it.type || "totp").toUpperCase()} · ${(it.algorithm || "SHA1").toUpperCase()} · ${it.digits || 6}位${it.type === "hotp" ? ` · counter ${it.counter || 0}` : ` · ${it.period || 30}s`}</div>
            </div>`;
          preview.appendChild(div);
        }
        r.querySelector('[data-act="cancel"]')?.addEventListener("click", () => {
          doClose();
          resolve(false);
        });
        r.querySelector('[data-act="ok"]')?.addEventListener("click", async () => {
          const strat = r.querySelector('input[name="ip-merge"]:checked')?.value || "overwrite";
          const stat = await mergeIntoCurrent(items, strat);
          const tail = skipped ? `；源文件另有 ${skipped} 条未导入` : "";
          toast(`导入完成：新增 ${stat.added}，更新 ${stat.updated}，跳过 ${stat.kept}${tail}`, "ok");
          doClose();
          resolve(true);
        });
      }
    });
  });
}

async function mergeIntoCurrent(rawItems, strategy = "overwrite") {
  const scope = activeScope();
  if (scope.kind === "none") return { added: 0, updated: 0, kept: 0 };

  // 数据源：项目 itemsData 或访客 state.items
  const items = scope.kind === "project"
    ? (Array.isArray(scope.proj.itemsData) ? scope.proj.itemsData : (scope.proj.itemsData = []))
    : (Array.isArray(state.items) ? state.items : (state.items = []));

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

  if (scope.kind === "project") {
    scope.proj.itemsData = items;
    saveSyncProjects();
    if (state.currentProjectId === scope.proj.id) state.items = items.map(it => ({ ...it }));
  } else {
    // 访客模式：state.items 即源数据，直接 persist
    state.items = items;
  }
  await persist();
  return { added, updated, kept };
}

function collectCurrentProjectExportItems() {
  const scope = activeScope();
  if (scope.kind === "none") {
    toast(scope.reason
      ? `${scope.reason}再导出。汇总视图请使用管理员面板的全部解密导出。`
      : "请先切换到具体项目再导出。",
      "warn");
    return { scope: null, cleaned: [] };
  }

  const rawItems = scope.kind === "project"
    ? (Array.isArray(scope.proj.itemsData) ? scope.proj.itemsData.slice() : [])
    : (Array.isArray(state.items) ? state.items.slice() : []);

  const map = new Map();
  for (const it of rawItems) {
    if (it.deleted) continue;
    const k = itemKey(it);
    const prev = map.get(k);
    if (!prev || Number(it.updatedAt || 0) >= Number(prev.updatedAt || 0)) map.set(k, it);
  }

  const sourceLabel = scope.kind === "project" ? (scope.proj.name || scope.proj.syncId || "project") : "本地账户库";
  return { scope, cleaned: Array.from(map.values()), sourceLabel };
}

// 当前作用域已存在的条目（用于预检查）
function currentScopeItems() {
  const scope = activeScope();
  if (scope.kind === "project") return Array.isArray(scope.proj.itemsData) ? scope.proj.itemsData : [];
  if (scope.kind === "guest") return Array.isArray(state.items) ? state.items : [];
  return [];
}

function sanitizeFileName(value) {
  return String(value || "part").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 64);
}
