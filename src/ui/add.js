// 统一添加面板：Tab 切换 扫码 / 粘贴密钥 / 从链接
// 模态形式打开

import { openModal } from "./modal.js";
import { toast } from "./toast.js";
import { parseOtpAuth, parseOtpAuthMigration, codeForItem, formatCode, secondsLeft } from "../core/totp.js";

export function openAddModal({ onSubmit, onScan } = {}) {
  let activeTab = "manual";
  const { close, root } = openModal({
    title: "添加 2FA 账户",
    bodyHtml: `
      <div class="segmented" role="tablist" id="add-tabs">
        <button class="seg active" type="button" id="add-tab-manual" role="tab" aria-selected="true" aria-controls="add-pane-manual" tabindex="0" data-tab="manual">粘贴密钥</button>
        <button class="seg" type="button" id="add-tab-scan" role="tab" aria-selected="false" aria-controls="add-pane-scan" tabindex="-1" data-tab="scan">扫描二维码</button>
        <button class="seg" type="button" id="add-tab-link" role="tab" aria-selected="false" aria-controls="add-pane-link" tabindex="-1" data-tab="link">从链接</button>
      </div>

      <div class="add-pane mt-3" id="add-pane-manual" role="tabpanel" aria-labelledby="add-tab-manual" data-pane="manual">
        <div class="field">
          <label>密钥 Secret <span class="muted">（Base32 格式）</span></label>
          <input id="f-secret" class="input mono" placeholder="HKGZ HPK2 T7VV GP7Q 6CGG 6KKC UKLQ 4JAL" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" />
        </div>
        <div class="field mt-2">
          <label>服务名称（issuer）</label>
          <input id="f-issuer" class="input" placeholder="如：GitHub、Google" />
        </div>
        <div class="field mt-2">
          <label>账号 <span class="muted">（可选）</span></label>
          <input id="f-account" class="input" placeholder="如：me@example.com" />
        </div>
        <div class="field mt-2">
          <label>密码 <span class="muted">（可选）</span></label>
          <div class="input-with-toggle">
            <input id="f-password" class="input" type="password" placeholder="如需一起保存可填写" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" />
            <button type="button" class="toggle" data-toggle-password>👁</button>
          </div>
        </div>

        <details class="mt-3" id="adv">
          <summary class="hint" style="cursor:pointer; user-select:none;">高级选项（算法 / 位数 / 周期 / HOTP）</summary>
          <div class="col mt-2">
            <div class="row gap-2">
              <div class="field grow">
                <label>类型</label>
                <select id="f-type" class="input">
                  <option value="totp">TOTP（基于时间）</option>
                  <option value="hotp">HOTP（基于计数器）</option>
                </select>
              </div>
              <div class="field grow">
                <label>算法</label>
                <select id="f-algo" class="input">
                  <option>SHA1</option>
                  <option>SHA256</option>
                  <option>SHA512</option>
                </select>
              </div>
            </div>
            <div class="row gap-2">
              <div class="field grow">
                <label>位数</label>
                <select id="f-digits" class="input">
                  <option selected>6</option>
                  <option>4</option>
                  <option>8</option>
                </select>
              </div>
              <div class="field grow" id="f-period-wrap">
                <label>周期 (秒)</label>
                <input id="f-period" class="input" type="number" value="30" min="5" />
              </div>
              <div class="field grow hidden" id="f-counter-wrap">
                <label>初始计数器</label>
                <input id="f-counter" class="input" type="number" value="0" min="0" />
              </div>
            </div>
          </div>
        </details>
      </div>

      <div class="add-pane hidden" id="add-pane-scan" role="tabpanel" aria-labelledby="add-tab-scan" data-pane="scan" hidden>
        <p class="hint mb-2">摄像头实时识别（需要 HTTPS）或选择本机图片。</p>
        <div class="scanner-stage">
          <video id="scan-video" playsinline muted></video>
          <canvas id="scan-canvas"></canvas>
          <div class="frame-corners"><i></i></div>
        </div>
        <div class="btn-row mt-3">
          <button class="btn" id="scan-start">📷 启动摄像头</button>
          <label class="btn ghost" for="scan-file">🖼 选择图片
            <input type="file" id="scan-file" accept="image/*" hidden />
          </label>
          <button class="btn ghost" id="scan-stop">停止</button>
        </div>
        <p class="hint mt-2" id="scan-hint">提示：扫描 Google Authenticator 导出二维码可批量导入。</p>
      </div>

      <div class="add-pane hidden" id="add-pane-link" role="tabpanel" aria-labelledby="add-tab-link" data-pane="link" hidden>
        <p class="hint mb-2">支持 <code>otpauth://...</code> 单条链接，或 Google Authenticator 的 <code>otpauth-migration://...</code> 批量迁移格式。</p>
        <div class="field">
          <label>otpauth 链接</label>
          <textarea id="f-otpauth" class="input" placeholder="otpauth://totp/Issuer:Account?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30"></textarea>
        </div>
      </div>
    `,
    footerHtml: `
      <div class="btn-row right">
        <button class="btn ghost" data-act="cancel">取消</button>
        <button class="btn ghost" data-act="ok-keep">保存并继续</button>
        <button class="btn" data-act="ok">添加</button>
      </div>
    `,
    onMount: (r, doClose) => {
      const tabs = r.querySelectorAll("[data-tab]");
      const panes = r.querySelectorAll("[data-pane]");
      const setActiveTab = (nextTab) => {
        activeTab = nextTab;
        tabs.forEach(x => {
          const active = x.dataset.tab === activeTab;
          x.classList.toggle("active", active);
          x.setAttribute("aria-selected", active ? "true" : "false");
          x.tabIndex = active ? 0 : -1;
        });
        panes.forEach(p => {
          const active = p.dataset.pane === activeTab;
          p.classList.toggle("hidden", !active);
          p.toggleAttribute("hidden", !active);
        });
        // 手动模式才显示"保存并继续"
        const keepBtn = r.querySelector('[data-act="ok-keep"]');
        if (keepBtn) keepBtn.style.display = activeTab === "manual" ? "" : "none";
        if (activeTab === "scan" && typeof onScan === "function") {
          if (!r.dataset.scannerBound) {
            r.dataset.scannerBound = "1";
            onScan(r, doClose);
          }
        }
      };
      tabs.forEach(t => t.addEventListener("click", () => {
        setActiveTab(t.dataset.tab);
      }));
      tabs.forEach((t) => t.addEventListener("keydown", (e) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
        e.preventDefault();
        const list = Array.from(tabs);
        const current = list.indexOf(t);
        let next = current;
        if (e.key === "Home") next = 0;
        else if (e.key === "End") next = list.length - 1;
        else if (e.key === "ArrowRight") next = (current + 1) % list.length;
        else if (e.key === "ArrowLeft") next = (current - 1 + list.length) % list.length;
        const target = list[next];
        if (!target) return;
        setActiveTab(target.dataset.tab);
        target.focus();
      }));
      setActiveTab(activeTab);

      const typeSel = r.querySelector("#f-type");
      const passwordToggle = r.querySelector("[data-toggle-password]");
      if (passwordToggle) {
        passwordToggle.addEventListener("click", () => {
          const inp = r.querySelector("#f-password");
          inp.type = inp.type === "password" ? "text" : "password";
        });
      }
      typeSel.addEventListener("change", () => {
        const isHotp = typeSel.value === "hotp";
        r.querySelector("#f-period-wrap").classList.toggle("hidden", isHotp);
        r.querySelector("#f-counter-wrap").classList.toggle("hidden", !isHotp);
      });

      r.querySelector("#f-secret").focus();

      r.querySelector('[data-act="cancel"]').addEventListener("click", doClose);
      r.querySelector('[data-act="ok"]').addEventListener("click", () => {
        if (activeTab === "manual") {
          const item = collectManual(r);
          if (!item) return;
          onSubmit?.([item]);
          doClose();
        } else if (activeTab === "link") {
          const items = collectLink(r);
          if (!items || !items.length) return;
          onSubmit?.(items);
          doClose();
        }
      });
      r.querySelector('[data-act="ok-keep"]').addEventListener("click", () => {
        if (activeTab !== "manual") return;
        const item = collectManual(r);
        if (!item) return;
        onSubmit?.([item]);
        // 保留焦点，清空 secret/issuer/account/password 准备下一条
        r.querySelector("#f-secret").value = "";
        r.querySelector("#f-issuer").value = "";
        r.querySelector("#f-account").value = "";
        const pw = r.querySelector("#f-password"); if (pw) pw.value = "";
        r.querySelector("#f-secret").focus();
      });
    }
  });
  return { close, root };
}

export function openEditModal(item, { onSubmit } = {}) {
  const initial = normalizeItem(item);
  openModal({
    title: "编辑 2FA 账户",
    bodyHtml: `
      <div class="field">
        <label>密钥 Secret <span class="muted">（Base32 格式）</span></label>
        <input id="f-secret" class="input mono" value="${escapeAttr(initial.secret)}" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" />
      </div>
      <div class="field mt-2">
        <label>服务名称（issuer）</label>
        <input id="f-issuer" class="input" value="${escapeAttr(initial.issuer)}" />
      </div>
      <div class="field mt-2">
        <label>账号 <span class="muted">（可选）</span></label>
        <input id="f-account" class="input" value="${escapeAttr(initial.account)}" />
      </div>
      <div class="field mt-2">
        <label>密码 <span class="muted">（可选）</span></label>
        <div class="input-with-toggle">
          <input id="f-password" class="input" type="password" value="${escapeAttr(initial.password)}" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" />
          <button type="button" class="toggle" data-toggle-password>👁</button>
        </div>
      </div>

      <details class="mt-3" id="adv" open>
        <summary class="hint" style="cursor:pointer; user-select:none;">高级选项（算法 / 位数 / 周期 / HOTP）</summary>
        <div class="col mt-2">
          <div class="row gap-2">
            <div class="field grow">
              <label>类型</label>
              <select id="f-type" class="input">
                <option value="totp" ${initial.type === "totp" ? "selected" : ""}>TOTP（基于时间）</option>
                <option value="hotp" ${initial.type === "hotp" ? "selected" : ""}>HOTP（基于计数器）</option>
              </select>
            </div>
            <div class="field grow">
              <label>算法</label>
              <select id="f-algo" class="input">
                <option ${initial.algorithm === "SHA1" ? "selected" : ""}>SHA1</option>
                <option ${initial.algorithm === "SHA256" ? "selected" : ""}>SHA256</option>
                <option ${initial.algorithm === "SHA512" ? "selected" : ""}>SHA512</option>
              </select>
            </div>
          </div>
          <div class="row gap-2">
            <div class="field grow">
              <label>位数</label>
              <select id="f-digits" class="input">
                <option ${initial.digits === 4 ? "selected" : ""}>4</option>
                <option ${initial.digits === 6 ? "selected" : ""}>6</option>
                <option ${initial.digits === 8 ? "selected" : ""}>8</option>
              </select>
            </div>
            <div class="field grow ${initial.type === "hotp" ? "hidden" : ""}" id="f-period-wrap">
              <label>周期 (秒)</label>
              <input id="f-period" class="input" type="number" value="${initial.period}" min="5" />
            </div>
            <div class="field grow ${initial.type === "hotp" ? "" : "hidden"}" id="f-counter-wrap">
              <label>计数器</label>
              <input id="f-counter" class="input" type="number" value="${initial.counter}" min="0" />
            </div>
          </div>
        </div>
      </details>

      <!-- 3.6 实时预览 -->
      <div class="section-card mt-3" id="edit-preview" style="text-align:center;">
        <div class="text-xs muted" style="margin-bottom:4px;">实时预览</div>
        <div id="edit-preview-code" style="font-family: var(--font-mono); font-size: 28px; letter-spacing: 4px; font-weight: 700;">— —</div>
        <div id="edit-preview-meta" class="text-xs muted" style="margin-top:4px;"></div>
      </div>
    `,
    footerHtml: `
      <div class="btn-row right">
        <button class="btn ghost" data-act="cancel">取消</button>
        <button class="btn" data-act="ok">保存</button>
      </div>
    `,
    onMount: (r, doClose) => {
      const typeSel = r.querySelector("#f-type");
      const passwordToggle = r.querySelector("[data-toggle-password]");
      if (passwordToggle) {
        passwordToggle.addEventListener("click", () => {
          const inp = r.querySelector("#f-password");
          inp.type = inp.type === "password" ? "text" : "password";
        });
      }
      typeSel.addEventListener("change", () => {
        const isHotp = typeSel.value === "hotp";
        r.querySelector("#f-period-wrap").classList.toggle("hidden", isHotp);
        r.querySelector("#f-counter-wrap").classList.toggle("hidden", !isHotp);
        previewSchedule();
      });

      r.querySelector("#f-secret").focus();

      // 3.6 预览：表单变化即更新
      const previewCode = r.querySelector("#edit-preview-code");
      const previewMeta = r.querySelector("#edit-preview-meta");
      let previewTimer = null;
      async function doPreview() {
        const cur = collectManualSilent(r);
        if (!cur || !cur.secret) {
          previewCode.textContent = "— —";
          previewMeta.textContent = "请输入 Secret";
          return;
        }
        try {
          const code = await codeForItem(cur);
          previewCode.textContent = formatCode(code, cur.digits);
          if (cur.type === "totp") {
            const left = secondsLeft(cur.period);
            previewMeta.textContent = `${cur.algorithm} · ${cur.digits}位 · ${cur.period}s · 还剩 ${left}s`;
          } else {
            previewMeta.textContent = `${cur.algorithm} · ${cur.digits}位 · counter=${cur.counter}`;
          }
        } catch {
          previewCode.textContent = "ERR";
          previewMeta.textContent = "Secret 无效";
        }
      }
      function previewSchedule() {
        if (previewTimer) clearTimeout(previewTimer);
        previewTimer = setTimeout(doPreview, 100);
      }
      ["#f-secret", "#f-algo", "#f-digits", "#f-period", "#f-counter"].forEach(sel => {
        r.querySelector(sel)?.addEventListener("input", previewSchedule);
        r.querySelector(sel)?.addEventListener("change", previewSchedule);
      });
      doPreview();
      const tick = setInterval(doPreview, 1000);
      // 关闭模态时清 ticker
      const obs = new MutationObserver(() => {
        if (!document.body.contains(r)) { clearInterval(tick); obs.disconnect(); }
      });
      obs.observe(document.body, { childList: true, subtree: true });

      r.querySelector('[data-act="cancel"]').addEventListener("click", doClose);
      r.querySelector('[data-act="ok"]').addEventListener("click", () => {
        const next = collectManual(r);
        if (!next) return;
        onSubmit?.(next);
        doClose();
      });
    }
  });
}

// 静默版本（不弹 toast，用于实时预览）
function collectManualSilent(r) {
  const secret = (r.querySelector("#f-secret")?.value || "").trim().replace(/\s+/g, "").toUpperCase();
  if (!secret) return null;
  const type = r.querySelector("#f-type").value;
  const item = {
    type,
    issuer: r.querySelector("#f-issuer").value.trim(),
    account: r.querySelector("#f-account").value.trim(),
    secret,
    algorithm: r.querySelector("#f-algo").value,
    digits: Number(r.querySelector("#f-digits").value || 6),
  };
  if (type === "totp") item.period = Number(r.querySelector("#f-period").value || 30);
  else item.counter = Number(r.querySelector("#f-counter").value || 0);
  return item;
}

function collectManual(r) {
  const secret = r.querySelector("#f-secret").value.trim().replace(/\s+/g, "").toUpperCase();
  if (!secret) { toast("请输入 Secret", "warn"); return null; }
  const type = r.querySelector("#f-type").value;
  const item = {
    type,
    issuer: r.querySelector("#f-issuer").value.trim(),
    account: r.querySelector("#f-account").value.trim(),
    password: r.querySelector("#f-password")?.value ?? "",
    secret,
    algorithm: r.querySelector("#f-algo").value,
    digits: Number(r.querySelector("#f-digits").value || 6),
  };
  if (type === "totp") item.period = Number(r.querySelector("#f-period").value || 30);
  else item.counter = Number(r.querySelector("#f-counter").value || 0);
  return item;
}

function collectLink(r) {
  const txt = r.querySelector("#f-otpauth").value.trim();
  if (!txt) { toast("请粘贴 otpauth 链接", "warn"); return null; }
  if (txt.startsWith("otpauth-migration://") || /^[A-Za-z0-9_\-]+=*$/.test(txt)) {
    const items = parseOtpAuthMigration(txt);
    if (!items.length) { toast("未解析到迁移数据", "err"); return null; }
    return items;
  }
  const item = parseOtpAuth(txt);
  if (!item || !item.secret) { toast("链接无效", "err"); return null; }
  return [item];
}

function normalizeItem(item) {
  return {
    type: item?.type === "hotp" ? "hotp" : "totp",
    issuer: item?.issuer || "",
    account: item?.account || "",
    password: item?.password || "",
    secret: (item?.secret || "").replace(/\s+/g, "").toUpperCase(),
    algorithm: (item?.algorithm || "SHA1").toUpperCase(),
    digits: Number(item?.digits || 6),
    period: Number(item?.period || 30),
    counter: Number(item?.counter || 0),
  };
}

function escapeAttr(str) {
  const div = document.createElement("div");
  div.textContent = String(str ?? "");
  return div.innerHTML.replace(/"/g, "&quot;");
}
