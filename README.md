Web 2FA Authenticator（Cloudflare Pages）

简介
- 纯前端 2FA 验证器，兼容 Google/Microsoft Authenticator 的 TOTP（otpauth）与 Google 迁移导出（protobuf）。
- 支持算法 SHA1/SHA256/SHA512、6/8 位、周期可设（默认 30s），HOTP 计数器可用。
- 导入：粘贴 otpauth、扫码识别（或选图识别）、迁移导出；手动 Base32 秘钥（可含空格分组）。
- 存储：本地加密（主密码，PBKDF2 + AES‑GCM）、导入/导出备份、PWA 离线。
- 同步：端到端加密 + Cloudflare KV，多设备自动同步；可选写入校验（Server Token）。
- 分享：单条 TOTP 只读页面（服务端仅存密文；支持默认/自定义/永久有效期，支持撤销）。

使用场景与限制
- 面向“一次性验证码生成”，不包含厂商推送审批功能。

目录结构（要点）
- 前端：`index.html`、`styles.css`、`app.js`、`shared.html`、`shared.js`、`sw.js`、`manifest.webmanifest`
- Functions：
  - 同步：`functions/api/sync/[id].js`
  - 分享：`functions/api/share/[id].js`
  - 门禁：`functions/api/gate.js` + `_middleware.js`

快速开始
1) 本地静态预览：直接打开 `index.html`。
2) 本地端到端测试（含 Functions + 真实 KV）：
   - 安装 wrangler 并登录：`npm i -g wrangler && wrangler login`
   - 创建 KV：
     - 生产：`wrangler kv:namespace create AUTH_KV`
     - 预览：`wrangler kv:namespace create AUTH_KV --preview`
   - 复制示例：`cp wrangler.toml.example wrangler.toml`，填入 `id/preview_id` 与可选 `SYNC_TOKEN`
   - 启动：`npm run dev`（HTTP）或 `npm run dev:https`（HTTPS）
3) dev:remote（直连云端开发）：
   - 保留本地 `wrangler.toml`（不提交仓库）
   - 运行：`npm run dev:remote`（等价 `wrangler pages dev . --remote`）
   - Pages 仪表盘设置的 `ACCESS_GATE/SYNC_TOKEN/SHARE_TTL` 将直接生效

部署到 Cloudflare Pages
1) 创建项目：Connect to Git 或 Direct Upload；Build command 留空；Output directory 填 `/`。
2) 绑定 Functions：Settings → Functions → KV bindings → Add → Variable name：`AUTH_KV`（选择/新建命名空间，建议区分 Preview/Production）。
3) 环境变量（可选但推荐按需设置）：Settings → Environment variables → Add
   - `SYNC_TOKEN`：Server Token（强随机字符串）。启用后，前端“Server Token”需同值才能推送/分享（写入）。
   - `ACCESS_GATE`：全局门禁访问口令（非空即启用）。启用后，所有设备首次访问需输入口令（发放 7 天 HttpOnly Cookie）。
   - `SHARE_TTL`：分享默认有效期（秒）。默认 86400（24h）；设为 0/负数/perm 表示永久。
4) 验证访问：
   - 同步面板填相同 Sync ID/Sync Secret（跨设备一致），如启用校验则填 Server Token。
   - 勾选“自动同步”，一端“推送”，另一端“拉取”或等待自动拉取。

核心功能
- TOTP/HOTP 生成：
  - TOTP 倒计时、临期高亮；HOTP 提供“下一次”按钮递增计数器。
  - 导入方式：otpauth 链接、扫码/选图识别、迁移导出（protobuf）、手动 Base32（支持分组空格）。
- 本地加密与解锁：
  - 可设置“主密码”（PBKDF2 + AES‑GCM）加密本地存储；仅本地有效，不与云端同步。
- 多设备同步：
  - 使用 Sync ID + Sync Secret 进行 E2E 加密；云端仅存密文。
  - 可开启自动同步（启动拉取、每 60s 拉取、保存后自动推送）。
  - 若启用 `SYNC_TOKEN`，写入（推送/分享）需在前端填写同值的“Server Token”，拉取不受影响。
- 全局门禁（ACCESS_GATE）：
  - 开启后，首次访问弹出“访问口令”对话框；通过后发 7 天 HttpOnly Cookie。
  - 未通过门禁时，除分享读取（/api/share GET/HEAD）与门禁 API 外，其余 API 返回 401。
  - 静态页面照常加载，由前端弹窗拦截交互，避免重定向循环。
- 分享（单条 TOTP 只读页面）：
  - “分享”会本地加密该条目参数，仅将密文写 KV；链接的解密密钥置于 URL 片段（#），服务端不可见。
  - 可选有效期：默认（由 `SHARE_TTL` 控制）、1h/24h/永久/自定义小时；也可在后端设置永久（`SHARE_TTL=0/perm`）。
  - 仅 KV 数据可用：若 KV 不存在 `share:<SID>`，`shared.html` 显示“分享不存在或已过期”。
  - 撤销：
    - 同步面板“撤销分享”粘贴链接或 SID 删除；或 `DELETE /api/share/<SID>`（启用校验需 `X-Token: <SYNC_TOKEN>`）。
    - 删除原验证码时，系统会自动尝试撤销与其关联的分享（需具备 Server Token 时方可成功）。

环境变量一览
- `AUTH_KV`（绑定）：KV 命名空间绑定名（Pages UI 配置）。
- `SYNC_TOKEN`（可选）：Server Token。前端“Server Token”需同值才能写入 KV。
- `ACCESS_GATE`（可选）：全局门禁访问口令。非空启用；首次访问需输入；Cookie 有效 7 天。
- `SHARE_TTL`（可选）：分享默认有效期（秒）。默认 86400；0/负数/`perm` 代表永久。

生成 SYNC_TOKEN 示例
- OpenSSL：`openssl rand -base64 32`
- Node.js：`node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
- PowerShell：`[Convert]::ToBase64String((1..32 | %% { [byte](Get-Random -Max 256) }))`

常见问题与排查
- Safari 分享失败：多为启用 `SYNC_TOKEN` 但未在前端填写“Server Token”，/api/share 返回 401。请补填并确认使用 HTTPS、环境一致（Preview/Production）。
- 远端 KV 看不到本地数据：`npm run dev` 默认本地模拟；使用 `npm run dev:remote` 或实际部署到 Preview，再在对应命名空间查看键：`sync:<Sync ID>`。

安全与隐私
- 主密码仅用于本地解锁，不同步到云端；若需所有设备统一入口，请使用 `ACCESS_GATE` 门禁。
- 数据同步与分享均为端到端加密；云端仅存密文与必要元数据。

公开仓库与敏感配置
- `.gitignore` 已忽略 `wrangler.toml`、`wrangler.*.toml`、`.env*`；请勿提交真实 ID/密钥。
- 若已被追踪：`git rm --cached wrangler.toml` 后提交；本地文件保留不删。
- 推荐使用 `npm run dev:remote` 连接远端环境，无需在仓库暴露配置。

兼容性
- 扫码依赖 `BarcodeDetector` 与 `getUserMedia`；若不可用，可“选择图片”或粘贴 otpauth。
- HOTP：可导入/新增，界面提供“下一次(HOTP)”按钮递增计数器。

数据合并策略（自动）
- 键对齐：优先 `id`，否则 `type|secret|issuer|account`。
- 规则：取 `updatedAt` 最新版本；删除为墓碑（UI 不显示但参与同步）。
- 清理墓碑：同步面板“清理已删除”可彻底移除并触发推送（请先确保所有设备已同步）。

许可
- 仅示例用途，按需修改与自托管。

