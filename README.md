# Web 2FA Authenticator

一个纯前端的 2FA 验证器（TOTP/HOTP），可离线运行，支持 PWA 安装、二维码扫码/图片识别、otpauth 链接与 Google Authenticator 迁移格式导入、本地主密码加密、以及基于 Cloudflare Pages Functions + KV 的端到端加密多设备同步与临时分享。

- 主要页面：`index.html`、`shared.html`（查看分享）、`shares.html`（分享管理）
- 前端逻辑：`app.js`、`shared.js`、`shares.js`
- 后端（Pages Functions）：`functions/`（同步、分享、访问口令 Gate 中间件等）

## 功能特性
- TOTP/HOTP 支持
  - 算法：SHA1/SHA256/SHA512，位数 6/8，周期可配
  - 解析 `otpauth://` 链接与 Google Authenticator 迁移格式（`otpauth-migration://`）
- 导入与扫码
  - 粘贴 `otpauth://...`，或选择图片识别二维码
  - 支持原生 `BarcodeDetector`（在支持的浏览器/HTTPS 环境下）
- 本地存储与加密
  - 默认保存在 `localStorage`
  - 可设置主密码后使用 AES‑GCM + PBKDF2 加密本地数据
- 多设备同步（端到端加密）
  - 使用自定义 `Sync ID` + `Sync Secret` 生成密钥在本地加密数据，再同步到 Cloudflare KV
  - 可选设置 `Server Token` 以限制服务端写入
  - 支持手动推送/拉取、自动同步与清理删除项
- 二维码分享（加密）
  - 为某个 TOTP 生成随机密钥加密后上传到 KV，仅分享页面拿着 `#k=` 片段密钥才能解密
  - 支持有效期（秒）或永久，支持撤销
  - 提供分享管理页，支持本地引用清理与云端列表查看
- PWA 与离线支持
  - `manifest.webmanifest` + `sw.js`，可“添加到主屏幕”，离线可用
- 访问口令 Gate（可选）
  - 通过 `ACCESS_GATE` 启用后，未持有 Cookie 的访问需先输入口令

## 快速开始
- 运行环境
  - Node.js（仅用于本地开发脚手架）
  - Cloudflare Wrangler（v3 及以上）
- 安装依赖：本项目无构建步骤，无需安装前端依赖
- 本地开发
  - 复制 `wrangler.toml.example` 为 `wrangler.toml`，填入你创建的 KV 命名空间 id
  - 启动（HTTP，本地预览）：`npm run dev`
  - 启动（HTTPS，便于摄像头/BarcodeDetector）：`npm run dev:https`
  - 远程开发（Cloudflare 边缘执行）：`npm run dev:remote`

提示：部分浏览器的摄像头/剪贴板能力需要 HTTPS 上下文；扫码与复制在 `https://` 或安装为 PWA 后体验更佳。

## 部署到 Cloudflare Pages
1) 创建 Pages 项目，连接你的代码仓库
2) 构建设置
- Build command：无
- Build output directory：根目录（包含静态文件）
- Functions directory：`functions`
3) 绑定 KV：在 Pages 项目 Settings → Functions → KV Bindings 添加命名空间，绑定名设为 `AUTH_KV`
4) 环境变量（可选）
- `SYNC_TOKEN`：若设置，写入型 API 需要携带匹配的 `X-Token` 请求头
- `ACCESS_GATE`：设置后启用全站访问口令（见“访问口令 Gate”）
- `SHARE_TTL`：分享默认有效期（秒，默认 86400；≤0 表示默认永久）

本地开发时，`wrangler.toml` 中需声明同名绑定与变量，示例见：`wrangler.toml.example:1`

## 使用说明
- 添加账户
  - 点击“添加账户”可粘贴 `otpauth://` 或 `otpauth-migration://` 链接；也可手动输入参数
  - 点击“扫码导入”可直接摄像头识别或从图片选择二维码
- 导入/导出
  - 导出会生成 JSON 文件；若本地启用了主密码，则导出的是加密数据包
  - 导入支持加密与未加密格式
- 主密码/解锁
  - “密码/解锁”用于设置/更换主密码（对本地数据加密），或在已加密情况下解锁
- 多设备同步
  - 在“同步”面板设置 `Sync ID`（命名空间区分你的数据）与 `Sync Secret`（端到端加密密钥来源）
  - 可勾选“自动同步”：启动时拉取、保存后自动推送、每 60s 自动拉取
  - 可选填写 `Server Token`，需要与后端 `SYNC_TOKEN` 一致
- 分享
  - 在条目上点击“分享”，选择有效期生成链接。链接形如：`/shared.html?sid=...#k=...`，其中 `#k` 为解密密钥，仅在浏览器端使用
  - 可在“分享管理”中查看本地记录、复制链接、绑定缺失密钥、撤销分享、或查看云端 SID 列表

## 配置与 API 参考
- 绑定与变量
  - `AUTH_KV`：Cloudflare KV 命名空间绑定名
  - `SYNC_TOKEN`（可选）：设置后，写入型接口需 `X-Token: <SYNC_TOKEN>`
  - `ACCESS_GATE`（可选）：设置站点访问口令
  - `SHARE_TTL`（可选）：分享默认有效期（秒）
- 主要接口（Pages Functions）
  - 同步：`GET/PUT /api/sync/:id`（`functions/api/sync/[id].js:1`）
  - 分享内容：`GET/HEAD/PUT/POST/DELETE /api/share/:id`（`functions/api/share/[id].js:1`）
    - 可通过查询 `?ttl=SECONDS` 或 `?ttl=perm|0` 指定有效期
  - 分享密钥保管：`GET/PUT/DELETE /api/sharekey/:id`（`functions/api/sharekey/[id].js:1`）
  - 分享列表：`GET /api/share/list`（`functions/api/share/list.js:1`）
  - 访问口令：`GET/POST/DELETE /api/gate`（`functions/api/gate.js:1`）
  - 全局中间件 Gate：`functions/_middleware.js:1`

## 安全说明
- 本地数据
  - 未设置主密码时，数据以明文 JSON 存于浏览器 `localStorage`
  - 设置主密码后，使用 AES‑GCM + PBKDF2 加密存储
- 多设备同步
  - 同步前在本地使用 `Sync Secret` 派生密钥加密；服务端仅保存密文
  - `Sync ID` 用作命名空间；请确保各设备上的 `Sync Secret` 一致
- 分享
  - 分享密钥通过 URL 片段 `#k=` 传递，服务端不可见；拿到完整链接的人即可解密，请谨慎分享
  - 建议设定有限有效期，并在不需要时及时撤销
- 访问口令 Gate
  - 设置 `ACCESS_GATE` 后，未持有正确 Cookie 的请求将被拦截，前端也会弹出输入框

## 浏览器支持与限制
- 推荐使用最新版 Chromium/Firefox/Edge。Safari 在剪贴板/扫码支持上可能有所差异
- 摄像头与 Clipboard 能力通常要求 HTTPS 或已安装为 PWA
- 若浏览器不支持 `BarcodeDetector`，可“选择图片”或手动粘贴 `otpauth://` 链接

## 项目结构（节选）
- `index.html`：主界面
- `app.js`：前端核心逻辑（TOTP/HOTP、存储、同步、分享、UI）
- `shared.html` + `shared.js`：分享查看页（前端解密）
- `shares.html` + `shares.js`：分享管理页
- `functions/`：Cloudflare Pages Functions（同步/分享/API、中间件 Gate）
- `sw.js`：Service Worker（缓存静态资源）
- `manifest.webmanifest`：PWA 清单
- `wrangler.toml.example`：本地开发示例配置

## 常见问题（FAQ）
- 无法扫码？
  - 请使用 `npm run dev:https` 以 HTTPS 运行本地环境，或部署到 HTTPS 站点
- 同步报 401？
  - 若后端设置了 `SYNC_TOKEN`，前端“同步”里需要填写相同的 Server Token，或去掉后端限制
- 分享链接打开后显示“分享不存在/已过期”？
  - 检查是否超过有效期，或在“分享管理”中查看并重新生成

## 开发脚本
- `npm run dev`：本地 Pages Dev（HTTP）
- `npm run dev:https`：本地 Pages Dev（HTTPS）
- `npm run dev:remote`：远程 Dev（代码在 Cloudflare 边缘执行）
