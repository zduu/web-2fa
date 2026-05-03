# Web 2FA Authenticator

<div align="center">

一个**纯前端**的 2FA 验证器（TOTP / HOTP），支持离线运行、PWA 安装、端到端加密的多设备同步。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Pages](https://img.shields.io/badge/deploy-Cloudflare%20Pages-orange.svg)](https://pages.cloudflare.com/)

</div>

---

## ✨ 特点

- 🚀 **即点即用**：普通用户打开页面即可本地添加 2FA，默认不上传
- 🔐 **端到端加密同步**：每个项目用 `Sync Secret` 派生 AES-GCM 密钥，云端只存密文
- 🪪 **Passkey 快捷解锁**：在支持 WebAuthn `prf` 的浏览器中，可把 Passkey 作为本地主密码之外的额外解锁方式
- ↕️ **项目内拖拽排序**：支持拖拽调整卡片顺序，并在本地持久化保存
- 🎨 **三档主题**：支持暗色 / 亮色 / 跟随系统，分享页也同步主题色
- 🛡 **管理员能力默认隐藏**：管理员入口默认不显示，需在“关于”页连续点击版本号 7 次后再输入 `ADMIN_KEY`
- 🔒 **分享仅管理员可用**：普通用户不显示分享入口，管理员可统一查看全部分享记录与访问日志
- 📱 **分享支持离线 QR**：生成链接后会弹出二维码、链接和有效期提示，手机扫码更直接
- 🔐 **分享口令可选**：可额外设置接收方访问口令；不设置时仍可直接通过链接访问
- 🔳 **支持批量迁移二维码导出**：当前项目可直接导出为 `otpauth-migration://` 多张二维码，便于迁移到 Google Authenticator 等应用
- 🧾 **管理员审计日志**：所有 API 写操作会记录最近 30 天的 method/path/status/IP 摘要/UA 摘要
- 📷 **导入更完整**：支持手动输入、`otpauth://`、`otpauth-migration://`、Aegis 明文 JSON、Bitwarden CSV/JSON、andOTP 加密备份
- ♻️ **重复导入自动去重**：同一项目重复扫同一个二维码时，会自动跳过；若之前只是“逻辑删除”，会直接恢复
- ♿ **键盘与对话框可访问性增强**：列表语义、Tab 语义、模态焦点陷阱已补齐
- 📱 **PWA + 离线**：支持安装到桌面/主屏，断网也能生成验证码

---

## 🚀 三种使用场景

### 1. 普通访客「即点即用」
打开页面 → 「+」添加账户 → 粘贴密钥或扫描二维码 → 立刻显示验证码。

完全本地（localStorage），无需登录、无需创建任何“项目”，关闭浏览器后数据仍在。点击卡片即可复制验证码，长按或右键可进行编辑、删除、复制 `otpauth` 链接等操作。
如果你已经启用了主密码，本应用还支持在兼容浏览器里额外绑定一把 Passkey，用生物识别或设备 PIN 快速解锁本地数据。
如果要从其他验证器迁入，可在「设置 → 数据」里直接导入 Aegis 明文 JSON、Bitwarden CSV/JSON、andOTP 加密备份，或扫描 `otpauth://` / `otpauth-migration://` 二维码。
如果要迁移到其他支持 Google 批量导入的验证器，可在「设置 → 数据」里使用“批量二维码”导出当前项目。

### 2. 管理员管理多设备同步
管理员登录后，设置入口（右上齿轮）→「项目」→「新建项目」，填项目名、Sync ID、Sync Secret 三项即可创建端到端加密的同步空间：

- 推送 / 拉取 / 自动同步全部一键完成
- 多设备只需配置相同的 Sync ID + Secret
- 支持创建多个项目（个人 / 工作 / 测试），并提供「📊 全部汇总视图」聚合查看

### 3. 管理员高阶运维
进入「关于」页，连续点击版本号 `v0.2.0` 7 次显示高级入口，再输入 `Admin Key` 登录后，才会出现“分享”“管理员”标签页：

- 查看全部分享记录，并统一复制 / 撤销分享
- 查看分享访问次数、最后访问时间与 User-Agent 摘要
- 生成分享后立即展示离线二维码、链接与有效期提示；可选再加一层接收方口令
- 查看最近 30 天 API 写操作审计日志（含拒绝请求）
- 列出云端所有同步项目（KV `sync:*`）
- 批量解密预览（可输入多个 `Sync Secret` 尝试）
- 多格式导出（`otpauth` / JSON / CSV，可按项目分文件 / 仅导出选中）
- RSA 公钥密钥托管 + 私钥找回
- 批量密钥迁移（旧 Secret → 新 Secret）

---

## 📱 本地 APK（无云端）

如果你的目标是“手机上本地运行，不依赖远程云端”，这个仓库现在已经支持 **本地 APK 模式**：

- APK 内运行的是同一套前端核心逻辑，但会切换到 `local-app` 模式
- 所有账户、项目数据只保存在手机本地 `localStorage`
- 不再访问 Cloudflare Pages Functions / KV
- “项目”在 APK 中会变成**本地项目库**，用于本机分类与汇总
- 云同步 / 云分享 / 管理员云端浏览在 APK 版里默认关闭

### APK 产出方式

APK 不再依赖本地机器构建，统一改为 **GitHub Actions** 产出：

1. 推送到 `main` / `master`，或在 Actions 页面手动触发 `Android APK`
2. Workflow 会临时安装 Capacitor / TypeScript / Android SDK
3. 构建完成后，在该次 Actions 的 `Artifacts` 中下载 `web-2fa-local-debug-apk`

说明：

- Web 云端版继续使用根目录源码 + `wrangler pages dev/deploy`
- APK 本地版仍然通过 `scripts/build-local-web.mjs` 生成 `dist-local/`，但默认由 CI 执行
- `dist-local/` 只是临时构建产物，不入库
- 本地 `package.json` 已移除 APK 构建用的 Capacitor 依赖与脚本，避免要求开发机安装整套 Android 打包链

---

## ⚙️ 部署到 Cloudflare Pages

### 一、创建 KV 命名空间
在 Cloudflare Dashboard 创建一个 KV 命名空间，记下 ID。

### 二、连接仓库 / 部署
```bash
wrangler pages deploy
```
或在 Pages 控制台连接 Git 仓库自动部署。

如果你不想改现有的 Build command / Build output directory，但又想避免 `android/` 的改动频繁触发 Pages 无效构建，可以在 Cloudflare Pages 控制台配置 **Build watch paths**：

- Include paths: `*`
- Exclude paths: `android/**`

配置位置：

- Workers & Pages
- 选择你的 Pages 项目
- `Settings` → `Build` → `Build watch paths`

这样做的效果是：

- `android/` 下各级目录和文件的改动不会触发新的 Pages 构建
- Web 源码、`functions/`、根目录页面文件的改动仍会正常触发构建

注意：

- 这只能减少无效构建触发，不能改变 Pages 读取仓库根目录这一事实。
- 也就是说，它解决的是“不要因为 Android 改动而重建”，不是“从仓库结构上彻底隔离 android 目录”。

### 三、绑定 KV
Pages 项目 → Settings → Functions → KV Bindings：变量名 `AUTH_KV` → 选择刚才创建的 KV。

### 四、设置环境变量

| 变量名 | 必选 | 作用 |
|---|---|---|
| `ADMIN_KEY` | 推荐 | **管理员主密钥**。一个值搞定：同步写入鉴权、云端浏览鉴权、分享写入鉴权 |
| `SYNC_MODE` | 可选 | `strict`（默认）/ `open`。strict 下读取也需要 ADMIN_KEY，普通访客无法下载任何同步密文 |
| `ACCESS_GATE` | 可选 | 全站访问口令（独立于 ADMIN_KEY）。设置后用户进站需先通过 cookie 验证 |
| `SHARE_TTL` | 可选 | 分享默认有效期（秒，<=0 表示永久） |
| `SYNC_TOKEN` | 兼容 | 旧版别名，等价于 ADMIN_KEY |
| `KV_ADMIN_KEY` | 兼容 | 旧版别名，等价于 ADMIN_KEY（云端浏览专用） |

> **建议**：只配 `ADMIN_KEY`，再决定 `SYNC_MODE`。其他都默认。

### 五、本地开发
```bash
cp wrangler.toml.example wrangler.toml   # 编辑 KV ID 和环境变量
npm run dev:https                        # 推荐 HTTPS（摄像头/剪贴板需要）
```

说明：
- 本地不设置 `ADMIN_KEY` 也能跑前端，但管理员相关接口会不可用
- 想测试扫码、复制、PWA 安装，优先使用 `npm run dev:https`

---

## 📐 架构

```
┌──────────────┐                    ┌──────────────┐                    ┌──────────────┐
│   设备 A     │                    │  云端 (KV)   │                    │   设备 B     │
│              │ ── Sync Secret ──→ │              │ ←── Sync Secret ── │              │
│  原始数据    │     加密推送       │  密文数据    │     拉取并解密     │  本地数据    │
└──────────────┘                    └──────────────┘                    └──────────────┘
                                          ↑
                                          │  ADMIN_KEY 鉴权（strict 模式下读写都需要）
                                          │
                                    ┌─────┴──────┐
                                    │  访客或    │
                                    │  其他用户  │
                                    └────────────┘
```

### 双层防护
1. **写入永远要鉴权**（ADMIN_KEY）—— 即使知道你的 Sync ID，没 Admin Key 也无法覆盖
2. **strict 读取也鉴权** —— 普通访客根本拿不到任何 KV 密文
3. **Sync Secret 端到端加密** —— 即便密文泄露，没 Sync Secret 也解不开

---

## 🔌 API

```http
GET    /api/sync/:id            # 拉取（strict 模式需鉴权）
PUT    /api/sync/:id            # 推送（始终需鉴权）
DELETE /api/sync/:id            # 删除项目密文

GET    /api/share/:id           # 获取分享密文（公开）
PUT    /api/share/:id?ttl=3600  # 创建分享
DELETE /api/share/:id           # 撤销分享

GET    /api/share/list          # 列出所有分享 SID（需鉴权）
GET    /api/share/stat          # 获取分享访问统计（需鉴权）
GET    /api/sharekey/:id        # 获取分享密钥（需鉴权）
PUT    /api/sharekey/:id        # 存储分享密钥（需鉴权）

GET    /api/vault/:id           # 取出密钥托管密文（需鉴权）
PUT    /api/vault/:id           # 存放密钥托管密文（需鉴权）

POST   /api/admin/list-all      # 列出所有 sync:* 项目（需鉴权）
GET    /api/admin/audit         # 获取最近审计日志（需鉴权）

GET    /api/gate                # 检查 ACCESS_GATE
POST   /api/gate                # 提交访问口令
DELETE /api/gate                # 退出
```

请求头：
- `X-Token`: ADMIN_KEY（推荐）或 SYNC_TOKEN（兼容）
- `X-KV-Admin-Key`: ADMIN_KEY 或 KV_ADMIN_KEY（云端浏览也接受）

---

## 📂 项目结构

```
web-2fa/
├── index.html                # 极简 shell
├── shared.html               # 分享查看页
├── styles.css                # 设计系统
├── app.js                    # 入口
├── assets/
│   └── icons/                # PWA / favicon / Apple Touch 图标
├── src/
│   ├── core/
│   │   ├── totp.js           # TOTP/HOTP/otpauth/migration
│   │   ├── crypto.js         # AES-GCM/PBKDF2/RSA-OAEP
│   │   ├── migration-formats.js # Aegis/Bitwarden/andOTP 迁移格式解析
│   │   ├── passkey.js        # Passkey PRF / 本地快捷解锁
│   │   ├── storage.js        # localStorage + 主密码加密
│   │   ├── qrgen.js          # 分享/导出用离线二维码包装
│   │   ├── qrgen-vendor.js   # vendored QR encoder
│   │   └── version.js        # APP_VERSION 单一来源
│   ├── sync/
│   │   ├── sync.js           # 推送/拉取/合并/自动同步（页面隐藏自动暂停）
│   │   ├── projects.js       # 项目 CRUD/切换
│   │   ├── vault.js          # RSA 托管/找回/迁移
│   │   └── cloud.js          # 云端浏览/批量解密/导出
│   ├── share/
│   │   └── share.js          # 二维码分享/撤销/列表
│   ├── ui/
│   │   ├── home.js           # 主页 + tick + 卡片交互
│   │   ├── add.js            # 添加面板（Tab 切换）
│   │   ├── scanner.js        # QR 扫描
│   │   ├── drawer.js         # 设置抽屉 + 所有面板
│   │   ├── theme.js          # 主题偏好（dark/light/auto）
│   │   ├── modal.js          # 模态/Prompt/ActionSheet
│   │   ├── toast.js          # Toast + 复制/下载
│   │   ├── ring.js           # SVG 圆形进度环
│   │   ├── avatar.js         # Issuer 字母头像
│   │   ├── prefs.js          # 显示密度偏好
│   │   └── import-export.js  # 导入/导出（含加密包与 migration QR）
│   └── admin/
│       └── unlock.js         # 管理员密码校验
├── functions/                # Cloudflare Pages Functions
│   ├── _middleware.js
│   ├── _lib/
│   │   ├── auth.js          # 共享鉴权工具（恒时比较 + 多字段兼容）
│   │   └── audit.js         # API 写请求审计日志
│   └── api/
│       ├── health.js
│       ├── sync-trash.js
│       ├── sync-backup/[id].js
│       ├── sync/[id].js
│       ├── share/[id].js
│       ├── share/list.js
│       ├── share/stat.js
│       ├── sharekey/[id].js
│       ├── vault/[id].js
│       ├── gate.js
│       └── admin/
│           ├── list-all.js
│           └── audit.js
├── tests/                    # Vitest 核心算法/合并逻辑测试
├── .github/workflows/ci.yml  # CI：测试 + Functions 构建
├── sw.js                     # Service Worker
└── manifest.webmanifest
```

---

## 🆚 v0.2 重构说明（与 v0.1 对比）

| 维度 | v0.1 | v0.2 |
|---|---|---|
| 前端文件 | 单文件 `app.js` 2752 行 | ES Module 化，`src/` 下 17 个模块 |
| 概念数量 | Server Token / Sync Secret / KV Admin Key / Vault 公私钥 五种 | Admin Key + Sync Secret 两种（旧字段仍兼容） |
| 默认体验 | 一进来满屏按钮和概念 | 极简：FAB + 齿轮，按需展开 |
| 隐藏交互 | 三击标题设 Server Token | 「关于」页版本号连点 7 次后显示管理员入口 |
| 云端可见性 | GET 永远开放 | strict 模式（默认）GET 也鉴权 |
| 视觉 | 网格 + 线条进度条 | 玻璃拟态 + 圆形 SVG 进度环 + 渐变 |
| 鉴权代码 | 复制粘贴在多个 endpoint | 抽到 `functions/_lib/auth.js`，恒时比较降低时序攻击面 |
| 自动同步 | 60s 固定轮询 | 页面隐藏时自动暂停拉取 |

**数据完全兼容**：升级后旧 localStorage 数据自动可用，无需迁移。

---

## ❓ 常见问题

详见 [CONCEPTS.md](CONCEPTS.md)。

### 我什么都不想配置，能用吗？
能。打开页面即可添加 2FA 账户，离线本地存储。

### 我想多设备同步，最少要做什么？
1. 部署 + 配置 KV
2. 设置环境变量 `ADMIN_KEY`
3. 在前端“关于”页连续点击版本号 7 次，显示高级入口后输入 Admin Key
4. 进入"项目"→ 新建项目，填项目名 / Sync ID / Sync Secret
5. 在另一台设备登录管理员、填同样的 Sync ID + Secret

### 我不想让别人看到我的云端数据怎么办？
保持默认 `SYNC_MODE = strict`。strict 模式下，没有 Admin Key 的人发 GET `/api/sync/:id` 会被拒绝（401），根本拿不到密文。

### 重复扫描同一个二维码会怎样？
同一项目内会自动去重：

- 如果这个账户已经存在，会跳过，不会新增第二条
- 如果这个账户之前被删除过，但只是逻辑删除，会自动恢复
- Google Authenticator 导出的批量迁移码也适用这套规则

---

## 📄 License

MIT
