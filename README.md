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
- 🛡 **管理员能力默认隐藏**：管理员入口默认不显示，需在“关于”页连续点击版本号 7 次后再输入 `ADMIN_KEY`
- 🔒 **分享仅管理员可用**：普通用户不显示分享入口，管理员可统一查看全部分享记录
- 📷 **导入更完整**：支持手动输入、`otpauth://`、Google Authenticator 导出二维码 `otpauth-migration://`
- ♻️ **重复导入自动去重**：同一项目重复扫同一个二维码时，会自动跳过；若之前只是“逻辑删除”，会直接恢复
- 📱 **PWA + 离线**：支持安装到桌面/主屏，断网也能生成验证码

---

## 🚀 三种使用场景

### 1. 普通访客「即点即用」
打开页面 → 「+」添加账户 → 粘贴密钥或扫描二维码 → 立刻显示验证码。

完全本地（localStorage），无需登录、无需创建任何“项目”，关闭浏览器后数据仍在。点击卡片即可复制验证码，长按或右键可进行编辑、删除、复制 `otpauth` 链接等操作。

### 2. 管理员管理多设备同步
管理员登录后，设置入口（右上齿轮）→「项目」→「新建项目」，填项目名、Sync ID、Sync Secret 三项即可创建端到端加密的同步空间：

- 推送 / 拉取 / 自动同步全部一键完成
- 多设备只需配置相同的 Sync ID + Secret
- 支持创建多个项目（个人 / 工作 / 测试），并提供「📊 全部汇总视图」聚合查看

### 3. 管理员高阶运维
进入「关于」页，连续点击版本号 `v0.2.0` 7 次显示高级入口，再输入 `Admin Key` 登录后，才会出现“分享”“管理员”标签页：

- 查看全部分享记录，并统一复制 / 撤销分享
- 列出云端所有同步项目（KV `sync:*`）
- 批量解密预览（可输入多个 `Sync Secret` 尝试）
- 多格式导出（`otpauth` / JSON / CSV，可按项目分文件 / 仅导出选中）
- RSA 公钥密钥托管 + 私钥找回
- 批量密钥迁移（旧 Secret → 新 Secret）

---

## ⚙️ 部署到 Cloudflare Pages

### 一、创建 KV 命名空间
在 Cloudflare Dashboard 创建一个 KV 命名空间，记下 ID。

### 二、连接仓库 / 部署
```bash
wrangler pages deploy
```
或在 Pages 控制台连接 Git 仓库自动部署。

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
GET    /api/sharekey/:id        # 获取分享密钥（需鉴权）
PUT    /api/sharekey/:id        # 存储分享密钥（需鉴权）

GET    /api/vault/:id           # 取出密钥托管密文（需鉴权）
PUT    /api/vault/:id           # 存放密钥托管密文（需鉴权）

POST   /api/admin/list-all      # 列出所有 sync:* 项目（需鉴权）

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
│   │   └── storage.js        # localStorage + 主密码加密
│   ├── sync/
│   │   ├── sync.js           # 推送/拉取/合并/自动同步
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
│   │   ├── modal.js          # 模态/Prompt/ActionSheet
│   │   ├── toast.js          # Toast + 复制/下载
│   │   ├── ring.js           # SVG 圆形进度环
│   │   ├── avatar.js         # Issuer 字母头像
│   │   └── import-export.js  # 导入/导出（含加密包）
│   └── admin/
│       └── unlock.js         # 管理员密码校验
├── functions/                # Cloudflare Pages Functions
│   ├── _middleware.js
│   └── api/
│       ├── sync/[id].js
│       ├── share/[id].js
│       ├── share/list.js
│       ├── sharekey/[id].js
│       ├── vault/[id].js
│       ├── gate.js
│       └── admin/list-all.js
├── sw.js                     # Service Worker
└── manifest.webmanifest
```

---

## 🆚 v0.2 重构说明（与 v0.1 对比）

| 维度 | v0.1 | v0.2 |
|---|---|---|
| 前端文件 | 单文件 `app.js` 2752 行 | ES Module 化，`src/` 下 19 个模块 |
| 概念数量 | Server Token / Sync Secret / KV Admin Key / Vault 公私钥 五种 | Admin Key + Sync Secret 两种（旧字段仍兼容） |
| 默认体验 | 一进来满屏按钮和概念 | 极简：FAB + 齿轮，按需展开 |
| 隐藏交互 | 三击标题设 Server Token | 「关于」页版本号连点 7 次后显示管理员入口 |
| 云端可见性 | GET 永远开放 | strict 模式（默认）GET 也鉴权 |
| 视觉 | 网格 + 线条进度条 | 玻璃拟态 + 圆形 SVG 进度环 + 渐变 |

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
