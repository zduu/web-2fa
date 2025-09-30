# Web 2FA Authenticator

<div align="center">

一个**纯前端**的 2FA 验证器（TOTP/HOTP），支持离线运行、PWA 安装、多设备同步、端到端加密。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Pages](https://img.shields.io/badge/deploy-Cloudflare%20Pages-orange.svg)](https://pages.cloudflare.com/)

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [使用说明](#-使用说明) • [核心概念](CONCEPTS.md) • [常见问题](#-常见问题)

</div>

---

## 📖 核心文档

> 💡 **首次使用必读**：[核心概念与权限说明（CONCEPTS.md）](CONCEPTS.md)
> 详细解释本地/云端存储、项目管理、Server Token 权限、使用场景和数据流向图

---

## ✨ 功能特性

### 🔐 TOTP/HOTP 支持
- ✅ 算法：SHA1/SHA256/SHA512，位数 6/8，周期可配
- ✅ 完全兼容 Google/Microsoft Authenticator
- ✅ 支持 `otpauth://` 和 `otpauth-migration://` 协议

### 📥 多种导入方式
| 方式 | 说明 | 推荐度 |
|------|------|--------|
| **Secret 密钥** | 直接粘贴 Base32 格式的密钥（如 `HKGZ HPK2...`） | ⭐⭐⭐⭐⭐ |
| **二维码扫描** | 摄像头实时扫描或选择图片识别 | ⭐⭐⭐⭐ |
| **otpauth 链接** | 粘贴完整的 `otpauth://...` 链接 | ⭐⭐⭐ |
| **批量迁移** | 支持 Google Authenticator 迁移格式 | ⭐⭐⭐⭐⭐ |

### 💾 本地存储与加密
- 📦 默认保存在浏览器 `localStorage`（完全离线可用）
- 🔒 可选主密码加密（AES-GCM + PBKDF2）
- 🚫 敏感信息密码模式显示（Server Token、主密码）

### ☁️ 多设备同步（端到端加密）

#### 工作原理
```
┌──────────────┐                    ┌──────────────┐                    ┌──────────────┐
│   设备 A     │                    │  云端 (KV)   │                    │   设备 B     │
│              │                    │              │                    │              │
│ 原始数据     │ ──加密并推送──→     │  密文数据    │ ←──拉取并解密──   │ 配置项目     │
│              │                    │              │                    │              │
└──────────────┘                    └──────────────┘                    └──────────────┘
        ↓                                                                       ↓
    本地存储                                                               本地存储
```

#### 核心特性
- 🔐 **端到端加密**：云端服务器无法解密数据
- 📁 **多项目管理**：为个人/工作/测试等场景创建独立项目
- 📊 **全部项目视图**：汇总显示**你本地已有项目**的验证码（只读，不访问其他用户数据）
- 🔄 **自动同步**：可选启用（启动时拉取、保存后推送、每 60 秒拉取）
- 🔀 **数据隔离**：每个项目独立存储，互不影响

#### 项目配置
| 配置项 | 说明 | 是否必填 |
|--------|------|----------|
| **项目名称** | 本地显示用，便于识别（如"个人账号"） | ✅ 必填 |
| **Sync ID** | 云端唯一标识，自定义字符串（如 `my-2fa`） | ✅ 必填 |
| **Sync Secret** | 端到端加密密钥，跨设备必须一致 | ✅ 必填 |
| **Server Token** | 限制云端写入权限（与服务端 `SYNC_TOKEN` 匹配） | ❌ 可选 |
| **自动同步** | 启用后自动推送/拉取 | ❌ 可选 |

### 🔗 二维码分享（临时加密）
- 🔐 随机密钥加密后上传到 KV
- ⏱️ 支持有效期（1小时/24小时/永久）
- 🔑 密钥通过 URL 片段传递（`#k=...`），服务器不可见
- ❌ 支持随时撤销分享

### 📱 PWA 与离线支持
- ✅ 可"添加到主屏幕"，像原生应用一样使用
- ✅ Service Worker 缓存，完全离线可用
- ✅ 响应式设计，移动端友好

### 🎨 界面优化
- 🌃 现代化暗色主题
- 📊 **实时状态指示器**：存储状态 / Token 状态 / 项目状态
- 💡 **内嵌使用提示**：界面中直接提供帮助和权限说明
- ✨ 流畅动画效果（卡片悬停、弹窗过渡、折叠面板）
- 🎯 智能焦点管理和键盘快捷键

### 🛡️ 访问控制（可选）
- 🔐 全局访问口令 Gate（`ACCESS_GATE`）
- 🎫 基于 Cookie 的会话验证

---

## 🚀 快速开始

### 环境要求
- Node.js 18+ （仅用于本地开发）
- Cloudflare Wrangler v3+

### 本地开发

1️⃣ **克隆项目**
```bash
git clone <your-repo-url>
cd 2fa
```

2️⃣ **配置 KV**
```bash
# 复制配置文件
cp wrangler.toml.example wrangler.toml

# 编辑 wrangler.toml，填入你的 KV 命名空间 ID
```

3️⃣ **启动开发服务器**
```bash
# HTTP 模式（基础功能）
npm run dev

# HTTPS 模式（推荐，支持摄像头/剪贴板）
npm run dev:https

# 远程模式（代码在 Cloudflare 边缘执行）
npm run dev:remote
```

4️⃣ **访问**
```
打开 http://localhost:8788 （或 https://localhost:8788）
```

---

## 🌐 部署到 Cloudflare Pages

### 一键部署

1️⃣ **连接仓库**
- 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
- 进入 Pages → Create a project → Connect to Git
- 选择你的代码仓库

2️⃣ **构建设置**
| 配置项 | 值 |
|--------|------|
| Build command | `（留空）` |
| Build output directory | `/`（根目录） |
| Functions directory | `functions` |

3️⃣ **绑定 KV**
- 进入 Pages 项目 → Settings → Functions → KV Bindings
- 添加绑定：**变量名** `AUTH_KV`，**命名空间** 选择你创建的 KV

4️⃣ **环境变量（可选）**
| 变量名 | 说明 | 示例 |
|--------|------|------|
| `SYNC_TOKEN` | 写入型 API 需要匹配此 Token | `your-secret-token-123` |
| `ACCESS_GATE` | 全站访问口令 | `site-password-456` |
| `SHARE_TTL` | 分享默认有效期（秒，≤0 表示永久） | `86400`（24小时） |
| `KV_ADMIN_KEY` | 云端浏览管理员密钥（用于查看所有同步项目） | `admin-key-789` |

---

## 📘 使用说明

### 1️⃣ 添加账户

#### 方式一：直接输入 Secret（推荐）
1. 点击 **"添加账户"**
2. 在 **"密钥 Secret"** 输入框中粘贴密钥（Base32 格式）
3. 填写 **服务名称** 和 **账号**（可选）
4. 点击 **"添加"**

#### 方式二：扫描二维码
1. 点击 **"扫码导入"**
2. 选择 **"摄像头扫描"** 或 **"选择图片"**
3. 自动识别并添加

#### 高级选项
- 展开 **"高级选项"**：配置算法、位数、周期
- 展开 **"从链接导入"**：粘贴 `otpauth://` 链接

---

### 2️⃣ 多设备同步

#### 首次设置（设备 A）

1. **三击页面标题** "Web 2FA Authenticator" 设置 Server Token（如果后端启用了验证）
2. 点击 **"同步"** → **"+ 新建项目"**
3. 填写项目配置：
   ```
   项目名称：个人账号
   Sync ID：my-personal-2fa
   Sync Secret：MyStrongPassword123
   自动同步：☑️ 启用
   ```
4. 点击 **"保存项目"**
5. 点击 **"推送到云端"**

#### 同步到其他设备（设备 B）

1. 三击标题设置相同的 **Server Token**（如需要）
2. 点击 **"同步"** → **"+ 新建项目"**
3. 填写**相同**的配置：
   ```
   项目名称：个人账号
   Sync ID：my-personal-2fa
   Sync Secret：MyStrongPassword123
   ```
4. 点击 **"保存项目"**
5. 点击 **"从云端拉取"**

#### 日常使用
- ✅ 启用 **"自动同步"**：自动推送/拉取，无需手动操作
- 📊 点击 **"📊 全部项目（汇总视图）"**：查看所有项目的验证码

---

### 3️⃣ 导入/导出

#### 导出数据
- 点击 **"导出"** 生成 JSON 文件
- 如果已设置主密码，导出的是加密数据包

#### 导入数据
- 点击 **"导入"** 选择 JSON 文件
- 支持加密和未加密格式

---

### 4️⃣ 主密码加密

1. 点击 **"密码/解锁"**
2. 输入主密码（留空取消）
3. 确认后本地数据将使用 AES-GCM 加密

**注意**：忘记主密码无法恢复数据，请务必记住！

---

### 5️⃣ 云端浏览（管理员）

#### 功能说明
管理员可以通过 KV Admin Key 查看云端所有同步项目（包括其他用户的项目）。**数据仍是加密的**，只有拥有对应 Sync Secret 的用户才能解密。

#### 使用步骤

1. **配置 KV Admin Key**
   - 在 Cloudflare Pages 环境变量中设置 `KV_ADMIN_KEY`（如 `admin-key-789`）

2. **访问云端浏览**
   - 点击 **"同步"** → **"浏览云端所有项目"**
   - 输入 KV Admin Key
   - 点击 **"加载云端项目"**

3. **查看和导入**
   - 查看所有同步项目的 Sync ID 和元数据
   - 点击 **"导入为新项目"** 可将云端项目导入到本地
   - 需要输入正确的 Sync Secret 才能解密数据

#### 使用场景
- 🔍 **监控和审计**：管理员查看云端有哪些同步项目
- 🔄 **数据迁移**：快速发现并导入已有的云端项目
- 🛡️ **安全管理**：检查是否有异常的同步数据

**注意**：
- ⚠️ 仅管理员使用，普通用户无需此功能
- ⚠️ 即使能看到项目列表，没有 Sync Secret 也无法解密数据
- ⚠️ KV Admin Key 应妥善保管，不要泄露

---

## 🔐 安全说明

### 本地数据
- ✅ 未设置主密码：明文 JSON 存储在 `localStorage`
- ✅ 设置主密码后：AES-GCM + PBKDF2（150,000 次迭代）加密存储

### 多设备同步
- ✅ 数据在本地加密后才上传（Sync Secret 派生密钥）
- ✅ 云端服务器只存储密文，无法解密
- ✅ 每个项目独立加密，互不影响

### Server Token
- ✅ 密码模式存储，不明文显示
- ✅ 仅用于限制云端写入权限（读取开放）
- ✅ 可随时切换显示/隐藏

### 分享
- ⚠️ 密钥通过 URL 片段传递（`#k=...`），拿到完整链接即可解密
- ⚠️ 建议设置有效期，用完及时撤销

---

## ❓ 常见问题

### Q1: 我不清楚本地/云端、Token、项目的区别？
**A:** 请阅读 **[CONCEPTS.md](CONCEPTS.md)**，里面有详细的概念说明、权限矩阵、使用场景和数据流向图。

---

### Q2: 推送失败，提示 401 错误？
**A:** 说明后端启用了 `SYNC_TOKEN` 验证。

**解决方法**：
1. 三击页面标题 "Web 2FA Authenticator"
2. 输入与后端 `SYNC_TOKEN` 一致的 Token
3. 保存后重新推送

详见：[CONCEPTS.md - Server Token 权限](CONCEPTS.md#三server-token-权限)

---

### Q3: 本地和云端有什么区别？
**A:**
- **本地**：数据只在当前浏览器，其他设备看不到
- **云端**：数据加密后上传到 Cloudflare KV，可跨设备访问
- **推送** = 本地 → 云端（上传）
- **拉取** = 云端 → 本地（下载）

详见：[CONCEPTS.md - 存储层次](CONCEPTS.md#一存储层次)

---

### Q4: 如何管理多个账号集合（个人/工作）？
**A:** 使用多项目管理功能。

**场景示例**：
- 项目 1："个人账号" - 私人邮箱、社交账号
- 项目 2："工作账号" - 公司 AWS、GitHub 企业版
- 项目 3："测试环境" - 临时测试用账号

**查看所有账号**：点击 "📊 全部项目（汇总视图）"

详见：[CONCEPTS.md - 场景 4](CONCEPTS.md#场景-4管理多个账号集合)

---

### Q5: 无法扫码？
**A:** 摄像头需要 HTTPS 或 PWA 环境。

**解决方法**：
- 本地开发：`npm run dev:https`
- 部署后：部署到 HTTPS 站点
- 替代方案：点击 "选择图片" 识别二维码截图

---

### Q6: 忘记 Sync Secret 怎么办？
**A:** Sync Secret 是加密密钥，忘记后**无法恢复**云端数据。

**补救措施**：
- 从本地导出数据（未加密）
- 创建新项目并重新推送

---

### Q7: Server Token 和 Sync Secret 有什么区别？
**A:**
| 项目 | Server Token | Sync Secret |
|------|--------------|-------------|
| **作用** | 限制云端写入权限 | 端到端加密密钥 |
| **安全性** | 验证身份 | 保护数据 |
| **忘记后** | 可重新设置 | **无法恢复数据** |
| **共享方式** | 所有设备相同 | 所有设备相同 |

---

### Q8: 为什么汇总视图不能删除？
**A:** 汇总视图是只读的，防止误删。

**删除方法**：
1. 切换到具体项目
2. 在项目中删除账户

---

### Q9: "全部项目视图"会显示云端所有人的数据吗？
**A:** ❌ **不会！这是常见误解。**

- 📊 全部项目视图是**本地虚拟视图**
- ✅ 只显示你本地已创建项目的数据汇总
- ❌ 不会访问云端其他用户的数据
- ❌ 不会自动拉取云端所有项目

**工作原理**：遍历你本地的项目列表，合并所有项目的验证码数据。

详见：[CONCEPTS.md - Q: "全部项目视图"会显示云端所有用户的数据吗？](CONCEPTS.md#q-全部项目视图会显示云端所有用户的数据吗)

---

## 🏗️ 项目结构

```
2fa/
├── index.html                # 主界面（添加账户、同步、分享管理）
├── app.js                    # 前端核心逻辑（50KB+）
├── shared.html + shared.js   # 分享查看页（前端解密）
├── shares.html + shares.js   # 分享管理页（已集成到主界面）
├── styles.css                # 样式表（优化版）
├── CONCEPTS.md               # 核心概念与权限说明文档
├── functions/                # Cloudflare Pages Functions
│   ├── api/
│   │   ├── sync/[id].js      # 同步接口（GET/PUT）
│   │   ├── share/[id].js     # 分享接口（GET/PUT/DELETE）
│   │   ├── sharekey/[id].js  # 分享密钥（GET/PUT/DELETE）
│   │   ├── share/list.js     # 分享列表（GET）
│   │   ├── gate.js           # 访问口令（GET/POST/DELETE）
│   │   └── admin/
│   │       └── list-all.js   # 云端浏览（POST，需要 KV_ADMIN_KEY）
│   └── _middleware.js        # 全局中间件（Gate 验证）
├── sw.js                     # Service Worker
├── manifest.webmanifest      # PWA 清单
└── wrangler.toml.example     # 本地开发配置示例
```

---

## 🔌 API 参考

### 同步 API
```http
GET  /api/sync/:id        # 拉取云端数据（无需 Token）
PUT  /api/sync/:id        # 推送到云端（需要 Token 如果后端启用验证）
```

### 分享 API
```http
GET    /api/share/:id           # 获取分享内容
PUT    /api/share/:id?ttl=3600  # 创建分享（ttl=有效期秒数，perm=永久）
DELETE /api/share/:id           # 撤销分享
GET    /api/share/list          # 列出所有分享（需要 Token）
```

### 分享密钥 API
```http
GET    /api/sharekey/:id   # 获取分享密钥（需要 Token）
PUT    /api/sharekey/:id   # 存储分享密钥（需要 Token）
DELETE /api/sharekey/:id   # 删除分享密钥（需要 Token）
```

### 访问口令 API
```http
GET    /api/gate           # 检查是否需要口令
POST   /api/gate           # 验证口令
DELETE /api/gate           # 清除口令 Cookie
```

### 云端浏览 API（管理员）
```http
POST   /api/admin/list-all # 列出所有同步项目（需要 X-KV-Admin-Key header）
```

**请求头**：
```http
X-KV-Admin-Key: your-admin-key-here
```

**响应示例**：
```json
{
  "success": true,
  "total": 3,
  "projects": [
    {
      "syncId": "my-personal-2fa",
      "metadata": {
        "version": 1,
        "hasData": true,
        "updatedAt": null
      },
      "encryptedData": {
        "v": 1,
        "iv": "...",
        "ct": "..."
      }
    }
  ]
}
```

---

## 🛠️ 开发脚本

```bash
# 本地开发
npm run dev                # HTTP 模式
npm run dev:https          # HTTPS 模式（推荐）
npm run dev:remote         # 远程模式（Cloudflare 边缘执行）

# 部署
wrangler pages deploy      # 手动部署到 Cloudflare Pages
```

---

## 📊 浏览器支持

| 浏览器 | 版本 | 支持度 | 备注 |
|--------|------|--------|------|
| Chrome/Edge | 最新版 | ✅✅✅ | 推荐 |
| Firefox | 最新版 | ✅✅✅ | 推荐 |
| Safari | 最新版 | ✅✅ | 剪贴板/扫码支持可能有差异 |
| 其他 | - | ⚠️ | 需支持 Web Crypto API |

**注意**：
- 摄像头和剪贴板需要 HTTPS 或 PWA 环境
- 不支持 `BarcodeDetector` 的浏览器可使用 "选择图片" 或手动输入

---

## 🎉 更新日志

### v2.0.0 - 最新版本（2024）

#### 🆕 新增功能
- ✨ **全局 Server Token 管理**：三击标题设置，统一管理
- 🎯 **实时状态指示器**：存储状态 / Token 状态 / 项目状态
- 📖 **CONCEPTS.md 文档**：完整的概念说明和使用指南
- 💡 **内嵌使用提示**：界面中直接提供帮助
- 🔐 **密码/解锁优化**：现代化弹窗，支持显示/隐藏切换
- 📁 **多项目管理**：支持创建多个独立的同步项目
- 📊 **全部项目视图**：汇总显示所有项目的验证码

#### 🎨 界面优化
- 现代化暗色主题
- 流畅的动画效果（卡片悬停、弹窗过渡）
- 响应式布局，移动端友好
- 智能焦点管理和键盘快捷键

#### 🔧 交互改进
- 添加账户界面：突出 Secret 输入，折叠高级选项
- 统一表单切换显示，避免混乱
- 权限说明直接显示在操作界面中

---

## 📄 许可证

MIT License

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

<div align="center">

**⭐ 如果觉得有用，请给个 Star 支持一下！⭐**

Made with ❤️ by [Your Name]

</div>