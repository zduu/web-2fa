// 管理员模式解锁：探测 ADMIN_KEY 是否正确
// 通过尝试访问需要鉴权的接口（/api/share/list 或 /api/admin/list-all）来验证

import { state, saveGlobalToken, saveAdminUnlocked } from "../core/storage.js";
import { apiUrl, canUseCloudApis, isLocalOnlyApp } from "../core/runtime.js";

// 探测 token 是否有效。返回 { ok, msg }
export async function verifyAdminKey(adminKey) {
  if (isLocalOnlyApp()) return { ok: false, msg: "本地 APK 版不需要 Admin Key" };
  if (!canUseCloudApis()) return { ok: false, msg: "APK 未配置云端 API 地址" };
  if (!adminKey) return { ok: false, msg: "请输入 Admin Key" };

  // 优先用 /api/admin/list-all 探测（这个 endpoint 一定需要鉴权）
  // 原则：只要服务端没有返回 401，就说明 Admin Key 鉴权已通过；
  // 其他错误（服务端异常、网关拦截等）不应影响 Key 有效性判断。
  try {
    const res = await fetch(apiUrl("/api/admin/list-all"), {
      method: "POST",
      headers: {
        "X-KV-Admin-Key": adminKey,
        "X-Token": adminKey,
        "Content-Type": "application/json"
      }
    });
    // 401 是唯一表示"Key 不对"的信号
    if (res.status === 401) return { ok: false, msg: "Admin Key 不正确" };
    if (res.status === 200) {
      const data = await res.json().catch(() => ({}));
      if (data?.success === false && isAdminKeyMissingResponse(res, data)) {
        // 服务端未配置任何 Admin Key → 用 share/list 再探一次
        return await probeShareList(adminKey);
      }
      // 200 且非 admin_key_missing → 鉴权已通过（success:false 可能是服务端内部错误）
      return { ok: true };
    }
    // 非 200 非 401（网关拦截、503 等）→ 降级到 share/list
    return await probeShareList(adminKey);
  } catch {}
  return await probeShareList(adminKey);
}

function isAdminKeyMissingResponse(response, data) {
  if (response?.headers?.get?.("X-Note") === "admin_key_missing") return true;
  const error = typeof data?.error === "string" ? data.error.toLowerCase() : "";
  return error.includes("admin key") && error.includes("configured");
}

async function probeShareList(adminKey) {
  try {
    const res = await fetch(apiUrl("/api/share/list"), {
      headers: { "X-Token": adminKey }
    });
    // 同样原则：只要不是 401，Key 就是对的
    if (res.status === 401) return { ok: false, msg: "Admin Key 不正确" };
    // 明确的服务端配置问题单独提示
    if (res.headers?.get?.("X-Note") === "kv-missing") {
      return { ok: false, msg: "服务端未绑定 AUTH_KV" };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, msg: "网络错误" };
  }
}

export function unlockAdmin(adminKey) {
  state.globalToken = adminKey;
  saveGlobalToken(adminKey);
  saveAdminUnlocked(true);
}

export function lockAdmin() {
  state.globalToken = "";
  saveGlobalToken("");
  saveAdminUnlocked(false);
}
