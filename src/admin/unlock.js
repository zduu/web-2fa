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
  try {
    const res = await fetch(apiUrl("/api/admin/list-all"), {
      method: "POST",
      headers: {
        "X-KV-Admin-Key": adminKey,
        "X-Token": adminKey,
        "Content-Type": "application/json"
      }
    });
    if (res.status === 401) return { ok: false, msg: "Admin Key 不正确" };
    if (res.status === 200) {
      const data = await res.json().catch(() => ({}));
      if (data && data.success === false && data.error?.includes("not configured")) {
        // server didn't configure ADMIN_KEY/KV_ADMIN_KEY; fall back to share/list probe
        return await probeShareList(adminKey);
      }
      return { ok: true };
    }
  } catch {}
  return await probeShareList(adminKey);
}

async function probeShareList(adminKey) {
  try {
    const res = await fetch(apiUrl("/api/share/list"), {
      headers: { "X-Token": adminKey }
    });
    if (res.status === 401) return { ok: false, msg: "Admin Key 不正确" };
    if (res.ok) return { ok: true };
    // 200 with empty list also acceptable (no shares yet)
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
