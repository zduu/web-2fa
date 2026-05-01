// 全站访问门 (ACCESS_GATE)
// - 未配置 gate 时直通
// - 配置 gate 时：所有 /api/* 需要 cf_gate cookie 通过；
//   但 /api/share GET/HEAD、/api/gate、shared.html 这种公开链路放行；
//   /api/share PUT/DELETE、/api/sharekey、/api/vault 也允许通过任意有效管理员 token (ADMIN_KEY/SYNC_TOKEN) 直通

import { isAuthed } from "./_lib/auth.js";
import { shouldAuditRequest, writeAuditLog } from "./_lib/audit.js";

export const onRequest = async (ctx) => {
  const { request, env } = ctx;
  const url = new URL(request.url);
  const path = url.pathname;
  const finish = (response) => {
    if (shouldAuditRequest(request)) {
      ctx.waitUntil?.(writeAuditLog(env, request, response));
    }
    return response;
  };
  const runNext = async () => finish(await ctx.next());
  const deny = () => finish(gateRequired());

  const gate = env.ACCESS_GATE;
  if (!gate) {
    return await runNext();
  }

  const allowPrefixes = [
    "/api/gate",
    "/api/health",
    "/shared.html",
    "/shared.js",
    "/api/share/",
    "/manifest.webmanifest",
    "/assets/icons/",
    "/styles.css",
    "/sw.js",
    "/favicon.ico",
  ];
  if (allowPrefixes.some((p) => path.startsWith(p))) {
    // share 路径下还要在下面做写鉴权
    if (!path.startsWith("/api/share/")) {
      return await runNext();
    }
  }

  const cookie = request.headers.get("Cookie") || "";
  const want = await sha256b64url(gate);
  const got = parseCookie(cookie).get("cf_gate");
  const hasCookie = !!(got && timingSafeEqual(got, want));
  const tokenHeader = request.headers.get("X-Token");
  const hasAdminToken = isAuthed(env, tokenHeader);

  if (path.startsWith("/api/")) {
    // sharekey / vault：cookie OR 管理员 token
    if (path.startsWith("/api/sharekey/") || path.startsWith("/api/vault/")) {
      if (hasAdminToken || hasCookie) {
        return await runNext();
      }
      return deny();
    }
    // share GET/HEAD 公开；PUT/DELETE 需 cookie 或管理员 token
    if (path.startsWith("/api/share/")) {
      if (request.method === "GET" || request.method === "HEAD") return await ctx.next();
      if (hasAdminToken || hasCookie) {
        return await runNext();
      }
      return deny();
    }
    if (!hasCookie) return deny();
    return await runNext();
  }

  // 静态资源：放行（前端会发现 gate 后弹登录）
  return await ctx.next();
};

function gateRequired() {
  return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store", "X-Gate": "required" } });
}

function parseCookie(str) {
  const map = new Map();
  str.split(/;\s*/).forEach(kv => {
    const i = kv.indexOf("="); if (i === -1) return;
    const k = kv.slice(0, i).trim(); const v = kv.slice(i + 1).trim();
    if (k) map.set(k, v);
  });
  return map;
}

async function sha256b64url(text) {
  const data = new TextEncoder().encode(text);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  let b64 = btoa(String.fromCharCode(...hash));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  return diff === 0;
}
