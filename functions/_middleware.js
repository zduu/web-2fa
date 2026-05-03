// 全站访问门 (ACCESS_GATE)
// - 未配置 gate 时直通
// - 配置 gate 时：所有 /api/* 需要 cf_gate cookie 通过；
//   但 /api/share GET/HEAD、/api/gate、shared.html 这种公开链路放行；
//   /api/share PUT/DELETE、/api/sharekey、/api/vault 允许 ADMIN_KEY/SYNC_TOKEN 直通；
//   /api/admin/* 允许 ADMIN_KEY/SYNC_TOKEN/KV_ADMIN_KEY 直通

import { isAdminAuthed, isAuthed } from "./_lib/auth.js";
import { getAccessGateState, readAccessGateCookie } from "./_lib/access-gate.js";
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

  const gate = await getAccessGateState(env);
  if (!gate.enabled) {
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

  const got = readAccessGateCookie(request);
  const hasCookie = !!(got && timingSafeEqual(got, gate.cookieValue));
  const tokenHeader = request.headers.get("X-Token");
  const hasAdminToken = isAuthed(env, tokenHeader);
  const hasAdminApiToken = isAdminAuthed(env, request);

  if (path.startsWith("/api/")) {
    if (path.startsWith("/api/admin/")) {
      if (hasAdminApiToken || hasCookie) {
        return await runNext();
      }
      return deny();
    }
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

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  return diff === 0;
}
