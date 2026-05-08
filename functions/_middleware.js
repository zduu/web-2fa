// 全站访问门 (ACCESS_GATE)
// - 未配置 gate 时直通
// - 配置 gate 时：所有 /api/* 需要 cf_gate cookie 通过；
//   但 /api/share GET/HEAD、/api/gate、shared.html 这种公开链路放行；
//   /api/share PUT/DELETE、/api/sharekey、/api/vault、/api/sync* 允许 ADMIN_KEY/SYNC_TOKEN 直通；
//   /api/admin/* 允许 ADMIN_KEY/SYNC_TOKEN/KV_ADMIN_KEY 直通

import { isAdminAuthed, isAuthed } from "./_lib/auth.js";
import { getAccessGateState, readAccessGateCookie } from "./_lib/access-gate.js";
import { shouldAuditRequest, writeAuditLog } from "./_lib/audit.js";

export const onRequest = async (ctx) => {
  const { request, env } = ctx;
  const url = new URL(request.url);
  const path = url.pathname;
  const finish = (response) => {
    const finalResponse = path.startsWith("/api/") ? withCors(request, env, response) : response;
    if (shouldAuditRequest(request)) {
      ctx.waitUntil?.(writeAuditLog(env, request, finalResponse));
    }
    return finalResponse;
  };
  const runNext = async () => finish(await ctx.next());
  const deny = () => finish(gateRequired());

  if (path.startsWith("/api/") && request.method === "OPTIONS") {
    return finish(new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } }));
  }

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
      if (request.method === "GET" || request.method === "HEAD") return await runNext();
      if (hasAdminToken || hasCookie) {
        return await runNext();
      }
      return deny();
    }
    // sync endpoints：cookie OR 管理员 token。移动 APK 跨源调用时无法依赖站点 cookie。
    if (path.startsWith("/api/sync/") || path.startsWith("/api/sync-trash") || path.startsWith("/api/sync-backup/")) {
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

function withCors(request, env, response) {
  const headers = new Headers(response.headers);
  const origin = request.headers.get("Origin") || "";
  const allowedOrigin = getAllowedOrigin(origin, env);
  if (allowedOrigin) {
    headers.set("Access-Control-Allow-Origin", allowedOrigin);
    headers.set("Vary", appendVary(headers.get("Vary"), "Origin"));
  }
  headers.set("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,DELETE,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, X-Token, X-KV-Admin-Key, Cache-Control");
  headers.set("Access-Control-Max-Age", "86400");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function getAllowedOrigin(origin, env) {
  if (!origin) return "";
  const configured = String(env.CORS_ORIGIN || "").trim();
  if (configured === "*") return origin;
  const allow = configured
    ? configured.split(",").map((x) => x.trim()).filter(Boolean)
    : ["https://localhost", "http://localhost", "capacitor://localhost"];
  return allow.includes(origin) ? origin : "";
}

function appendVary(current, value) {
  if (!current) return value;
  const parts = current.split(",").map((x) => x.trim().toLowerCase());
  return parts.includes(value.toLowerCase()) ? current : `${current}, ${value}`;
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  return diff === 0;
}
