const AUDIT_PREFIX = "audit:";
const AUDIT_TTL_SECONDS = 30 * 24 * 3600;

export async function writeAuditLog(env, request, response) {
  if (!env?.AUTH_KV?.put) return;
  const ts = Date.now();
  const key = `${AUDIT_PREFIX}${ts}:${Math.random().toString(36).slice(2, 8)}`;
  const body = JSON.stringify({
    ts,
    method: request.method,
    path: compactPath(request.url),
    status: Number(response?.status || 0) || null,
    ipSummary: await summarizeIp(request.headers.get("CF-Connecting-IP")),
    uaSample: sanitizeUserAgent(request.headers.get("User-Agent")),
  });
  try {
    await env.AUTH_KV.put(key, body, { expirationTtl: AUDIT_TTL_SECONDS });
  } catch {}
}

export function shouldAuditRequest(request) {
  const method = String(request?.method || "").toUpperCase();
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) return false;
  let url;
  try { url = new URL(request.url); } catch { return false; }
  if (!url.pathname.startsWith("/api/")) return false;
  if (url.pathname === "/api/admin/audit") return false;
  return true;
}

function compactPath(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const full = `${url.pathname}${url.search}`;
    return full.slice(0, 200);
  } catch {
    return "/";
  }
}

async function summarizeIp(ip) {
  const text = String(ip || "").trim();
  if (!text) return "";
  const data = new TextEncoder().encode(text);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return Array.from(digest.slice(0, 6)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sanitizeUserAgent(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text ? text.slice(0, 160) : "";
}
