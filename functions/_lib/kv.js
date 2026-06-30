export function hasKvMethods(env, methods) {
  return !!(env?.AUTH_KV && methods.every((method) => typeof env.AUTH_KV[method] === "function"));
}

export function kvMissingTextResponse(status = 503) {
  return new Response("Not configured", {
    status,
    headers: { "Cache-Control": "no-store", "X-Note": "kv-missing" },
  });
}

export function kvMissingJsonResponse(status = 503) {
  return new Response(JSON.stringify({ success: false, error: "AUTH_KV missing" }), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Note": "kv-missing" },
  });
}
