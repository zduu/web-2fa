// 健康检查：返回服务端能力清单（不暴露 secret）
// 公开端点，但通过 ACCESS_GATE 时仍要 cookie
export async function onRequestGet(context) {
  const { env } = context;
  const kv = !!(env.AUTH_KV && env.AUTH_KV.get && env.AUTH_KV.put);

  const body = {
    ok: kv,
    kv: kv ? "ok" : "missing",
    serverTime: new Date().toISOString(),
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
