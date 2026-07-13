export class RequestBodyTooLargeError extends Error {
  constructor(limit) {
    super(`Request body exceeds ${limit} bytes`);
    this.name = "RequestBodyTooLargeError";
    this.limit = limit;
  }
}

export async function readRequestText(request, limit = 512 * 1024) {
  const max = Math.max(1, Math.trunc(Number(limit)) || 1);
  const declared = Number(request.headers.get("Content-Length"));
  if (Number.isFinite(declared) && declared > max) throw new RequestBodyTooLargeError(max);
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > max) throw new RequestBodyTooLargeError(max);
  return text;
}

export async function readRequestJson(request, limit = 64 * 1024) {
  return JSON.parse(await readRequestText(request, limit));
}

export function requestTooLarge(error) {
  if (!(error instanceof RequestBodyTooLargeError)) throw error;
  return new Response("Payload Too Large", {
    status: 413,
    headers: { "Cache-Control": "no-store" },
  });
}
