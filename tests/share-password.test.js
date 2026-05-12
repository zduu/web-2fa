import { afterEach, describe, expect, it, vi } from "vitest";

import { b64url, fromB64url } from "../src/core/crypto.js";
import { wrapShareKeyWithPassword, unwrapShareKeyWithPassword } from "../src/core/share-password.js";
import { createShareLink } from "../src/share/share.js";
import { state } from "../src/core/storage.js";

afterEach(() => {
  vi.restoreAllMocks();
  state.globalToken = "";
});

describe("share password protection", () => {
  it("round-trips arbitrary bytes through b64url helpers", () => {
    const bytes = new Uint8Array(Array.from({ length: 31 }, (_, i) => (i * 17) % 256));
    expect(fromB64url(b64url(bytes))).toEqual(bytes);
  });

  it("wraps and unwraps a share key with a receiver password", async () => {
    const keyRaw = crypto.getRandomValues(new Uint8Array(32));
    const bundle = await wrapShareKeyWithPassword(keyRaw, "correct horse battery staple");
    const unwrapped = await unwrapShareKeyWithPassword(bundle, "correct horse battery staple");
    expect(unwrapped).toEqual(keyRaw);
  });

  it("stores share decrypt material by default for admin cross-device convenience", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toContain("/api/share/");
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toContain("/api/sharekey/");
    const body = JSON.parse(init.body);
    expect(body.k).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(body.requiresPassword).toBe(false);
  });

  it("can explicitly opt out of server-side share key storage", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    }, null, { storeKey: false });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toContain("/api/share/");
  });

  it("stores only the password-wrapped share bundle when protected escrow is enabled", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    }, null, { storeKey: true, password: "receiver pass" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toContain("/api/sharekey/");
    const body = JSON.parse(init.body);
    expect(body.k).toBe("");
    expect(body.requiresPassword).toBe(true);
    expect(body.protectedBundle).toMatchObject({
      s: expect.any(String),
      iv: expect.any(String),
      wk: expect.any(String),
      iter: expect.any(Number),
    });
  });
});
