import { describe, expect, it } from "vitest";

import { b64url, fromB64url } from "../src/core/crypto.js";
import { wrapShareKeyWithPassword, unwrapShareKeyWithPassword } from "../src/core/share-password.js";

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
});
