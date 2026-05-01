import { b64url, fromB64url, toB64, fromB64 } from "./crypto.js";

const PASSKEY_PRF_CONTEXT = new TextEncoder().encode("web-2fa-passkey-unlock-v1");
const PASSKEY_WRAP_CONTEXT = new TextEncoder().encode("web-2fa-passkey-wrap-v1");
const PASSKEY_RP_NAME = "Web 2FA Authenticator";

export function hasPasskeyPrfPrerequisites() {
  return typeof window !== "undefined"
    && !!window.isSecureContext
    && typeof PublicKeyCredential !== "undefined"
    && !!navigator?.credentials?.create
    && !!navigator?.credentials?.get;
}

export async function getPasskeyPrfSupport() {
  if (!hasPasskeyPrfPrerequisites()) {
    return { supported: false, reason: "需要 HTTPS 安全上下文和系统 Passkey 支持。" };
  }
  if (typeof PublicKeyCredential.getClientCapabilities === "function") {
    try {
      const capabilities = await PublicKeyCredential.getClientCapabilities();
      if (capabilities?.["extension:prf"] === false) {
        return { supported: false, reason: "当前浏览器或认证器不支持 WebAuthn PRF 扩展。" };
      }
      if (capabilities?.userVerifyingPlatformAuthenticator === false
        && capabilities?.passkeyPlatformAuthenticator === false) {
        return { supported: false, reason: "当前设备没有可用的用户验证 Passkey 认证器。" };
      }
      return { supported: true, capabilities };
    } catch {}
  }
  return { supported: true };
}

export async function createLocalUnlockPasskey({ label = "" } = {}) {
  const support = await getPasskeyPrfSupport();
  if (!support.supported) throw new Error(support.reason || "当前环境不支持 Passkey。");

  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: currentRpId(), name: PASSKEY_RP_NAME },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: `local-unlock@${currentRpId()}`,
        displayName: label || "Web 2FA 本地快捷解锁",
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      timeout: 60_000,
      attestation: "none",
      extensions: {
        prf: { eval: { first: PASSKEY_PRF_CONTEXT } },
        credProps: true,
      },
    }
  });
  if (!cred) throw new Error("Passkey 创建失败。");

  const credentialId = b64url(new Uint8Array(cred.rawId));
  let prfOutput = readPrfFirst(cred);
  if (!prfOutput) {
    const evaluated = await evaluatePasskeyPrf(credentialId);
    prfOutput = evaluated.prfOutput;
  }
  if (!prfOutput) throw new Error("Passkey 已创建，但当前认证器未返回可用的 PRF 输出。");

  const transports = typeof cred.response?.getTransports === "function"
    ? cred.response.getTransports().filter(Boolean)
    : [];

  return {
    credentialId,
    prfOutput,
    transports,
    label: label || "当前设备 Passkey",
  };
}

export async function evaluatePasskeyPrf(credentialId) {
  const idBytes = typeof credentialId === "string" ? fromB64url(credentialId) : new Uint8Array(credentialId);
  const idKey = typeof credentialId === "string" ? credentialId : b64url(idBytes);
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: currentRpId(),
      allowCredentials: [{ type: "public-key", id: idBytes }],
      userVerification: "required",
      timeout: 60_000,
      extensions: {
        prf: {
          evalByCredential: {
            [idKey]: { first: PASSKEY_PRF_CONTEXT }
          }
        }
      }
    }
  });
  if (!cred) throw new Error("Passkey 验证失败。");
  const prfOutput = readPrfFirst(cred);
  if (!prfOutput) throw new Error("当前浏览器或认证器不支持 Passkey PRF 输出。");
  return { credential: cred, prfOutput };
}

export async function wrapBytesWithPasskeyPrf(rawBytes, prfOutput, salt) {
  const key = await derivePasskeyWrappingKey(prfOutput, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, rawBytes));
  return { iv: toB64(iv), ct: toB64(ct) };
}

export async function unwrapBytesWithPasskeyPrf(wrapped, prfOutput, salt) {
  const key = await derivePasskeyWrappingKey(prfOutput, salt);
  const iv = fromB64(wrapped.iv);
  const ct = fromB64(wrapped.ct);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}

export async function derivePasskeyWrappingKey(prfOutput, salt) {
  const prfBytes = toUint8Array(prfOutput);
  const saltBytes = toUint8Array(salt);
  const material = new Uint8Array(PASSKEY_WRAP_CONTEXT.length + prfBytes.length + saltBytes.length);
  material.set(PASSKEY_WRAP_CONTEXT, 0);
  material.set(prfBytes, PASSKEY_WRAP_CONTEXT.length);
  material.set(saltBytes, PASSKEY_WRAP_CONTEXT.length + prfBytes.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function readPrfFirst(credential) {
  try {
    const results = credential?.getClientExtensionResults?.();
    const first = results?.prf?.results?.first;
    return first ? new Uint8Array(first) : null;
  } catch {
    return null;
  }
}

function currentRpId() {
  return location.hostname;
}

function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return new Uint8Array(value || []);
}
