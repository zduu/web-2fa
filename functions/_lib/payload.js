export function isCipherPayload(value) {
  return !!(
    value &&
    typeof value === "object" &&
    typeof value.iv === "string" &&
    value.iv.trim() &&
    typeof value.ct === "string" &&
    value.ct.trim()
  );
}

export function isVaultPayload(value) {
  if (isVaultCipher(value)) return true;
  if (!value || typeof value !== "object" || !Array.isArray(value.recipients)) return false;
  return value.recipients.length > 0 && value.recipients.every((recipient) => {
    const cipher = recipient?.cipher || recipient;
    return isVaultCipher(cipher);
  });
}

function isVaultCipher(value) {
  return !!(
    value &&
    typeof value === "object" &&
    typeof value.ek === "string" &&
    value.ek.trim() &&
    typeof value.iv === "string" &&
    value.iv.trim() &&
    typeof value.ct === "string" &&
    value.ct.trim()
  );
}
