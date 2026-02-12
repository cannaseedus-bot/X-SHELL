export function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (value !== null && typeof value === "object") {
    const sortedKeys = Object.keys(value).sort();
    const out = {};
    sortedKeys.forEach(key => {
      out[key] = canonicalize(value[key]);
    });
    return out;
  }

  return value;
}

export function canonicalJSONString(value) {
  return JSON.stringify(canonicalize(value));
}

export async function sha256HexFromString(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(value) {
  return sha256HexFromString(canonicalJSONString(value));
}
