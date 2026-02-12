import { canonicalJSONString } from "./hash_engine.js";

function toBase64(uint8Array) {
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < uint8Array.length; i += chunkSize) {
    const chunk = uint8Array.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

async function hashBytes(uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", uint8Array);
  return [...new Uint8Array(digest)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function scxq2Encode(payloadObject) {
  const canonical = canonicalJSONString(payloadObject);

  const tokens = canonical
    .replace(/[{}[\],:"]/g, " ")
    .split(/\s+/)
    .filter(Boolean);

  const dict = [...new Set(tokens)].sort();

  if (dict.length > 255) {
    throw new Error("SCXQ2 dictionary overflow");
  }

  const dictIndex = new Map();
  dict.forEach((token, index) => dictIndex.set(token, index));

  const encoder = new TextEncoder();
  const stream = tokens.map(token => dictIndex.get(token));

  const dictBytes = [];
  dict.forEach(token => {
    const encoded = encoder.encode(token);
    if (encoded.length > 255) {
      throw new Error("SCXQ2 token overflow");
    }
    dictBytes.push(encoded.length);
    dictBytes.push(...encoded);
  });

  const header = [
    dict.length,
    (stream.length >> 24) & 255,
    (stream.length >> 16) & 255,
    (stream.length >> 8) & 255,
    stream.length & 255
  ];

  const full = new Uint8Array([...header, ...dictBytes, ...stream]);
  const hashHex = await hashBytes(full);

  return {
    compressed_base64: toBase64(full),
    hash: "sha256:" + hashHex
  };
}
