import { sha256HexFromString } from "./hash_engine.js";

export const STATIC_ARBITRATION_POLICY = {
  name: "deterministic_weight_desc",
  rules: ["rank nodes by weight", "select max nodes"]
};

export function rankVectors(vectors) {
  return [...vectors].sort((a, b) => {
    const weightDiff = b.weights.local - a.weights.local;
    if (weightDiff !== 0) {
      return weightDiff;
    }
    return a.id.localeCompare(b.id);
  });
}

export async function policyHash() {
  const policyString = JSON.stringify(STATIC_ARBITRATION_POLICY);
  const hash = await sha256HexFromString(policyString);
  return "sha256:" + hash;
}
