const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const ALLOWED_PROOFS = new Set([
  "collapse_only",
  "one_outcome",
  "field_perception",
  "compression_law"
]);

const REQUIRED_KEYS = [
  "@proposal",
  "@version",
  "vector_state_hash",
  "lane_configuration_hash",
  "arbitration_policy_hash",
  "entropy_expected",
  "proposed_signal_hash",
  "proof_expectations"
];

export function validateCPE(cpe) {
  const keys = Object.keys(cpe).sort();
  const requiredSorted = [...REQUIRED_KEYS].sort();
  if (JSON.stringify(keys) !== JSON.stringify(requiredSorted)) {
    return { valid: false, reason: "CPE has missing or extra properties" };
  }

  if (cpe["@proposal"] !== "xcfe-collapse") {
    return { valid: false, reason: "@proposal must be xcfe-collapse" };
  }

  if (cpe["@version"] !== "v1") {
    return { valid: false, reason: "@version must be v1" };
  }

  if (!SHA256_PATTERN.test(cpe.vector_state_hash)) {
    return { valid: false, reason: "Invalid vector_state_hash" };
  }

  if (!SHA256_PATTERN.test(cpe.lane_configuration_hash)) {
    return { valid: false, reason: "Invalid lane_configuration_hash" };
  }

  if (!SHA256_PATTERN.test(cpe.arbitration_policy_hash)) {
    return { valid: false, reason: "Invalid arbitration_policy_hash" };
  }

  if (!SHA256_PATTERN.test(cpe.proposed_signal_hash)) {
    return { valid: false, reason: "Invalid proposed_signal_hash" };
  }

  if (cpe.entropy_expected !== 0.21) {
    return { valid: false, reason: "entropy_expected must equal 0.21" };
  }

  if (!Array.isArray(cpe.proof_expectations) || cpe.proof_expectations.length < 1) {
    return { valid: false, reason: "proof_expectations must be non-empty array" };
  }

  const unique = new Set(cpe.proof_expectations);
  if (unique.size !== cpe.proof_expectations.length) {
    return { valid: false, reason: "proof_expectations must be unique" };
  }

  const invalidProof = cpe.proof_expectations.find(item => !ALLOWED_PROOFS.has(item));
  if (invalidProof) {
    return { valid: false, reason: "Invalid proof expectation: " + invalidProof };
  }

  return { valid: true, reason: "CPE contract valid" };
}
