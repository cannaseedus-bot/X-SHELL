import { scxq2Encode } from "./scxq2.js";
import { sha256HexFromString } from "./hash_engine.js";

const DEFAULT_PROOF_EXPECTATIONS = ["collapse_only", "one_outcome", "compression_law"];
const NULL_HASH = "0".repeat(64);

export async function buildCPE(vectorHash, lanePayload, arbitrationPolicyHash) {
  const lane = await scxq2Encode(lanePayload);
  const signalHash = await sha256HexFromString(JSON.stringify(lanePayload));

  return {
    "@proposal": "xcfe-collapse",
    "@version": "v1",
    vector_state_hash: "sha256:" + vectorHash,
    lane_configuration_hash: lane.hash,
    arbitration_policy_hash: arbitrationPolicyHash || "sha256:" + NULL_HASH,
    entropy_expected: 0.21,
    proposed_signal_hash: "sha256:" + signalHash,
    proof_expectations: DEFAULT_PROOF_EXPECTATIONS
  };
}
