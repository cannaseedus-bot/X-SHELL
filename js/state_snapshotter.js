import { canonicalJSONString, sha256HexFromString } from "./hash_engine.js";

export async function createSnapshot(flowGraph, rankedVectors) {
  const snapshot = {
    flow_graph: flowGraph,
    ranked_vectors: rankedVectors.map(vector => ({
      id: vector.id,
      weight: vector.weights.local
    }))
  };

  const canonical = canonicalJSONString(snapshot);
  const hash = await sha256HexFromString(canonical);

  return {
    snapshot_hash: "sha256:" + hash,
    snapshot
  };
}
