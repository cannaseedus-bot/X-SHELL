import { canonicalize, sha256Hex } from "./hash_engine.js";

export class VectorStore {
  constructor() {
    this.vectors = [];
  }

  addVector() {
    const id = "node_" + String(this.vectors.length).padStart(3, "0");
    this.vectors.push({
      "@xcfe_vector": "v1",
      id,
      state: {
        domain: "analysis",
        magnitude: this.vectors.length + 1,
        phase: 0
      },
      weights: {
        inbound: 0,
        local: this.vectors.length + 1,
        outbound: this.vectors.length + 1
      },
      lanes: [],
      constraints: ["no_parallel_collapse", "deterministic_only"]
    });
  }

  getVectors() {
    return [...this.vectors]
      .map(canonicalize)
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  buildFlowGraph(policyHash) {
    const vectors = this.getVectors();
    const nodes = vectors.map(vector => ({
      id: vector.id,
      weight: vector.weights.local
    }));

    const edges = [];
    for (let i = 0; i < nodes.length - 1; i++) {
      edges.push({
        from: nodes[i].id,
        to: nodes[i + 1].id,
        weight: nodes[i + 1].weight
      });
    }

    return canonicalize({
      "@xcfe_flow": "v1",
      nodes: nodes.sort((a, b) => a.id.localeCompare(b.id)),
      edges: edges.sort((a, b) =>
        a.from === b.from ? a.to.localeCompare(b.to) : a.from.localeCompare(b.from)
      ),
      policy_hash: policyHash
    });
  }

  async hash() {
    return sha256Hex(this.getVectors());
  }
}
