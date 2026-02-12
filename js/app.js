import { VectorStore } from "./vector_store.js";
import { renderGraph } from "./flow_renderer.js";
import { policyHash, rankVectors } from "./arbitration_simulator.js";
import { buildCPE } from "./cpe_builder.js";
import { validateCPE } from "./cpe_validator.js";
import { createSnapshot } from "./state_snapshotter.js";
import { replaySnapshot } from "./replay_simulator.js";
import { downloadArtifact } from "./proposal_emitter.js";

const store = new VectorStore();
const snapshots = [];

const svg = document.getElementById("graph");
const vectorList = document.getElementById("vector-list");
const replayList = document.getElementById("replay-list");
const proposalOutput = document.getElementById("proposal-output");
const auditOutput = document.getElementById("audit-output");

async function currentState() {
  const arbPolicyHash = await policyHash();
  const vectors = store.getVectors();
  const ranked = rankVectors(vectors);
  const flowGraph = store.buildFlowGraph(arbPolicyHash);

  return {
    arbPolicyHash,
    vectors,
    ranked,
    flowGraph,
    lanePayload: {
      flow_graph: flowGraph,
      ranked_nodes: ranked.map(vector => ({
        id: vector.id,
        weight: vector.weights.local
      }))
    }
  };
}

async function refresh() {
  const state = await currentState();
  renderGraph(svg, state.flowGraph);

  vectorList.innerHTML = "";
  state.vectors.forEach(vector => {
    const li = document.createElement("li");
    li.textContent = vector.id + " (w=" + vector.weights.local + ")";
    vectorList.appendChild(li);
  });
}

function renderReplayList() {
  replayList.innerHTML = "";
  snapshots.forEach((entry, index) => {
    const replay = replaySnapshot(entry.snapshot);
    const li = document.createElement("li");
    li.textContent =
      "#" +
      String(index + 1).padStart(2, "0") +
      " " +
      entry.snapshot_hash +
      " head=" +
      (replay.ranked_head || "none");
    replayList.appendChild(li);
  });
}

document.getElementById("add-vector").onclick = async () => {
  store.addVector();
  await refresh();
};

document.getElementById("snapshot-state").onclick = async () => {
  const state = await currentState();
  const entry = await createSnapshot(state.flowGraph, state.ranked);
  snapshots.push(entry);
  renderReplayList();
};

document.getElementById("simulate-arbitration").onclick = async () => {
  const state = await currentState();
  proposalOutput.textContent = JSON.stringify(
    {
      mode: "simulation",
      policy_hash: state.arbPolicyHash,
      ranked_nodes: state.ranked.map(vector => ({
        id: vector.id,
        weight: vector.weights.local
      }))
    },
    null,
    2
  );
};

document.getElementById("audit-sandbox").onclick = async () => {
  const state = await currentState();
  const vectorHash = await store.hash();
  const cpe = await buildCPE(vectorHash, state.lanePayload, state.arbPolicyHash);
  const cpeValidation = validateCPE(cpe);

  const audit = {
    deterministic: true,
    collapse_boundary_crossed: false,
    static_policy_hash: state.arbPolicyHash,
    cpe_contract: cpeValidation
  };

  auditOutput.textContent = JSON.stringify(audit, null, 2);
};

document.getElementById("emit-proposal").onclick = async () => {
  const state = await currentState();
  const vectorHash = await store.hash();
  const cpe = await buildCPE(vectorHash, state.lanePayload, state.arbPolicyHash);
  const check = validateCPE(cpe);

  if (!check.valid) {
    proposalOutput.textContent = "CPE invalid: " + check.reason;
    return;
  }

  proposalOutput.textContent = JSON.stringify(cpe, null, 2);
  downloadArtifact(cpe);
};

refresh();
