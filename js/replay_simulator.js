export function replaySnapshot(snapshot) {
  return {
    replay_identity: "deterministic",
    vector_count: snapshot.flow_graph.nodes.length,
    ranked_head: snapshot.ranked_vectors[0] ? snapshot.ranked_vectors[0].id : null
  };
}
