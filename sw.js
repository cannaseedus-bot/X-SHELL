const CACHE_NAME = "xshell-v2";

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache =>
      cache.addAll([
        "./",
        "./index.html",
        "./manifest.webmanifest",
        "./cpe.schema.json",
        "./css/styles.css",
        "./js/app.js",
        "./js/hash_engine.js",
        "./js/vector_store.js",
        "./js/flow_renderer.js",
        "./js/arbitration_simulator.js",
        "./js/scxq2.js",
        "./js/cpe_builder.js",
        "./js/cpe_validator.js",
        "./js/state_snapshotter.js",
        "./js/replay_simulator.js",
        "./js/proposal_emitter.js"
      ])
    )
  );
});

self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request).then(response => response || fetch(event.request))
  );
});
