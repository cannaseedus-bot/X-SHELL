# X-SHELL

Deterministic XCFE control-plane PWA with strict boundary separation.

## Layered manifests

- `manifest.webmanifest` → install metadata only
- `runtime_manifest.json` → runtime capability/boundary contract
- `build_manifest.json` → reproducible build lock metadata
- `cpe.schema.json` → CPE envelope schema contract
- `artifact.schema.json` → sw.khl collapse artifact contract

## Reproducible build tooling

- `build.sh` → deterministic K-Shell build wrapper
- `verify_build.sh` → source+binary hash lock verification
- `scripts/source_tree_hash.sh` → canonical source tree hash for C/H files

## Deterministic C tooling

- `k_shell.c` → fixed-command deterministic verifier CLI
- `kux_codegen.c` → C-only stage-0 generator for deterministic verifier source emission

## Documentation

- `docs/k-shell.md` → K-Shell command and artifact contract
- `docs/reproducible-build.md` → reproducible build workflow
- `docs/stage0-codegen.md` → stage-0 generator workflow
