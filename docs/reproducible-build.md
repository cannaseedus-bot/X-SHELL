# Reproducible Build Pipeline (K-Shell)

This repository separates concerns into distinct manifests and layers:

- `manifest.webmanifest`: install metadata only (PWA surface).
- `runtime_manifest.json`: runtime capability and boundary declaration for X-Shell.
- `build_manifest.json`: supply-chain lock for deterministic kernel builds.

## Reproducible Build Law

A build is reproducible only if all of the following are fixed:

- source tree
- compiler identity/version
- target triplet
- flags and linker options
- locale/time environment

Then:

`sha256(binary_A) == sha256(binary_B)`

## Deterministic Build Command

```bash
./build.sh
```

`build.sh` enforces deterministic constraints:

- pinned compiler command (overrideable via `CC=`)
- strict flags (`-O2 -static -std=c11 -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector`)
- timestamp stripping (`-Wl,--no-insert-timestamp`)
- normalized env (`LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH=0`)

Outputs:

- `k_shell.exe`
- `k_shell.exe.sha256`

## Canonical Source Tree Hash

```bash
./scripts/source_tree_hash.sh
```

This computes a canonical hash over sorted `*.c`/`*.h` files.

## Verification Flow

1. Fill `build_manifest.json` placeholders:
   - `compiler.compiler_sha256`
   - `source_tree_hash`
   - `expected_sha256`
2. Run:

```bash
./verify_build.sh
```

The verifier checks:

- source hash matches locked `source_tree_hash`
- produced binary hash matches locked `expected_sha256`

If either differs, verification fails deterministically.

## Optional Hermetic Mode

For stronger isolation, use a pinned Docker image and run `build.sh` inside it.
