# Stage-0 C-Only Code Generator

`kux_codegen.c` is a self-hosted C generator that emits a deterministic verifier stack:

- `sha256.h`
- `sha256.c`
- `kux_verifier.c`
- `build.bat`

## Determinism properties

- no Python or scripting runtime
- no template files loaded from disk
- no timestamps or random values
- static string-embedded outputs
- deterministic per-file SHA-256 printed by the generator
- byte-identical file emission across repeated runs

## Emitted verifier contract

`kux_verifier` command line:

```text
kux_verifier <collapse_hash> <mode> <layout> <declared_projection_hash>
```

Rules:

- `layout` must be `deterministic`
- projection hash is recomputed as SHA-256 of concatenated inputs
- mismatch returns non-zero and prints `FAIL: projection hash mismatch`

## Build

```bash
gcc -std=c11 -O2 -Wall -Wextra -pedantic kux_codegen.c -o kux_codegen
```

## Run

```bash
./kux_codegen
```

The generator overwrites the four output files with byte-identical content each run.
