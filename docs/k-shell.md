# K-Shell Deterministic CLI Contract (v1)

K-Shell uses fixed command dispatch with no plugin loading, no script execution, no async runtime, and no dynamic module resolution.

## Command set

- `help`
- `emit` (deterministically emits `sha256.h`, `sha256.c`, `kux_verifier.c`, `build.bat`)
- `verify <artifact.json>`
- `hash <file>`
- `artifact <artifact.json>`
- `exit`

## Artifact contract enforcement

`artifact` and `verify` enforce the frozen collapse-artifact contract:

- `@artifact = collapse`
- `@version = v1`
- `@origin = sw.khl`
- `@deterministic = true`
- `input.timestamp = null`
- `collapse.entropy = 0.21`
- all proof flags = `true`
- `projection_ready = true`
- forbidden projection/orchestration fields rejected

`verify` is deterministic post-validation output:

- `Artifact VALID`
- `Replay OK`
- `Badge: KUX_v1_GOLD`

## Schema

The canonical JSON Schema lives at `artifact.schema.json` with id `kuhul://artifact/collapse/v1`.
