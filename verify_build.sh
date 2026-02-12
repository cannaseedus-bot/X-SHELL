#!/usr/bin/env bash
set -euo pipefail

manifest="build_manifest.json"

if [ ! -f "$manifest" ]; then
  echo "error: missing $manifest" >&2
  exit 1
fi

expected_bin_hash=$(python3 - <<'PY'
import json
with open('build_manifest.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
print(data.get('expected_sha256', ''))
PY
)

expected_source_hash=$(python3 - <<'PY'
import json
with open('build_manifest.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
print(data.get('source_tree_hash', ''))
PY
)

if [ -z "$expected_bin_hash" ] || [ "$expected_bin_hash" = "TO_BE_FILLED" ]; then
  echo "error: build_manifest.json expected_sha256 is not locked" >&2
  exit 1
fi

if [ -z "$expected_source_hash" ] || [ "$expected_source_hash" = "TO_BE_FILLED" ]; then
  echo "error: build_manifest.json source_tree_hash is not locked" >&2
  exit 1
fi

actual_source_hash=$(./scripts/source_tree_hash.sh)

if [ "$actual_source_hash" != "$expected_source_hash" ]; then
  echo "FAIL: source tree hash mismatch"
  echo "expected: $expected_source_hash"
  echo "actual:   $actual_source_hash"
  exit 1
fi

./build.sh
actual_bin_hash=$(awk '{print $1}' k_shell.exe.sha256)

if [ "$actual_bin_hash" != "$expected_bin_hash" ]; then
  echo "FAIL: binary hash mismatch"
  echo "expected: $expected_bin_hash"
  echo "actual:   $actual_bin_hash"
  exit 1
fi

echo "PASS: reproducible build verified"
