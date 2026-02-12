#!/usr/bin/env bash
set -euo pipefail

# Canonical source hash for C/H sources only.
# Excludes VCS metadata and output artifacts by design.

export LC_ALL=C

files=$(find . -type f \( -name "*.c" -o -name "*.h" \) | sort)

if [ -z "$files" ]; then
  echo "error: no C/H sources found" >&2
  exit 1
fi

# shellcheck disable=SC2086
printf '%s\n' "$files" | xargs sha256sum | sha256sum | awk '{print $1}'
