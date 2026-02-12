#!/usr/bin/env bash
set -euo pipefail

CC="${CC:-x86_64-w64-mingw32-gcc}"
SRC="${SRC:-k_shell.c}"
OUT="${OUT:-k_shell.exe}"
HASH_OUT="${HASH_OUT:-k_shell.exe.sha256}"

CFLAGS=(
  -O2
  -static
  -std=c11
  -fno-ident
  -fno-asynchronous-unwind-tables
  -fno-stack-protector
)

LDFLAGS=(
  -Wl,--no-insert-timestamp
)

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "error: compiler not found: $CC" >&2
  exit 1
fi

if [ ! -f "$SRC" ]; then
  echo "error: source file not found: $SRC" >&2
  exit 1
fi

# Prevent host/environment entropy from leaking into generated output.
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH=0

"$CC" "$SRC" "${CFLAGS[@]}" "${LDFLAGS[@]}" -o "$OUT"
sha256sum "$OUT" > "$HASH_OUT"

echo "Build complete: $OUT"
echo "SHA256 written to: $HASH_OUT"
