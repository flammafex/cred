#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_DIR="${CRED_STDIO_SMOKE_STORE:-"$(mktemp -d /private/tmp/cred-stdio-service.XXXXXX)"}"
BIN="$ROOT_DIR/target/debug/cred"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cred-cli >/dev/null

"$BIN" --store "$STORE_DIR" key generate >"$STORE_DIR/key.json"
node "$ROOT_DIR/scripts/stdio-service-smoke.mjs" "$BIN" "$STORE_DIR" "$ROOT_DIR"
