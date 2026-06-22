#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_DIR="${CRED_HTTP_SMOKE_STORE:-"$(mktemp -d /private/tmp/cred-http-service.XXXXXX)"}"
PORT="${CRED_HTTP_SMOKE_PORT:-0}"
BIN="$ROOT_DIR/target/debug/cred"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cred-cli >/dev/null

"$BIN" --store "$STORE_DIR" key generate >"$STORE_DIR/key.json"

# Approve the grant via CLI before starting the HTTP service.
"$BIN" --store "$STORE_DIR" grant approve "$ROOT_DIR/examples/witness-permission-grant.json" \
  --approval-id approval-stdio-witness-1 >/dev/null

node "$ROOT_DIR/scripts/http-service-smoke.mjs" "$BIN" "$STORE_DIR" "$ROOT_DIR" "$PORT"
