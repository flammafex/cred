#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_DIR="${CRED_STDIO_SMOKE_STORE:-"$(mktemp -d /private/tmp/cred-stdio-service.XXXXXX)"}"
BIN="$ROOT_DIR/target/debug/cred"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cred-cli >/dev/null

"$BIN" --store "$STORE_DIR" key generate >"$STORE_DIR/key.json"

# Approve the grant via CLI before starting the stdio service.
# grant_approve/grant_deny are intentionally not exposed on the app-facing
# stdio channel — approvals must come from the trusted CLI. The grant itself
# is imported via the stdio service (cred.grant_import) since that is not
# security-sensitive.
"$BIN" --store "$STORE_DIR" grant approve "$ROOT_DIR/examples/witness-permission-grant.json" \
  --approval-id approval-stdio-witness-1 >/dev/null

node "$ROOT_DIR/scripts/stdio-service-smoke.mjs" "$BIN" "$STORE_DIR" "$ROOT_DIR"
