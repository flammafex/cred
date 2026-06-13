#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_DIR="${CRED_WITNESS_SMOKE_STORE:-"$(mktemp -d /private/tmp/cred-witness-adapter.XXXXXX)"}"
BIN="$ROOT_DIR/target/debug/cred"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cred-cli >/dev/null

"$BIN" --store "$STORE_DIR" key generate >"$STORE_DIR/key.json"
"$BIN" grant review "$ROOT_DIR/examples/witness-permission-grant.json" \
  >"$STORE_DIR/grant-review.json"
"$BIN" --store "$STORE_DIR" grant approve "$ROOT_DIR/examples/witness-permission-grant.json" \
  --approval-id approval-witness-adapter-1 \
  >"$STORE_DIR/grant-approval.json"
"$BIN" --store "$STORE_DIR" witness import "$ROOT_DIR/examples/witness-signed-attestation.json" \
  --record-id record-witness-attestation-1 \
  --cred-id cred:local:example \
  --source-app app:witness:local \
  >"$STORE_DIR/record.json"
"$BIN" --store "$STORE_DIR" witness present \
  --request "$ROOT_DIR/examples/witness-presentation-request.json" \
  --grant "$ROOT_DIR/examples/witness-permission-grant.json" \
  --approval-id approval-witness-adapter-1 \
  --record-id record-witness-attestation-1 \
  --presentation-id presentation-witness-adapter-1 \
  --cred-id cred:local:example \
  --signing-key "$STORE_DIR/controller_sk.hex" \
  >"$STORE_DIR/presentation.json"
"$BIN" verify "$STORE_DIR/presentation.json" >"$STORE_DIR/verify.json"

node "$ROOT_DIR/scripts/witness-adapter-smoke-check.mjs" \
  "$STORE_DIR/record.json" \
  "$STORE_DIR/presentation.json" \
  "$STORE_DIR/verify.json"
