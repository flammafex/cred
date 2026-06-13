#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_DIR="${CRED_FREEBIRD_SMOKE_STORE:-"$(mktemp -d /private/tmp/cred-freebird-adapter.XXXXXX)"}"
BIN="$ROOT_DIR/target/debug/cred"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cred-cli >/dev/null

"$BIN" --store "$STORE_DIR" key generate >"$STORE_DIR/key.json"
"$BIN" grant review "$ROOT_DIR/examples/freebird-permission-grant.json" \
  >"$STORE_DIR/grant-review.json"
"$BIN" --store "$STORE_DIR" grant approve "$ROOT_DIR/examples/freebird-permission-grant.json" \
  --approval-id approval-freebird-check-1 \
  >"$STORE_DIR/grant-approval.json"
"$BIN" --store "$STORE_DIR" freebird import-check "$ROOT_DIR/examples/freebird-check-request.json" \
  --record-id record-freebird-check-1 \
  --cred-id cred:local:example \
  --source-app app:freebird:local \
  >"$STORE_DIR/record.json"
"$BIN" --store "$STORE_DIR" freebird present-check \
  --request "$ROOT_DIR/examples/freebird-presentation-request.json" \
  --grant "$ROOT_DIR/examples/freebird-permission-grant.json" \
  --approval-id approval-freebird-check-1 \
  --record-id record-freebird-check-1 \
  --presentation-id presentation-freebird-check-1 \
  --cred-id cred:local:example \
  --signing-key "$STORE_DIR/controller_sk.hex" \
  >"$STORE_DIR/presentation.json"
"$BIN" verify "$STORE_DIR/presentation.json" >"$STORE_DIR/verify.json"

node "$ROOT_DIR/scripts/freebird-adapter-smoke-check.mjs" \
  "$STORE_DIR/record.json" \
  "$STORE_DIR/presentation.json" \
  "$STORE_DIR/verify.json"

if "$BIN" --store "$STORE_DIR" freebird import-check "$ROOT_DIR/examples/freebird-verify-request-consuming.json" \
  --record-id record-freebird-consuming-denied \
  --cred-id cred:local:example \
  >"$STORE_DIR/denied.json" 2>"$STORE_DIR/denied.err"; then
  echo "expected consuming Freebird import to fail" >&2
  exit 1
fi

grep -q "non-consuming and rejects freebird.verify_request" "$STORE_DIR/denied.err"
echo "Cred Freebird adapter smoke passed."
