#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_DIR="${CRED_MATCHLOCK_SMOKE_STORE:-"$(mktemp -d /private/tmp/cred-matchlock-adapter.XXXXXX)"}"
BIN="$ROOT_DIR/target/debug/cred"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cred-cli >/dev/null

"$BIN" --store "$STORE_DIR" key generate >"$STORE_DIR/key.json"
"$BIN" grant review "$ROOT_DIR/examples/matchlock-permission-grant.json" \
  >"$STORE_DIR/grant-review.json"
"$BIN" --store "$STORE_DIR" grant approve "$ROOT_DIR/examples/matchlock-permission-grant.json" \
  --approval-id approval-matchlock-1 \
  >"$STORE_DIR/grant-approval.json"
"$BIN" --store "$STORE_DIR" matchlock import-artifact "$ROOT_DIR/examples/matchlock-commitment.json" \
  --record-id record-matchlock-commitment-1 \
  --cred-id cred:local:example \
  --source-app app:matchlock:local \
  >"$STORE_DIR/record.json"
"$BIN" --store "$STORE_DIR" matchlock present-artifact \
  --request "$ROOT_DIR/examples/matchlock-presentation-request.json" \
  --grant "$ROOT_DIR/examples/matchlock-permission-grant.json" \
  --approval-id approval-matchlock-1 \
  --record-id record-matchlock-commitment-1 \
  --presentation-id presentation-matchlock-1 \
  --cred-id cred:local:example \
  --signing-key "$STORE_DIR/controller_sk.hex" \
  >"$STORE_DIR/presentation.json"
"$BIN" verify "$STORE_DIR/presentation.json" >"$STORE_DIR/verify.json"

node "$ROOT_DIR/scripts/matchlock-adapter-smoke-check.mjs" \
  "$STORE_DIR/record.json" \
  "$STORE_DIR/presentation.json" \
  "$STORE_DIR/verify.json"

if "$BIN" --store "$STORE_DIR" matchlock import-artifact "$ROOT_DIR/examples/matchlock-match-token.json" \
  --record-id record-matchlock-token-denied \
  --cred-id cred:local:example \
  >"$STORE_DIR/denied.json" 2>"$STORE_DIR/denied.err"; then
  echo "expected raw Matchlock token import to fail" >&2
  exit 1
fi

grep -q "rejects raw matchlock.match_token durable records" "$STORE_DIR/denied.err"
