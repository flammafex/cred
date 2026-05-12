#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STORE_DIR="${CRED_VAULT_SMOKE_STORE:-"$(mktemp -d /private/tmp/cred-vault.XXXXXX)"}"
PASSPHRASE="${CRED_VAULT_SMOKE_PASSPHRASE:-"correct horse battery staple"}"
BIN="$ROOT_DIR/target/debug/cred"

cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p cred-cli >/dev/null

"$BIN" --store "$STORE_DIR" record add "$ROOT_DIR/examples/witness-signed-attestation.json" \
  --record-id record-vault-witness-1 \
  --cred-id cred:local:example \
  --custody local_encrypted \
  --source-app app:witness:local \
  --vault-passphrase "$PASSPHRASE" \
  >"$STORE_DIR/record.json"
"$BIN" --store "$STORE_DIR" record reveal record-vault-witness-1 \
  --vault-passphrase "$PASSPHRASE" \
  >"$STORE_DIR/revealed.json"
"$BIN" hash "$STORE_DIR/revealed.json" >"$STORE_DIR/hash.json"
"$BIN" --store "$STORE_DIR" vault inventory >"$STORE_DIR/inventory.json"

node "$ROOT_DIR/scripts/vault-smoke-check.mjs" \
  "$STORE_DIR/record.json" \
  "$STORE_DIR/revealed.json" \
  "$STORE_DIR/hash.json" \
  "$STORE_DIR/inventory.json" \
  "$STORE_DIR"

if "$BIN" --store "$STORE_DIR" record reveal record-vault-witness-1 \
  --vault-passphrase wrong \
  >"$STORE_DIR/wrong-passphrase.json" 2>"$STORE_DIR/wrong-passphrase.err"; then
  echo "expected wrong vault passphrase to fail" >&2
  exit 1
fi

grep -q "failed to encrypt or decrypt vault blob" "$STORE_DIR/wrong-passphrase.err"
