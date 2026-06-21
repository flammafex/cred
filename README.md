# Cred

Cred is a local-first user agent for holding, granting, and presenting portable
proofs. It is the user-owned boundary between apps and proof-bearing material:
keys, credentials, attestations, commitments, signatures, receipts, and app
permissions.

## Standalone Role

Cred can be used on its own as:

- a local key and credential agent.
- an attestation and receipt archive.
- a permission broker between apps and private proof material.
- a selective presentation layer for app-bound proofs.
- a local signing and hash-timestamping coordinator.

SophiaDOS uses Cred as infrastructure, not as a market primitive. Freebird,
Witness, Matchlock, and HyperToken remain the core primitives; Cred gives a
person one place to custody and present the artifacts those primitives create.

## Contract Shape

The v1 Cred contract defines five canonical artifacts:

- `cred.manifest`: public agent capabilities, controller key, and storage
  posture.
- `cred.permission_grant`: app-bound permission to request specific
  capabilities under constraints.
- `cred.action_request`: an app request for Cred to present, derive, sign,
  timestamp, or store something.
- `cred.presentation`: the app-bound response containing embedded or referenced
  artifacts.
- `cred.artifact_record`: local durable metadata for a stored artifact.

The schema lives at `contracts/schemas/cred-agent.schema.json`.

## Workspace

| Path | Purpose |
| --- | --- |
| `crates/cred-core` | Cred v1 artifact types, validation, canonical JSON, and SHA-256 hashing. |
| `crates/cred-store` | Durable local JSONL store for records, imported grants, and presentation audit metadata. |
| `crates/cred-cli` | `cred` command-line interface. |
| `contracts/` | Standalone Cred contract files. |
| `docs/` | Human-readable protocol notes, including the stdio service contract. |
| `examples/` | Example Cred artifacts. |

## Current CLI

```bash
cargo run -p cred-cli -- manifest \
  --cred-id cred:local:example \
  --controller-public-key 1111111111111111111111111111111111111111111111111111111111111111 \
  --capability freebird.present \
  --capability witness.timestamp \
  --capability matchlock.present_artifact

cargo run -p cred-cli -- inspect examples/manifest.json
cargo run -p cred-cli -- hash examples/action-request.json
cargo run -p cred-cli -- --store ./tmp/cred-store key generate
cargo run -p cred-cli -- --store ./tmp/cred-store key public
cargo run -p cred-cli -- --store ./tmp/cred-store witness import examples/witness-signed-attestation.json \
  --record-id record-witness-attestation-1 \
  --cred-id cred:local:example
cargo run -p cred-cli -- --store ./tmp/cred-store record list
cargo run -p cred-cli -- --store ./tmp/cred-store record get record-witness-attestation-1
cargo run -p cred-cli -- --store ./tmp/cred-store vault inventory
cargo run -p cred-cli -- --store ./tmp/cred-store record add examples/witness-signed-attestation.json \
  --record-id record-vault-witness-1 \
  --cred-id cred:local:example \
  --custody local_encrypted \
  --vault-passphrase "$CRED_VAULT_PASSPHRASE"
cargo run -p cred-cli -- --store ./tmp/cred-store record reveal record-vault-witness-1 \
  --vault-passphrase "$CRED_VAULT_PASSPHRASE"

# If --store is omitted, Cred uses CRED_STORE_DIR or $HOME/.local/share/cred.
# If --vault-passphrase is omitted, Cred uses CRED_VAULT_PASSPHRASE.

cargo run -p cred-cli -- grant check \
  --grant examples/permission-grant.json \
  --request examples/action-request.json
cargo run -p cred-cli -- grant review examples/witness-permission-grant.json
cargo run -p cred-cli -- --store ./tmp/cred-store grant import examples/witness-permission-grant.json
cargo run -p cred-cli -- --store ./tmp/cred-store grant approve examples/witness-permission-grant.json \
  --approval-id approval-witness-attestation-1
cargo run -p cred-cli -- --store ./tmp/cred-store grant list
cargo run -p cred-cli -- --store ./tmp/cred-store grant get grant-witness-attestation-1
cargo run -p cred-cli -- --store ./tmp/cred-store grant approvals

cargo run -p cred-cli -- --store ./tmp/cred-store witness present \
  --request examples/witness-presentation-request.json \
  --grant examples/witness-permission-grant.json \
  --approval-id approval-witness-attestation-1 \
  --record-id record-witness-attestation-1 \
  --presentation-id presentation-record-1 \
  --cred-id cred:local:example \
  --signing-key ./tmp/cred-store/controller_sk.hex

cargo run -p cred-cli -- --store ./tmp/cred-store freebird import-check examples/freebird-check-request.json \
  --record-id record-freebird-check-1 \
  --cred-id cred:local:example
cargo run -p cred-cli -- --store ./tmp/cred-store grant approve examples/freebird-permission-grant.json \
  --approval-id approval-freebird-check-1
cargo run -p cred-cli -- --store ./tmp/cred-store freebird present-check \
  --request examples/freebird-presentation-request.json \
  --grant examples/freebird-permission-grant.json \
  --approval-id approval-freebird-check-1 \
  --record-id record-freebird-check-1 \
  --presentation-id presentation-freebird-check-1 \
  --cred-id cred:local:example \
  --signing-key ./tmp/cred-store/controller_sk.hex

cargo run -p cred-cli -- --store ./tmp/cred-store matchlock import-artifact examples/matchlock-commitment.json \
  --record-id record-matchlock-commitment-1 \
  --cred-id cred:local:example
cargo run -p cred-cli -- --store ./tmp/cred-store grant approve examples/matchlock-permission-grant.json \
  --approval-id approval-matchlock-1
cargo run -p cred-cli -- --store ./tmp/cred-store matchlock present-artifact \
  --request examples/matchlock-presentation-request.json \
  --grant examples/matchlock-permission-grant.json \
  --approval-id approval-matchlock-1 \
  --record-id record-matchlock-commitment-1 \
  --presentation-id presentation-matchlock-1 \
  --cred-id cred:local:example \
  --signing-key ./tmp/cred-store/controller_sk.hex

cargo run -p cred-cli -- present \
  --request examples/action-request.json \
  --artifact examples/manifest.json \
  --presentation-id presentation-smoke-1 \
  --cred-id cred:local:example

cargo run -p cred-cli -- --store ./tmp/cred-store serve stdio
```

Stdio client contract and fixtures:

- `docs/cred-stdio-service.md`
- `examples/stdio-service/requests.jsonl`
- `examples/stdio-service/responses.example.jsonl`

Witness adapter smoke:

```bash
./scripts/witness-adapter-smoke.sh
./scripts/freebird-adapter-smoke.sh
./scripts/matchlock-adapter-smoke.sh
./scripts/vault-smoke.sh
./scripts/stdio-service-smoke.sh
```

## First Implementation Target

The first implementation is deliberately small:

1. Create a `cred.manifest`.
2. Validate and hash Cred JSON artifacts.
3. Store durable `cred.artifact_record` metadata.
4. Accept a `cred.action_request` file.
5. Enforce `cred.permission_grant` constraints for an action request.
6. Return a signed or unsigned `cred.presentation` for embedded or referenced
   artifacts.
7. Track imported grants and successful presentations as metadata-only local
   audit records.
8. Require an explicit local approval for the exact permission-grant hash
   before presenting under that grant.
9. Expose the same review, approval, inventory, and presentation paths through
   a minimal stdio JSONL service.

That is enough to prove the app boundary before adding HTTP service transport,
Freebird issuance, Witness timestamping, or Matchlock derivation.
