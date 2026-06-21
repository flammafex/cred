# AGENTS.md — Cred

Guidance for AI agents and contributors working on the Cred repository.

## What Cred is

Cred is a local-first Rust user agent for holding, granting, and presenting
portable proofs. It is the user-owned boundary between apps and proof-bearing
material: keys, credentials, attestations, commitments, signatures, receipts,
and app permissions.

Cred is infrastructure for a broader ecosystem (SophiaDOS, Freebird, Witness,
Matchlock, HyperToken) — it gives a person one place to custody and present the
artifacts those primitives create.

## Workspace layout

| Path | Purpose |
| --- | --- |
| `crates/cred-core` | Artifact types, validation, canonical JSON, SHA-256 hashing, Ed25519 signing, grant enforcement. Single file: `src/lib.rs` (~1210 lines). |
| `crates/cred-store` | Durable local JSONL store + encrypted vault (XChaCha20Poly1305 + scrypt). Single file: `src/lib.rs` (~1060 lines). |
| `crates/cred-cli` | `cred` binary — all commands, stdio JSONL service, adapters. Single file: `src/main.rs` (~3017 lines). |
| `contracts/schemas/cred-agent.schema.json` | Canonical JSON Schema for the five v1 artifacts. |
| `docs/` | Protocol design (`cred-v1.md`), stdio service contract (`cred-stdio-service.md`), social graph adapter (`social-graph-adapter.md`). |
| `examples/` | Fixtures for every artifact type, including stdio service request/response pairs. |
| `scripts/` | Smoke test pairs: `.sh` builds + runs workflow, `.mjs` asserts. |

Dependency direction: `cred-cli` → `cred-store` → `cred-core`. Core depends on
nothing internal.

## Build, test, verify

```bash
cargo build                  # build all crates
cargo test                   # all workspace tests (inline #[cfg(test)] modules)
cargo test -p cred-core      # core unit + integration tests
cargo test -p cred-store     # store unit tests
cargo test -p cred-cli       # CLI unit tests
cargo clippy                 # lints (no config present)
./scripts/*-smoke.sh         # smoke tests (requires `node` on PATH; no npm install)
```

Smoke scripts: `stdio-service-smoke.sh`, `freebird-adapter-smoke.sh`,
`witness-adapter-smoke.sh`, `matchlock-adapter-smoke.sh`, `vault-smoke.sh`.
Each `.sh` builds `cred-cli`, provisions a temp store, runs a workflow, then
invokes a matching `.mjs` checker that asserts on the output.

## Critical invariants (do not break)

These are enforced in code and/or smoke tests. Any change must preserve them:

- Vault blobs store ciphertext only — never plaintext artifacts. Enforced in
  `crates/cred-store/src/lib.rs:334-413`; asserted in
  `scripts/vault-smoke-check.mjs`.
- Grant and presentation audit records are metadata-only — never raw proof
  material. See `crates/cred-store/src/lib.rs:152-176`, `628-655`.
- Private keys, Matchlock secrets, and unspent credentials are never published
  or printed. CLI key commands print public key/path only
  (`crates/cred-cli/src/main.rs:827-853`).
- `matchlock.match_token` import is rejected (raw token).
  `crates/cred-cli/src/main.rs:1398-1411`, tested at `2831-2845`.
- `freebird.verify_request` (consuming flow) import is rejected.
  `crates/cred-cli/src/main.rs:1028-1035`, tested at `2798-2810`.
- Local approval is required before presenting under a grant — exact grant
  hash must match the latest approval, and a later denial blocks presentation.
  `crates/cred-cli/src/main.rs:2193-2245`.
- Canonical JSON must stay deterministic: sorted object keys, arrays in order,
  floats rejected. `crates/cred-core/src/lib.rs:812-855`.
- Unknown capabilities are not silently granted — local approval gates all
  grants.

## Known risks (flagged by architecture review)

These are known gaps, not yet fixed. Consider them before touching related code:

1. **Stdio exposes `grant_approve`/`grant_deny` on the app-facing channel.**
   Any stdin-controlling process can self-approve
   (`crates/cred-cli/src/main.rs:614-631`, `673-690`).
2. **Store is not crash-safe or tamper-evident.** JSONL appends have no fsync,
   lock, or hash chain (`crates/cred-store/src/lib.rs:523-555`).
3. **Grant `cred_signature` is shape-validated only, not cryptographically
   verified.** `crates/cred-core/src/lib.rs:491-493`.
4. **`app_pubkey` is not used to authenticate requests** — only string
   `app_id` is compared (`crates/cred-core/src/lib.rs:385-387`).
5. **Canonical JSON is a local implementation, not RFC 8785/JCS** —
   cross-language consumers need a spec (`crates/cred-core/src/lib.rs:812-855`).

## Conventions

- Single-file crates: each crate is one `lib.rs` or `main.rs`. Large but flat.
- `#[serde(deny_unknown_fields)]` on artifact structs.
- Artifact-type strings are lowercase dotted namespaces: `cred.*`,
  `witness.*`, `freebird.*`, `social_graph.*`, `matchlock.*`.
- Error layering: `thiserror` in core/store, `anyhow` in CLI.
- `CONTRACT_VERSION` constant in `crates/cred-core/src/lib.rs:7`; version
  strings repeated in store records/blobs/audits and CLI JSON outputs.
- Tests are inline `#[cfg(test)]` modules; one integration test at
  `crates/cred-core/tests/social_graph_presentation_test.rs`.
- CLI favors JSON output for command summaries and service responses.

## Crypto stack

- **Signing**: Ed25519 via `ed25519-dalek` (`sign_presentation`,
  `verify_presentation_signature` in `crates/cred-core/src/lib.rs:325-365`).
- **Hashing**: SHA-256 over canonical JSON
  (`crates/cred-core/src/lib.rs:308-317`).
- **Encryption**: XChaCha20Poly1305, 24-byte nonce, per-blob random
  salt+nonce (`crates/cred-store/src/lib.rs:359-368`).
- **KDF**: scrypt, params `log_n=15, r=8, p=1` (fixed,
  `crates/cred-store/src/lib.rs:32-34`).
- **AAD**: binds `record_id`, stored artifact type, plaintext hash
  (`crates/cred-store/src/lib.rs:682-687`).
- **Key gen**: 32 bytes from `/dev/urandom`, stored as hex with `0600` perms
  (`crates/cred-cli/src/main.rs:2407-2435`).
- **Zeroize**: plaintext buffers and derived keys zeroized after
  encrypt/decrypt (`crates/cred-store/src/lib.rs:376-383`, `459-475`).
  Passphrases and `serde_json::Value` artifacts are not zeroized.

## Store on-disk layout

Root: `CRED_STORE_DIR` or `$HOME/.local/share/cred`
(`crates/cred-store/src/lib.rs:206-213`).

- `records.jsonl` — artifact records
- `grants.jsonl` — imported permission grants
- `grant_approvals.jsonl` — local approval decisions
- `presentation_audit.jsonl` — presentation audit entries
- `blobs/<sha256(record_id)>.json` — encrypted artifact blobs

## Env vars

| Var | Purpose |
| --- | --- |
| `CRED_STORE_DIR` | Store root (default `$HOME/.local/share/cred`) |
| `CRED_VAULT_PASSPHRASE` | Vault encryption passphrase |
| `CRED_CONTROLLER_SK` | Controller secret key path |
| `CRED_*_SMOKE_*` | Smoke test temp stores/passphrases |

## When adding a new adapter

Adapter logic is hand-coded in `crates/cred-cli/src/main.rs` (see
witness/freebird/matchlock/social_graph at `856-1459`). Adding an adapter
currently touches: Clap command structs, import + present functions, shape
validation, tests, examples, and docs. There is no adapter trait or
registration system — each is a parallel implementation.
