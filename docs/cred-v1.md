# Cred v1 Contract

Cred v1 describes the minimum interface for a local proof agent that can stand
alone or participate in SophiaDOS.

## Identity Boundary

Cred has a controller key so apps can verify that a presentation came from the
same local agent that granted permission. That key is not a universal human
identity. Apps should treat Cred presentations as app-bound responses to
specific requests.

Cred v1 signs presentations with Ed25519 over canonical JSON with
`cred_signature` omitted from the signed payload. The local CLI stores
controller secret keys as hex files by explicit path or at
`$CRED_STORE_DIR/controller_sk.hex`; generated files are created with owner-only
permissions on Unix platforms. This is local key custody, not encrypted key
management.

## Artifact Lifecycle

1. `cred.manifest` advertises the agent's controller key, supported
   capabilities, storage posture, and optional endpoints.
2. `cred.permission_grant` records what an app may ask for and under which
   constraints.
3. `cred.action_request` asks Cred to do work on behalf of an app.
4. `cred.presentation` answers a request with embedded, referenced, or redacted
   artifacts.
5. `cred.artifact_record` stores local metadata for artifacts under Cred
   custody.

## Capability Names

Capabilities are dotted lowercase names. Initial SophiaDOS-facing capabilities
include:

- `freebird.present`
- `freebird.issue`
- `witness.timestamp`
- `witness.present_attestation`
- `matchlock.derive_commitment`
- `matchlock.present_artifact`
- `matchlock.present_nullifier`
- `hypertoken.session`
- `sign.payload`
- `store.artifact`

Unknown capabilities must require explicit user approval before use.

## Witness Adapter

The Cred CLI exposes a named Witness adapter:

- `cred witness import` accepts only `sophia/v1`
  `witness.signed_attestation` artifacts and writes a slim
  `cred.artifact_record`.
- `cred witness present` presents an imported Witness attestation by reference,
  optionally gated by a `cred.permission_grant` and signed with the controller
  key.

The adapter is intentionally narrow. It does not verify Witness node signatures
itself; it preserves the Witness artifact hash and lets apps combine Cred
presentation verification with Witness verification.

## Freebird Adapter

The Cred CLI exposes a named non-consuming Freebird adapter:

- `cred freebird import-check` accepts only `sophia/v1`
  `freebird.check_request` artifacts and writes a slim `cred.artifact_record`.
- `cred freebird present-check` presents an imported check request by reference,
  optionally gated by a `cred.permission_grant` and signed with the controller
  key.

Cred does not own consuming Freebird token flows. The Freebird adapter rejects
`freebird.verify_request` artifacts and does not call `/v1/verify`; consuming
verification remains an app or verifier responsibility.

## Matchlock Adapter

The Cred CLI exposes a named Matchlock adapter for presentation-safe artifacts:

- `cred matchlock import-artifact` accepts `sophia/v1`
  `matchlock.participant_public_key`, `matchlock.commitment`,
  `matchlock.nullifier`, and opaque PSI envelope artifacts, then writes a slim
  `cred.artifact_record`.
- `cred matchlock present-artifact` presents an imported Matchlock artifact by
  reference, optionally gated by a `cred.permission_grant` and signed with the
  controller key.

The adapter rejects raw `matchlock.match_token` durable records. Match tokens
encode private selection state; Cred should present commitments, nullifiers,
public keys, or opaque PSI envelopes instead of placing raw tokens in durable
records.

## Grant Enforcement

A `cred.action_request` is allowed only when it matches a
`cred.permission_grant`:

- `app_id` must match.
- `grant_id` must be present on the request and equal to the grant.
- every action `kind` must appear in the grant's `capabilities`.
- action `audience` values must appear in `constraints.allowed_audiences` when
  that constraint is present.
- action `artifact_type` values must appear in
  `constraints.allowed_artifact_types` when that constraint is present.
- expired grants and exhausted `max_uses` grants must be rejected.
- export-style capabilities ending in `.export` require
  `constraints.allow_export: true`.

When Cred produces a presentation with a grant, the presented artifact type is
also checked against `constraints.allowed_artifact_types` when that constraint
is present. If the request itself names `action.artifact_type`, the presentation
must use one of those requested artifact types.

## Disclosure Modes

Presented artifacts use one of three disclosure modes:

- `embedded`: the artifact is included in the presentation.
- `reference`: the presentation points to a stored record.
- `redacted`: the presentation proves or acknowledges existence without
  revealing the artifact.

## Storage Rules

`cred.artifact_record` is metadata. It may contain hashes, labels, source app,
privacy class, and custody class. It must not contain raw private keys,
Matchlock private inputs, unspent Freebird tokens, or other secret material.

The v1 local store writes records to `records.jsonl`, one validated
`cred.artifact_record` per line. `record_id` values are unique within a store.
The durable record file remains a slim index even when Cred has local custody
of the raw artifact.

Cred v1 supports two durable custody modes:

- `external_reference`: Cred hashes the provided artifact and stores metadata
  with an `artifact_uri` pointing to the external location.
- `local_encrypted`: Cred canonicalizes the provided artifact, encrypts it as a
  local blob, and stores only the blob URI and plaintext hash in
  `cred.artifact_record`.

Local encrypted blobs use XChaCha20-Poly1305 with a 192-bit nonce. The content
encryption key is derived from the vault passphrase with scrypt using per-blob
salt. The encrypted blob stores encryption parameters, the plaintext artifact
hash, the stored artifact type, and ciphertext. It must not contain plaintext
artifact fields.

Use `--vault-passphrase` or `CRED_VAULT_PASSPHRASE` for commands that create or
reveal `local_encrypted` records. `record reveal` decrypts a local encrypted
record, verifies the decrypted artifact hash against the record, and prints the
artifact.

`vault inventory` summarizes local holdings without decrypting artifacts. It
groups record counts by artifact type, custody mode, and privacy class, and
reports whether each `local_encrypted` record has its encrypted blob present.

The v1 local store also writes two metadata-only audit indexes:

- `grants.jsonl`: imported permission grants represented as
  `cred.stored_grant` summaries. Each entry stores the grant id, app id,
  granted capabilities, constraints, source URI, timestamps, and the canonical
  hash of the original `cred.permission_grant`.
- `presentation_audit.jsonl`: successful presentation events represented as
  `cred.presentation_audit` summaries. Each entry stores the presentation id,
  request id, app id, optional grant id, presentation hash, presented artifact
  hashes, referenced record ids, and disclosure modes.

These audit files do not contain decrypted artifacts, embedded raw proof
material, local private keys, or vault passphrases. They answer inventory
questions such as "who has access?" and "what have I disclosed?" while keeping
artifact custody separate from authorization and disclosure history.

`vault inventory` includes those imported grants and successful presentation
audit entries alongside holdings, so the inventory can be generated without
decrypting local encrypted blobs.

Schema: `contracts/schemas/cred-agent.schema.json`.
