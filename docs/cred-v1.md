# Cred v1 Contract

Cred v1 describes the minimum interface for a local proof agent that can stand
alone or participate in SophiaDOS.

## Identity Boundary

Cred has a controller key so apps can verify that a presentation came from the
same local agent that granted permission. That key is not a universal human
identity. Apps should treat Cred presentations as app-bound responses to
specific requests.

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
- `matchlock.present_nullifier`
- `hypertoken.session`
- `sign.payload`
- `store.artifact`

Unknown capabilities must require explicit user approval before use.

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
The store is append-only metadata for now; raw artifact custody remains outside
the durable record file.

Schema: `contracts/schemas/cred-agent.schema.json`.
