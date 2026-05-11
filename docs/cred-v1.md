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

Schema: `contracts/schemas/cred-agent.schema.json`.
