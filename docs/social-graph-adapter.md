# Cred Social Graph Adapter Contract

Status: Pre-Phase 1 contract specification.

The `social_graph` adapter lets Cred import short-lived social graph eligibility
attestations and present them to a Freebird issuer as app-bound Cred
presentations. Graph analysis happens outside Cred. Cred's job is custody,
permission enforcement, per-use approval, and binding a general-purpose
attestation to one Freebird issuance request.

## Overview

The adapter accepts signed `social_graph.attestation` artifacts issued by a
trusted Social Graph Attester. The attestation is bound to the Cred controller
key by `holder_commitment`, but it is not bound to a Freebird request. At
presentation time Cred embeds the attestation in a `cred.presentation`, adds the
Freebird `request_binding_hash`, and signs the presentation with the Cred
controller key.

Freebird receives the resulting presentation through `SybilProof::SocialGraph`.
The issuer verifies the Cred presentation signature, the attester signature, the
request binding hash, the policy, expiry, eligibility level, and replay state.

The adapter must not import or present raw social graph material: Clout public
keys, trust edges, invitation chains, wallet history, exact graph scores, ballot
or rendezvous identifiers, stable user identifiers, or Freebird request bindings
inside the attestation.

## Artifact types

### `social_graph.attestation`

`social_graph.attestation` is a `sophia/v1` canonical artifact with these
fields:

- `contract_version`: always `"sophia/v1"`.
- `artifact_type`: always `"social_graph.attestation"`.
- `version`: attestation schema version, for example `"1"`.
- `attester_id`: identifier of the issuing attester.
- `kid`: attester signing key id.
- `policy_id`: scoring policy applied by the attester.
- `issued_at`: Unix seconds.
- `expires_at`: Unix seconds, greater than `issued_at` and normally no more
  than five minutes later.
- `eligibility_level`: coarse eligibility bucket, `1` through `3`.
- `quota_nullifier`: optional lowercase hex SHA-256 string for epoch quota.
- `jti`: unique attestation id.
- `holder_commitment`: lowercase hex SHA-256 of the Cred controller public key
  bytes.
- `signature`: lowercase hex Ed25519 signature by the attester over canonical
  JSON with `signature` omitted.

The adapter preserves the canonical artifact hash. It may verify basic shape,
expiry, and signature if trusted attester keys are configured, but apps and
Freebird issuers must still verify the attester signature independently.

### Mapping to `cred.artifact_record`

Importing an attestation writes a slim `cred.artifact_record`:

- `stored_artifact_type`: `"social_graph.attestation"`.
- `artifact_hash`: SHA-256 of the canonical imported attestation.
- `privacy`: `"selective"`.
- `custody`: normally `"local_encrypted"`; `"external_reference"` is allowed
  when Cred only stores a URI.
- `source_app`: the attester id or importing app id when known.
- `labels`: should include `"social_graph"` and may include policy or attester
  labels.

The durable record is metadata only. It must not contain raw graph evidence or
decrypted attestation contents when local encrypted custody is used.

## CLI commands

The CLI follows the existing adapter pattern used by `freebird import-check` /
`freebird present-check`, `witness import` / `witness present`, and
`matchlock import-artifact` / `matchlock present-artifact`.

### Import

```bash
cargo run -p cred-cli -- --store ./tmp/cred-store social_graph import-attestation examples/social-graph-attestation.json \
  --record-id record-social-graph-attestation-1 \
  --cred-id cred:local:example
```

`cred social_graph import-attestation <file>` accepts only `sophia/v1`
`social_graph.attestation` artifacts. It canonicalizes and hashes the artifact,
then writes a `cred.artifact_record` for later presentation.

### Present

```bash
cargo run -p cred-cli -- --store ./tmp/cred-store social_graph present-attestation \
  --request examples/social-graph-presentation-request.json \
  --grant examples/social-graph-permission-grant.json \
  --approval-id approval-social-graph-1 \
  --record-id record-social-graph-attestation-1 \
  --presentation-id presentation-social-graph-1 \
  --cred-id cred:local:example \
  --request-binding-hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
  --signing-key ./tmp/cred-store/controller_sk.hex
```

`cred social_graph present-attestation` presents an imported attestation to a
Freebird issuer. It requires a matching action request, a permission grant with
`social_graph.present`, and an approved local grant decision before producing a
signed presentation. The presentation embeds the attestation and includes the
Freebird `request_binding_hash`.

## Permission grant

The adapter capability is `social_graph.present`.

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "cred.permission_grant",
  "grant_id": "grant-social-graph-1",
  "cred_id": "cred:local:example",
  "app_id": "issuer:freebird:example",
  "capabilities": [
    "social_graph.present"
  ],
  "constraints": {
    "allowed_artifact_types": [
      "social_graph.attestation"
    ],
    "allowed_audiences": [
      "issuer:freebird:example"
    ],
    "max_uses": 1,
    "expires_at": 1719000300,
    "allow_export": false
  },
  "human_approval": "per_use",
  "created_at": 1718999600
}
```

Grant enforcement is the standard Cred enforcement path: `app_id`, `grant_id`,
action capabilities, allowed audiences, allowed artifact types, expiry, use
count, export policy, and the latest local approval decision must all match.
Social graph grants should normally be single-use and `human_approval` should be
`"per_use"`.

## Action request

A Freebird issuer or client asks Cred for a social graph presentation with a
`cred.action_request`:

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "cred.action_request",
  "request_id": "request-freebird-issue-1",
  "app_id": "issuer:freebird:example",
  "grant_id": "grant-social-graph-1",
  "requested_at": 1718999701,
  "purpose": "present a social graph eligibility attestation for Freebird issuance",
  "actions": [
    {
      "kind": "social_graph.present",
      "audience": "issuer:freebird:example",
      "semantic": "not_used",
      "artifact_type": "social_graph.attestation"
    }
  ]
}
```

The request binding itself is not placed in the action request unless a future
schema revision adds a dedicated field. The presentation command receives or
derives `request_binding_hash` and includes only the hash in the presentation.

## Presentation

The response is a `cred.presentation` containing one embedded
`social_graph.attestation`, a `request_binding_hash`, and a
`presentation_signature`.

`presentation_signature` is the Cred controller's Ed25519 signature over the
canonical JSON form of the presentation with `presentation_signature` omitted.
This binds the imported attestation to the specific Freebird `app_id`,
`request_id`, `grant_id`, and request binding hash.

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "cred.presentation",
  "presentation_id": "presentation-social-graph-1",
  "cred_id": "cred:local:example",
  "request_id": "request-freebird-issue-1",
  "grant_id": "grant-social-graph-1",
  "app_id": "issuer:freebird:example",
  "created_at": 1718999800,
  "artifacts": [
    {
      "artifact_type": "social_graph.attestation",
      "artifact_hash": "dfd3f3fe66c16b95124e9e10c15a7c9321ed3b75d0d79dc0d2e2b47dcbbdc507",
      "record_id": "record-social-graph-attestation-1",
      "disclosure": "embedded",
      "artifact": {
        "contract_version": "sophia/v1",
        "artifact_type": "social_graph.attestation",
        "version": "1",
        "attester_id": "attester:example:v1",
        "kid": "attester-key-2026-06",
        "policy_id": "clout-trust-v1",
        "issued_at": 1718999700,
        "expires_at": 1719000000,
        "eligibility_level": 2,
        "quota_nullifier": "9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7",
        "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "holder_commitment": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "signature": "9b4f1c2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
      }
    }
  ],
  "request_binding_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "presentation_signature": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
}
```

The client submits the complete presentation JSON as
`SybilProof::SocialGraph.attestation` and the `presentation_signature` hex value
as `SybilProof::SocialGraph.presentation`.

## Example artifacts

### Imported attestation

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "social_graph.attestation",
  "version": "1",
  "attester_id": "attester:example:v1",
  "kid": "attester-key-2026-06",
  "policy_id": "clout-trust-v1",
  "issued_at": 1718999700,
  "expires_at": 1719000000,
  "eligibility_level": 2,
  "quota_nullifier": "9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7",
  "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "holder_commitment": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "signature": "9b4f1c2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
}
```

### Artifact record

```json
{
  "contract_version": "sophia/v1",
  "artifact_type": "cred.artifact_record",
  "record_id": "record-social-graph-attestation-1",
  "cred_id": "cred:local:example",
  "stored_artifact_type": "social_graph.attestation",
  "artifact_hash": "dfd3f3fe66c16b95124e9e10c15a7c9321ed3b75d0d79dc0d2e2b47dcbbdc507",
  "privacy": "selective",
  "custody": "local_encrypted",
  "source_app": "attester:example:v1",
  "created_at": 1718999702,
  "labels": [
    "social_graph",
    "clout-trust-v1"
  ]
}
```

The grant, action request, and presentation examples above are the canonical
adapter examples for authorization and disclosure.

## Privacy properties

Cred learns and stores the imported attestation, including the attester id,
policy id, coarse eligibility level, expiry, optional quota nullifier, and holder
commitment. Cred does not need raw Clout graph data, trust edges, invitation
chains, wallet history, exact scores, ballot history, rendezvous data, or
Freebird redemption context.

The Social Graph Attester learns that a Cred controller requested eligibility
and may learn submitted graph evidence, but it does not learn which Freebird
issuer will receive the attestation, the Freebird request binding, when the
attestation is used, or whether it is used at all.

The Freebird issuer learns only what is in the Cred presentation: the signed
attestation, coarse eligibility level, policy id, expiry, request binding hash,
and optional quota nullifier. It must not receive raw graph evidence or exact
social graph scores.

Per-use approval is mandatory for normal social graph presentation grants. A
grant with `human_approval: "per_use"` plus `max_uses: 1` ensures Cred asks the
user before each disclosure and records a metadata-only presentation audit after
successful presentation.
