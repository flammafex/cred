# Cred Stdio Service

`cred serve stdio` is the first app-facing Cred transport. It is a local
newline-delimited JSON service over stdin/stdout. It lets an app ask Cred to
review grants, produce presentations, and inspect vault metadata without
shelling out to one CLI command per operation.

It is not a network service. It does not open a port, does not authenticate
remote clients, and does not bypass the same local approval rules used by the
CLI. Grant approval and denial are intentionally not exposed on the stdio
channel — those decisions must be made via the CLI (`cred grant approve` /
`cred grant deny`) so that a stdin-controlling process cannot self-approve
grants.

## Starting The Service

```bash
cargo run -p cred-cli -- --store ./tmp/cred-store serve stdio
```

Each input line is one JSON request. Each output line is one
`cred.service_response`.

## Request Envelope

```json
{"id":"1","method":"cred.service_info","params":{}}
```

Fields:

- `id`: optional JSON value echoed in the response. Use a string or number.
- `method`: required service method name.
- `params`: optional method parameters. Defaults to `{}`.

Blank input lines are ignored. Malformed JSON returns an error response with
`id: null`.

## Response Envelope

Successful response:

```json
{"contract_version":"sophia/v1","artifact_type":"cred.service_response","id":"1","ok":true,"result":{}}
```

Error response:

```json
{"contract_version":"sophia/v1","artifact_type":"cred.service_response","id":"1","ok":false,"error":{"message":"unsupported service method: cred.nope"}}
```

Service errors are returned in-band. The service should keep reading later
requests unless stdin closes or the process itself fails.

## Methods

### `cred.service_info`

Returns the stdio service metadata, store root, supported method list, and
whether presentation signing is enabled by default.

Params: none.

### `cred.vault_inventory`

Returns the same metadata-only inventory as `cred vault inventory`. It does not
decrypt local encrypted blobs.

Params: none.

### `cred.grant_review`

Reviews a supplied `cred.permission_grant` object and returns a
`cred.grant_review` with the canonical grant hash, readable summary lines, and
warnings.

Params:

- `grant`: required `cred.permission_grant` JSON object.

### `cred.grant_import`

Stores a slim `cred.stored_grant` record for a supplied grant.

Params:

- `grant`: required `cred.permission_grant` JSON object.
- `source_uri`: optional source hint stored with the grant summary.

### `cred.grant_approvals`

Lists local approval and denial records.

Params: none.

### `cred.present`

Produces a `cred.presentation`, optionally signs it, and appends a presentation
audit entry.

Params:

- `request`: required `cred.action_request` JSON object.
- `artifact`: optional artifact JSON object to present.
- `record_id`: optional stored record id to present by reference.
- `grant`: optional `cred.permission_grant` JSON object.
- `approval_id`: optional approval id to link in the audit entry.
- `signing_key`: optional filesystem path to an Ed25519 controller secret key.
- `sign`: optional boolean. Defaults to `true`.
- `uses_so_far`: optional grant use count. Defaults to `0`.
- `now`: optional Unix time for grant expiry/use checks.
- `presentation_id`: required presentation id.
- `cred_id`: required Cred id.
- `disclosure`: optional disclosure mode. Defaults to `embedded` for supplied
  artifacts and `reference` for stored records.

Exactly one of `artifact` or `record_id` must be supplied. If `grant` is
supplied, the latest local decision for the exact grant hash must be approved.
`approval_id` can pin the approval record linked into the audit entry, but it
does not override a later denial.

When `sign` is omitted or `true`, Cred signs with `signing_key` if supplied, or
with the store-local `controller_sk.hex`.

## Fixtures

The request fixture is executable against a store with a generated controller
key:

```bash
cargo run -p cred-cli -- --store ./tmp/cred-store key generate
cargo run -p cred-cli -- --store ./tmp/cred-store serve stdio \
  < examples/stdio-service/requests.jsonl
```

The response fixture is illustrative because real responses include runtime
timestamps, store paths, generated public keys, and signatures:

- `examples/stdio-service/requests.jsonl`
- `examples/stdio-service/responses.example.jsonl`

The smoke test `scripts/stdio-service-smoke.sh` runs the request fixture
against a temporary store and validates the live responses.

## Boundaries

The stdio service preserves Cred's narrower role:

- It stores and presents proof-bearing artifacts, but does not become a market
  primitive.
- It can present non-consuming Freebird check artifacts, but does not consume
  Freebird tokens.
- It can present safe Matchlock artifacts, but does not store raw match tokens
  or derive private Matchlock commitments.
- It signs Cred presentations, but the controller key is not a civil identity.
- It records approvals and disclosures as metadata, but does not store raw
  proof material in audit records.
