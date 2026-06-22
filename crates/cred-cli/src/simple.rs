use crate::commands::*;
use crate::util::{now_unix, print_json, read_json};
use anyhow::{Context, Result};
use cred_core::{artifact_type, canonical_hash_hex, manifest, validate_and_hash, verify_presentation_signature, CredEndpoint, CredPresentation};
use std::path::PathBuf;

pub(crate) fn print_manifest(command: ManifestCommand) -> Result<()> {
    let endpoints = Some(vec![CredEndpoint {
        transport: command.transport,
        uri: command.endpoint_uri,
    }]);
    let artifact = manifest(
        command.cred_id,
        command.controller_public_key,
        command.capabilities,
        now_unix()?,
        endpoints,
    );
    artifact.validate()?;
    print_json(&artifact)
}

pub(crate) fn inspect(path: PathBuf) -> Result<()> {
    let value = read_json(&path)?;
    let (kind, hash) = validate_and_hash(&value)?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.inspect_result",
        "inspected_artifact_type": kind.artifact_type(),
        "artifact_hash": hash
    });
    print_json(&summary)
}

pub(crate) fn hash(path: PathBuf) -> Result<()> {
    let value = read_json(&path)?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.hash_result",
        "input_artifact_type": artifact_type(&value).ok(),
        "artifact_hash": canonical_hash_hex(&value)?
    });
    print_json(&summary)
}

pub(crate) fn verify(path: PathBuf) -> Result<()> {
    let value = read_json(&path)?;
    let presentation: CredPresentation =
        serde_json::from_value(value.clone()).context("artifact must be a cred.presentation")?;
    verify_presentation_signature(&presentation)?;
    let public_key = presentation
        .cred_signature
        .as_ref()
        .expect("verified presentation has signature")
        .public_key
        .clone();
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.verify_result",
        "verified": true,
        "verified_artifact_type": "cred.presentation",
        "artifact_hash": canonical_hash_hex(&value)?,
        "public_key": public_key
    });
    print_json(&summary)
}
