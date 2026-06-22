use crate::commands::*;
use crate::presentation::present;
use crate::record::{artifact_uri_for_custody, store_record_with_optional_artifact};
use crate::util::{now_unix, read_json, record_store};
use anyhow::{bail, ensure, Context, Result};
use cred_core::{artifact_record, canonical_hash_hex};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn witness(command: WitnessCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        WitnessCommand::Import(command) => witness_import(command, store_path),
        WitnessCommand::Present(command) => witness_present(command, store_path),
    }
}

pub(crate) fn witness_import(command: WitnessImportCommand, store_path: Option<PathBuf>) -> Result<()> {
    let value = read_json(&command.attestation)?;
    ensure_witness_signed_attestation(&value)?;
    let artifact_hash = canonical_hash_hex(&value)?;
    let artifact_uri = artifact_uri_for_custody(
        &command.custody,
        command.artifact_uri,
        &command.record_id,
        &command.attestation,
    )?;
    let mut labels = command.labels;
    if !labels.iter().any(|label| label == "witness") {
        labels.push("witness".to_owned());
    }
    let vault_passphrase = command.vault_passphrase;
    let record = artifact_record(
        command.record_id,
        command.cred_id,
        "witness.signed_attestation".to_owned(),
        artifact_hash,
        artifact_uri,
        command.privacy,
        command.custody,
        Some(command.source_app),
        now_unix()?,
        Some(labels),
    );
    store_record_with_optional_artifact(record, &value, vault_passphrase.as_deref(), store_path)
}

pub(crate) fn witness_present(command: WitnessPresentCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path.clone())?;
    let Some(record) = store.get_record(&command.record_id)? else {
        bail!("record not found: {}", command.record_id);
    };
    ensure!(
        record.stored_artifact_type == "witness.signed_attestation",
        "record is not a witness.signed_attestation: {}",
        record.stored_artifact_type
    );

    present(
        PresentCommand {
            request: command.request,
            artifact: None,
            record_id: Some(command.record_id),
            grant: command.grant,
            approval_id: command.approval_id,
            signing_key: command.signing_key,
            now: command.now,
            presentation_id: command.presentation_id,
            cred_id: command.cred_id,
            disclosure: command.disclosure.or_else(|| Some("reference".to_owned())),
        },
        store_path,
    )
}

pub(crate) fn ensure_witness_signed_attestation(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("witness attestation must be a JSON object")?;
    ensure!(
        object.get("contract_version").and_then(Value::as_str) == Some("sophia/v1"),
        "witness attestation contract_version must be sophia/v1"
    );
    ensure!(
        object.get("artifact_type").and_then(Value::as_str) == Some("witness.signed_attestation"),
        "expected artifact_type witness.signed_attestation"
    );
    ensure!(
        object.get("attestation").is_some(),
        "witness.signed_attestation missing attestation"
    );
    ensure!(
        object.get("signatures").is_some(),
        "witness.signed_attestation missing signatures"
    );
    Ok(())
}
