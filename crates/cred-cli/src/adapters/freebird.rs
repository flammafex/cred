use crate::commands::*;
use crate::presentation::present;
use crate::record::{artifact_uri_for_custody, store_record_with_optional_artifact};
use crate::util::{now_unix, read_json, record_store};
use anyhow::{bail, ensure, Context, Result};
use cred_core::{artifact_record, canonical_hash_hex};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn freebird(command: FreebirdCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        FreebirdCommand::ImportCheck(command) => freebird_import_check(command, store_path),
        FreebirdCommand::PresentCheck(command) => freebird_present_check(command, store_path),
    }
}

pub(crate) fn freebird_import_check(
    command: FreebirdImportCheckCommand,
    store_path: Option<PathBuf>,
) -> Result<()> {
    let value = read_json(&command.check_request)?;
    ensure_freebird_check_request(&value)?;
    let artifact_hash = canonical_hash_hex(&value)?;
    let artifact_uri = artifact_uri_for_custody(
        &command.custody,
        command.artifact_uri,
        &command.record_id,
        &command.check_request,
    )?;
    let mut labels = command.labels;
    if !labels.iter().any(|label| label == "freebird") {
        labels.push("freebird".to_owned());
    }
    if !labels.iter().any(|label| label == "non_consuming") {
        labels.push("non_consuming".to_owned());
    }
    let vault_passphrase = command.vault_passphrase;
    let record = artifact_record(
        command.record_id,
        command.cred_id,
        "freebird.check_request".to_owned(),
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

pub(crate) fn freebird_present_check(
    command: FreebirdPresentCheckCommand,
    store_path: Option<PathBuf>,
) -> Result<()> {
    let store = record_store(store_path.clone())?;
    let Some(record) = store.get_record(&command.record_id)? else {
        bail!("record not found: {}", command.record_id);
    };
    ensure!(
        record.stored_artifact_type == "freebird.check_request",
        "record is not a non-consuming freebird.check_request: {}",
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

pub(crate) fn ensure_freebird_check_request(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("Freebird check request must be a JSON object")?;
    ensure!(
        object.get("contract_version").and_then(Value::as_str) == Some("sophia/v1"),
        "Freebird check request contract_version must be sophia/v1"
    );
    match object.get("artifact_type").and_then(Value::as_str) {
        Some("freebird.check_request") => {}
        Some("freebird.verify_request") => {
            bail!("Cred Freebird adapter is non-consuming and rejects freebird.verify_request")
        }
        Some(other) => bail!("expected artifact_type freebird.check_request, got {other}"),
        None => bail!("missing artifact_type; expected freebird.check_request"),
    }
    let token = object
        .get("token_b64")
        .and_then(Value::as_str)
        .context("freebird.check_request missing token_b64")?;
    ensure!(
        !token.is_empty() && token.bytes().all(is_base64url_byte),
        "freebird.check_request token_b64 must be non-empty base64url"
    );
    Ok(())
}

pub(crate) fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}
