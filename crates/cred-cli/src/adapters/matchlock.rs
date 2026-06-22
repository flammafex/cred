use crate::commands::*;
use crate::presentation::present;
use crate::record::{artifact_uri_for_custody, store_record_with_optional_artifact};
use crate::util::{now_unix, read_json, record_store};
use anyhow::{bail, ensure, Context, Result};
use cred_core::{artifact_record, artifact_type, canonical_hash_hex};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn matchlock(command: MatchlockCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        MatchlockCommand::ImportArtifact(command) => matchlock_import_artifact(command, store_path),
        MatchlockCommand::PresentArtifact(command) => {
            matchlock_present_artifact(command, store_path)
        }
    }
}

pub(crate) fn matchlock_import_artifact(
    command: MatchlockImportArtifactCommand,
    store_path: Option<PathBuf>,
) -> Result<()> {
    let value = read_json(&command.artifact)?;
    ensure_matchlock_presentation_safe_artifact(&value)?;
    let stored_artifact_type = artifact_type(&value)?.to_owned();
    let artifact_hash = canonical_hash_hex(&value)?;
    let artifact_uri = artifact_uri_for_custody(
        &command.custody,
        command.artifact_uri,
        &command.record_id,
        &command.artifact,
    )?;
    let mut labels = command.labels;
    if !labels.iter().any(|label| label == "matchlock") {
        labels.push("matchlock".to_owned());
    }
    let vault_passphrase = command.vault_passphrase;
    let record = artifact_record(
        command.record_id,
        command.cred_id,
        stored_artifact_type,
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

pub(crate) fn matchlock_present_artifact(
    command: MatchlockPresentArtifactCommand,
    store_path: Option<PathBuf>,
) -> Result<()> {
    let store = record_store(store_path.clone())?;
    let Some(record) = store.get_record(&command.record_id)? else {
        bail!("record not found: {}", command.record_id);
    };
    ensure_matchlock_safe_artifact_type(&record.stored_artifact_type)?;

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

pub(crate) fn ensure_matchlock_presentation_safe_artifact(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("Matchlock artifact must be a JSON object")?;
    ensure!(
        object.get("contract_version").and_then(Value::as_str) == Some("sophia/v1"),
        "Matchlock artifact contract_version must be sophia/v1"
    );
    let artifact_type = object
        .get("artifact_type")
        .and_then(Value::as_str)
        .context("Matchlock artifact missing artifact_type")?;
    ensure_matchlock_safe_artifact_type(artifact_type)?;

    match artifact_type {
        "matchlock.participant_public_key" => {
            ensure_only_fields(
                object,
                &[
                    "contract_version",
                    "artifact_type",
                    "pool_id",
                    "participant_public_key",
                    "signing_public_key",
                ],
            )?;
            ensure_non_empty_string_field(object, "pool_id")?;
            ensure_lower_hex_field(object, "participant_public_key", 32)?;
            ensure_optional_lower_hex_field(object, "signing_public_key", 32)?;
        }
        "matchlock.commitment" => {
            ensure_only_fields(
                object,
                &[
                    "contract_version",
                    "artifact_type",
                    "pool_id",
                    "commitment",
                    "hashes_raw_token_bytes",
                ],
            )?;
            ensure_non_empty_string_field(object, "pool_id")?;
            ensure_lower_hex_field(object, "commitment", 32)?;
            if let Some(value) = object.get("hashes_raw_token_bytes") {
                ensure!(
                    value.as_bool() == Some(true),
                    "matchlock.commitment hashes_raw_token_bytes must be true"
                );
            }
        }
        "matchlock.nullifier" => {
            ensure_only_fields(
                object,
                &[
                    "contract_version",
                    "artifact_type",
                    "pool_id",
                    "nullifier",
                    "domain",
                ],
            )?;
            ensure_non_empty_string_field(object, "pool_id")?;
            ensure_lower_hex_field(object, "nullifier", 32)?;
            ensure_optional_const_string_field(object, "domain", "matchlock-nullifier-v1")?;
        }
        "matchlock.psi_setup"
        | "matchlock.psi_request"
        | "matchlock.psi_response"
        | "matchlock.encrypted_owner_key" => {
            ensure_only_fields(
                object,
                &[
                    "contract_version",
                    "artifact_type",
                    "pool_id",
                    "payload_b64",
                    "owner_public_key",
                    "signature",
                ],
            )?;
            ensure_non_empty_string_field(object, "pool_id")?;
            ensure_base64_field(object, "payload_b64")?;
            ensure_optional_lower_hex_field(object, "owner_public_key", 32)?;
            ensure_optional_lower_hex_field(object, "signature", 64)?;
        }
        _ => unreachable!("artifact type already checked"),
    }

    Ok(())
}

pub(crate) fn ensure_matchlock_safe_artifact_type(artifact_type: &str) -> Result<()> {
    match artifact_type {
        "matchlock.participant_public_key"
        | "matchlock.commitment"
        | "matchlock.nullifier"
        | "matchlock.psi_setup"
        | "matchlock.psi_request"
        | "matchlock.psi_response"
        | "matchlock.encrypted_owner_key" => Ok(()),
        "matchlock.match_token" => {
            bail!("Cred Matchlock adapter rejects raw matchlock.match_token durable records; import a commitment, nullifier, public key, or PSI envelope instead")
        }
        other => bail!("unsupported presentation-safe Matchlock artifact_type: {other}"),
    }
}

pub(crate) fn ensure_only_fields(
    object: &serde_json::Map<String, Value>,
    allowed_fields: &[&str],
) -> Result<()> {
    for field in object.keys() {
        ensure!(
            allowed_fields.iter().any(|allowed| allowed == field),
            "unexpected Matchlock artifact field: {field}"
        );
    }
    Ok(())
}

pub(crate) fn string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Matchlock artifact missing or invalid {field}"))
}

pub(crate) fn ensure_non_empty_string_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<()> {
    ensure!(
        !string_field(object, field)?.is_empty(),
        "Matchlock artifact {field} must be non-empty"
    );
    Ok(())
}

pub(crate) fn ensure_optional_const_string_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    expected: &'static str,
) -> Result<()> {
    if let Some(value) = object.get(field) {
        ensure!(
            value.as_str() == Some(expected),
            "Matchlock artifact {field} must be {expected}"
        );
    }
    Ok(())
}

pub(crate) fn ensure_lower_hex_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    expected_bytes: usize,
) -> Result<()> {
    ensure_lower_hex_value(string_field(object, field)?, field, expected_bytes)
}

pub(crate) fn ensure_optional_lower_hex_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    expected_bytes: usize,
) -> Result<()> {
    if let Some(value) = object.get(field) {
        let value = value
            .as_str()
            .with_context(|| format!("Matchlock artifact {field} must be a string"))?;
        ensure_lower_hex_value(value, field, expected_bytes)?;
    }
    Ok(())
}

pub(crate) fn ensure_lower_hex_value(value: &str, field: &'static str, expected_bytes: usize) -> Result<()> {
    ensure!(
        value.len() == expected_bytes * 2
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !value.bytes().any(|byte| byte.is_ascii_uppercase()),
        "Matchlock artifact {field} must be lowercase hex for exactly {expected_bytes} bytes"
    );
    Ok(())
}

pub(crate) fn ensure_base64_field(object: &serde_json::Map<String, Value>, field: &'static str) -> Result<()> {
    let value = string_field(object, field)?;
    ensure!(
        !value.is_empty() && value.bytes().all(is_base64_byte),
        "Matchlock artifact {field} must be non-empty base64"
    );
    Ok(())
}

pub(crate) fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
}
