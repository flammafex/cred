use crate::commands::*;
use crate::util::{now_unix, print_json, record_store, read_json};
use anyhow::{bail, ensure, Context, Result};
use cred_core::{artifact_record, artifact_type, canonical_hash_hex};
use serde_json::Value;
use cred_store::RecordStore;
use std::path::{Path, PathBuf};

pub(crate) fn record(command: RecordCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        RecordCommand::Add(command) => record_add(command, store_path),
        RecordCommand::List => record_list(store_path),
        RecordCommand::Get(command) => record_get(command, store_path),
        RecordCommand::Reveal(command) => record_reveal(command, store_path),
    }
}

pub(crate) fn record_add(command: RecordAddCommand, store_path: Option<PathBuf>) -> Result<()> {
    let value = read_json(&command.artifact)?;
    let stored_artifact_type = artifact_type(&value)
        .context("artifact must include artifact_type")?
        .to_owned();
    let artifact_hash = canonical_hash_hex(&value)?;
    let artifact_uri = artifact_uri_for_custody(
        &command.custody,
        command.artifact_uri,
        &command.record_id,
        &command.artifact,
    )?;
    let labels = if command.labels.is_empty() {
        None
    } else {
        Some(command.labels)
    };
    let vault_passphrase = command.vault_passphrase;
    let record = artifact_record(
        command.record_id,
        command.cred_id,
        stored_artifact_type,
        artifact_hash,
        artifact_uri,
        command.privacy,
        command.custody,
        command.source_app,
        now_unix()?,
        labels,
    );
    store_record_with_optional_artifact(record, &value, vault_passphrase.as_deref(), store_path)
}

pub(crate) fn store_record_with_optional_artifact(
    record: cred_core::CredArtifactRecord,
    artifact: &Value,
    vault_passphrase: Option<&str>,
    store_path: Option<PathBuf>,
) -> Result<()> {
    record.validate()?;
    let store = record_store(store_path)?;
    if store.get_record(&record.record_id)?.is_some() {
        bail!("record already exists: {}", record.record_id);
    }
    if record.custody == "local_encrypted" {
        let passphrase = vault_passphrase
            .filter(|passphrase| !passphrase.is_empty())
            .context(
                "local_encrypted custody requires --vault-passphrase or CRED_VAULT_PASSPHRASE",
            )?;
        store.write_encrypted_artifact(&record, artifact, passphrase)?;
    }
    store.append_record(&record)?;
    print_json(&record)
}

pub(crate) fn record_list(store_path: Option<PathBuf>) -> Result<()> {
    let records = record_store(store_path)?.list_records()?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.record_list",
        "records": records
    });
    print_json(&summary)
}

pub(crate) fn record_get(command: RecordGetCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path)?;
    let Some(record) = store.get_record(&command.record_id)? else {
        bail!("record not found: {}", command.record_id);
    };
    print_json(&record)
}

pub(crate) fn record_reveal(command: RecordRevealCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path)?;
    let Some(record) = store.get_record(&command.record_id)? else {
        bail!("record not found: {}", command.record_id);
    };
    ensure!(
        record.custody == "local_encrypted",
        "record is not local_encrypted: {}",
        record.custody
    );
    let passphrase = command
        .vault_passphrase
        .as_deref()
        .filter(|passphrase| !passphrase.is_empty())
        .context("record reveal requires --vault-passphrase or CRED_VAULT_PASSPHRASE")?;
    let artifact = store.read_encrypted_artifact(&record, passphrase)?;
    print_json(&artifact)
}
pub(crate) fn artifact_uri_for_custody(
    custody: &str,
    explicit_uri: Option<String>,
    record_id: &str,
    artifact_path: &Path,
) -> Result<Option<String>> {
    if custody == "local_encrypted" {
        let vault_uri = RecordStore::vault_blob_uri(record_id);
        if let Some(explicit_uri) = explicit_uri {
            ensure!(
                explicit_uri == vault_uri,
                "local_encrypted custody uses Cred-managed vault URI: {vault_uri}"
            );
        }
        return Ok(Some(vault_uri));
    }

    if let Some(explicit_uri) = explicit_uri {
        return Ok(Some(explicit_uri));
    }
    if custody == "external_reference" {
        return Ok(Some(artifact_path.display().to_string()));
    }
    Ok(None)
}
