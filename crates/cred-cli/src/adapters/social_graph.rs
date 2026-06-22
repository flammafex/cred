use crate::commands::*;
use crate::grant::read_grant_with_hash;
use crate::presentation::{enforce_presentation_grant, read_action_request, require_approved_grant};
use crate::record::{artifact_uri_for_custody, store_record_with_optional_artifact};
use crate::util::{ensure_lower_hex, now_unix, print_json, read_json, read_record_artifact, read_secret_key, record_store};
use anyhow::{bail, ensure, Context, Result};
use cred_core::{artifact_record, canonical_hash_hex, sign_presentation, verify_presentation_signature, CredPresentation, GrantUsage, PresentedArtifact};
use cred_store::PresentationAuditEntry;
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn social_graph(command: SocialGraphCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        SocialGraphCommand::ImportAttestation(command) => {
            social_graph_import_attestation(command, store_path)
        }
        SocialGraphCommand::PresentAttestation(command) => {
            social_graph_present_attestation(command, store_path)
        }
    }
}

pub(crate) fn social_graph_import_attestation(
    command: SocialGraphImportAttestationCommand,
    store_path: Option<PathBuf>,
) -> Result<()> {
    let value = read_json(&command.attestation)?;
    ensure_social_graph_attestation(&value)?;
    let artifact_hash = canonical_hash_hex(&value)?;
    let artifact_uri = artifact_uri_for_custody(
        &command.custody,
        command.artifact_uri,
        &command.record_id,
        &command.attestation,
    )?;
    let object = value.as_object().expect("validated JSON object");
    let source_app = object
        .get("attester_id")
        .and_then(Value::as_str)
        .context("social_graph.attestation missing attester_id")?
        .to_owned();
    let policy_id = object
        .get("policy_id")
        .and_then(Value::as_str)
        .context("social_graph.attestation missing policy_id")?
        .to_owned();
    let mut labels = command.labels;
    if !labels.iter().any(|label| label == "social_graph") {
        labels.push("social_graph".to_owned());
    }
    if !labels.iter().any(|label| label == &policy_id) {
        labels.push(policy_id);
    }
    let vault_passphrase = command.vault_passphrase;
    let record = artifact_record(
        command.record_id,
        command.cred_id,
        "social_graph.attestation".to_owned(),
        artifact_hash,
        artifact_uri,
        command.privacy,
        command.custody,
        Some(source_app),
        now_unix()?,
        Some(labels),
    );
    store_record_with_optional_artifact(record, &value, vault_passphrase.as_deref(), store_path)
}

pub(crate) fn social_graph_present_attestation(
    command: SocialGraphPresentAttestationCommand,
    store_path: Option<PathBuf>,
) -> Result<()> {
    ensure_lower_hex(&command.request_binding_hash, "request_binding_hash", 32)?;
    let store = record_store(store_path.clone())?;
    let Some(record) = store.get_record(&command.record_id)? else {
        bail!("record not found: {}", command.record_id);
    };
    ensure!(
        record.cred_id == command.cred_id,
        "record cred_id does not match presentation cred_id"
    );
    ensure!(
        record.stored_artifact_type == "social_graph.attestation",
        "record is not a social_graph.attestation: {}",
        record.stored_artifact_type
    );
    let attestation = read_record_artifact(&store, &record, command.vault_passphrase.as_deref())?;
    ensure_social_graph_attestation(&attestation)?;
    ensure!(
        canonical_hash_hex(&attestation)? == record.artifact_hash,
        "stored attestation hash does not match record"
    );
    let request = read_action_request(&command.request)?;
    let (grant, grant_hash) = read_grant_with_hash(&command.grant)?;
    require_approved_grant(
        store_path.clone(),
        &grant,
        &grant_hash,
        Some(&command.approval_id),
    )?;
    let now = command.now.unwrap_or(now_unix()?);
    let uses_so_far = store.count_presentations_for_grant(&grant.grant_id)?;
    enforce_presentation_grant(
        &grant,
        &request,
        &command.cred_id,
        "social_graph.attestation",
        GrantUsage {
            now,
            uses_so_far,
        },
    )
    .context("permission grant denied social graph presentation")?;

    let presentation = CredPresentation {
        contract_version: "sophia/v1".to_owned(),
        artifact_type: "cred.presentation".to_owned(),
        presentation_id: command.presentation_id,
        cred_id: command.cred_id,
        request_id: request.request_id,
        grant_id: Some(grant.grant_id),
        app_id: request.app_id,
        created_at: now_unix()?,
        artifacts: vec![PresentedArtifact {
            artifact_type: "social_graph.attestation".to_owned(),
            artifact_hash: record.artifact_hash,
            record_id: Some(record.record_id),
            disclosure: "embedded".to_owned(),
            artifact: Some(attestation),
        }],
        request_binding_hash: Some(command.request_binding_hash),
        cred_signature: None,
    };
    let secret_key_hex = read_secret_key(&command.signing_key)?;
    let presentation = sign_presentation(presentation, &secret_key_hex)?;
    verify_presentation_signature(&presentation)?;

    let presentation_value = serde_json::to_value(&presentation)?;
    let presentation_hash = canonical_hash_hex(&presentation_value)?;
    let audit = PresentationAuditEntry::from_presentation(&presentation, presentation_hash, None);
    store.append_presentation_audit(&audit)?;

    print_json(&presentation)
}

pub(crate) fn ensure_social_graph_attestation(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("social_graph.attestation must be a JSON object")?;
    ensure!(
        object.get("contract_version").and_then(Value::as_str) == Some("sophia/v1"),
        "social_graph.attestation contract_version must be sophia/v1"
    );
    ensure!(
        object.get("artifact_type").and_then(Value::as_str) == Some("social_graph.attestation"),
        "expected artifact_type social_graph.attestation"
    );
    crate::adapters::matchlock::ensure_non_empty_string_field(object, "attester_id")?;
    crate::adapters::matchlock::ensure_non_empty_string_field(object, "policy_id")?;
    Ok(())
}
