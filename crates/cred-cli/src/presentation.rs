use crate::commands::PresentCommand;
use crate::grant::read_grant_with_hash;
use crate::util::{now_unix, print_json, read_json, read_secret_key, record_store};
use anyhow::{bail, ensure, Context, Result};
use cred_core::{artifact_type, canonical_hash_hex, enforce_grant, sign_presentation, verify_presentation_signature, CredActionRequest, CredPermissionGrant, CredPresentation, GrantUsage, PresentedArtifact};
use cred_store::{GrantApproval, PresentationAuditEntry};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn present(command: PresentCommand, store_path: Option<PathBuf>) -> Result<()> {
    ensure!(
        command.grant.is_some() || command.approval_id.is_none(),
        "--approval-id requires --grant"
    );
    let request = read_action_request(&command.request)?;
    let source = presentation_source(&command, store_path.clone())?;
    let grant = command
        .grant
        .as_ref()
        .map(read_grant_with_hash)
        .transpose()?;
    let presentation = build_presentation(PresentationBuild {
        request,
        source,
        grant,
        approval_id: command.approval_id,
        signing_key: command.signing_key,
        now: command.now,
        presentation_id: command.presentation_id,
        cred_id: command.cred_id,
        store_path,
    })?;
    print_json(&presentation)
}

pub(crate) struct PresentationBuild {
    pub(crate) request: CredActionRequest,
    pub(crate) source: PresentationSource,
    pub(crate) grant: Option<(CredPermissionGrant, String)>,
    pub(crate) approval_id: Option<String>,
    pub(crate) signing_key: Option<PathBuf>,
    pub(crate) now: Option<u64>,
    pub(crate) presentation_id: String,
    pub(crate) cred_id: String,
    pub(crate) store_path: Option<PathBuf>,
}

pub(crate) fn build_presentation(input: PresentationBuild) -> Result<CredPresentation> {
    ensure!(
        input.grant.is_some() || input.approval_id.is_none(),
        "--approval-id requires --grant"
    );
    ensure_request_allows_artifact(&input.request, &input.source.artifact_type)?;
    let mut approval_id = None;

    if let Some((grant, grant_hash)) = &input.grant {
        let approval = require_approved_grant(
            input.store_path.clone(),
            grant,
            grant_hash,
            input.approval_id.as_deref(),
        )?;
        approval_id = Some(approval.approval_id);
        let now = match input.now {
            Some(now) => now,
            None => now_unix()?,
        };
        let store = record_store(input.store_path.clone())?;
        let uses_so_far = store.count_presentations_for_grant(&grant.grant_id)?;
        enforce_presentation_grant(
            grant,
            &input.request,
            &input.cred_id,
            &input.source.artifact_type,
            GrantUsage {
                now,
                uses_so_far,
            },
        )?;
    }

    let mut presentation = CredPresentation {
        contract_version: "sophia/v1".to_owned(),
        artifact_type: "cred.presentation".to_owned(),
        presentation_id: input.presentation_id,
        cred_id: input.cred_id,
        request_id: input.request.request_id,
        grant_id: input.request.grant_id,
        app_id: input.request.app_id,
        created_at: now_unix()?,
        artifacts: vec![PresentedArtifact {
            artifact_type: input.source.artifact_type,
            artifact_hash: input.source.artifact_hash,
            record_id: input.source.record_id,
            disclosure: input.source.disclosure,
            artifact: input.source.artifact,
        }],
        request_binding_hash: None,
        cred_signature: None,
    };
    presentation.validate()?;
    if let Some(signing_key) = input.signing_key {
        let secret_key = read_secret_key(&signing_key)?;
        presentation = sign_presentation(presentation, &secret_key)?;
        verify_presentation_signature(&presentation)?;
    }
    let presentation_value = serde_json::to_value(&presentation)?;
    let presentation_hash = canonical_hash_hex(&presentation_value)?;
    let audit =
        PresentationAuditEntry::from_presentation(&presentation, presentation_hash, approval_id);
    record_store(input.store_path)?.append_presentation_audit(&audit)?;
    Ok(presentation)
}

pub(crate) fn require_approved_grant(
    store_path: Option<PathBuf>,
    grant: &CredPermissionGrant,
    grant_hash: &str,
    approval_id: Option<&str>,
) -> Result<GrantApproval> {
    let store = record_store(store_path)?;
    let approvals = store.list_grant_approvals()?;
    let approval = match approval_id {
        Some(approval_id) => approvals
            .iter()
            .find(|approval| approval.approval_id == approval_id)
            .cloned()
            .with_context(|| format!("grant approval not found: {approval_id}"))?,
        None => approvals
            .iter()
            .rev()
            .find(|approval| approval.grant_hash == grant_hash)
            .cloned()
            .context(
                "permission grant has no local approval record; run cred grant review and cred grant approve first",
            )?,
    };

    ensure!(
        approval.grant_hash == grant_hash,
        "grant approval does not match current grant hash"
    );
    ensure!(
        approval.grant_id == grant.grant_id
            && approval.cred_id == grant.cred_id
            && approval.app_id == grant.app_id,
        "grant approval metadata does not match current grant"
    );
    let latest_decision = approvals
        .iter()
        .rev()
        .find(|candidate| candidate.grant_hash == grant_hash)
        .context(
            "permission grant has no local approval record; run cred grant review and cred grant approve first",
        )?;
    ensure!(
        latest_decision.decision == "approved",
        "permission grant was not approved: {}",
        latest_decision.decision
    );
    ensure!(
        approval.decision == "approved",
        "pinned grant approval was not approved: {}",
        approval.decision
    );

    Ok(approval)
}

#[derive(Debug, Clone)]
pub(crate) struct PresentationSource {
    pub(crate) artifact_type: String,
    pub(crate) artifact_hash: String,
    pub(crate) record_id: Option<String>,
    pub(crate) disclosure: String,
    pub(crate) artifact: Option<Value>,
}

pub(crate) fn presentation_source(
    command: &PresentCommand,
    store_path: Option<PathBuf>,
) -> Result<PresentationSource> {
    match (&command.artifact, &command.record_id) {
        (Some(_), Some(_)) => bail!("pass either --artifact or --record-id, not both"),
        (None, None) => bail!("pass either --artifact or --record-id"),
        (Some(path), None) => {
            presentation_source_from_artifact(path, command.disclosure.as_deref())
        }
        (None, Some(record_id)) => {
            let store = record_store(store_path)?;
            let Some(record) = store.get_record(record_id)? else {
                bail!("record not found: {record_id}");
            };
            ensure!(
                record.cred_id == command.cred_id,
                "record cred_id does not match presentation cred_id"
            );
            presentation_source_from_record(record, command.disclosure.as_deref())
        }
    }
}

pub(crate) fn presentation_source_from_artifact(
    path: &PathBuf,
    disclosure: Option<&str>,
) -> Result<PresentationSource> {
    let artifact = read_json(path)?;
    presentation_source_from_value(artifact, disclosure)
}

pub(crate) fn presentation_source_from_value(
    artifact: Value,
    disclosure: Option<&str>,
) -> Result<PresentationSource> {
    let artifact_type = artifact_type(&artifact)
        .context("presented artifact must include artifact_type")?
        .to_owned();
    let artifact_hash = canonical_hash_hex(&artifact)?;
    let disclosure = disclosure.unwrap_or("embedded").to_owned();
    let embedded = if disclosure == "embedded" {
        Some(artifact)
    } else {
        None
    };
    if disclosure == "reference" {
        bail!("reference disclosure requires --record-id");
    }

    Ok(PresentationSource {
        artifact_type,
        artifact_hash,
        record_id: None,
        disclosure,
        artifact: embedded,
    })
}

pub(crate) fn presentation_source_from_record(
    record: cred_core::CredArtifactRecord,
    disclosure: Option<&str>,
) -> Result<PresentationSource> {
    let disclosure = disclosure.unwrap_or("reference").to_owned();
    ensure!(
        disclosure != "embedded",
        "record-backed presentations cannot use embedded disclosure"
    );

    Ok(PresentationSource {
        artifact_type: record.stored_artifact_type,
        artifact_hash: record.artifact_hash,
        record_id: Some(record.record_id),
        disclosure,
        artifact: None,
    })
}

pub(crate) fn enforce_presentation_grant(
    grant: &CredPermissionGrant,
    request: &CredActionRequest,
    cred_id: &str,
    artifact_type: &str,
    usage: GrantUsage,
) -> Result<()> {
    ensure!(
        grant.cred_id == cred_id,
        "permission grant cred_id does not match presentation cred_id"
    );
    enforce_grant(grant, request, usage).context("permission grant denied presentation")?;
    if let Some(allowed_artifact_types) = &grant.constraints.allowed_artifact_types {
        ensure!(
            allowed_artifact_types
                .iter()
                .any(|allowed| allowed == artifact_type),
            "permission grant denied presentation: artifact type is not allowed: {artifact_type}"
        );
    }
    Ok(())
}

pub(crate) fn ensure_request_allows_artifact(request: &CredActionRequest, artifact_type: &str) -> Result<()> {
    let requested_types: Vec<_> = request
        .actions
        .iter()
        .filter_map(|action| action.artifact_type.as_deref())
        .collect();
    if !requested_types.is_empty() {
        ensure!(
            requested_types
                .iter()
                .any(|requested| requested == &artifact_type),
            "request does not allow presented artifact type: {artifact_type}"
        );
    }

    Ok(())
}

pub(crate) fn read_action_request(path: &PathBuf) -> Result<CredActionRequest> {
    parse_action_request(read_json(path)?)
}

pub(crate) fn parse_action_request(value: Value) -> Result<CredActionRequest> {
    let request: CredActionRequest =
        serde_json::from_value(value).context("request must be a cred.action_request artifact")?;
    request.validate()?;
    Ok(request)
}
