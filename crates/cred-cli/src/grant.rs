use crate::commands::*;
use crate::util::{now_unix, print_json, read_json, record_store};
use anyhow::{bail, Context, Result};
use cred_core::{canonical_hash_hex, enforce_grant, verify_grant_signature, CredActionRequest, CredPermissionGrant, GrantUsage};
use cred_store::{GrantApproval, StoredGrant};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn grant(command: GrantCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        GrantCommand::Review(command) => grant_review(command),
        GrantCommand::Import(command) => grant_import(command, store_path),
        GrantCommand::Approve(command) => grant_decision(command, store_path, "approved"),
        GrantCommand::Deny(command) => grant_decision(command, store_path, "denied"),
        GrantCommand::List => grant_list(store_path),
        GrantCommand::Get(command) => grant_get(command, store_path),
        GrantCommand::Approvals => grant_approvals(store_path),
        GrantCommand::ApprovalGet(command) => grant_approval_get(command, store_path),
        GrantCommand::Check(command) => grant_check(command),
    }
}

pub(crate) fn grant_review(command: GrantReviewCommand) -> Result<()> {
    let (grant, grant_hash) = read_grant_with_hash(&command.grant)?;
    let review = grant_review_value(&grant, grant_hash);
    print_json(&review)
}

pub(crate) fn grant_review_value(grant: &CredPermissionGrant, grant_hash: String) -> Value {
    let summary = grant_review_summary(grant);
    let warnings = grant_review_warnings(grant);
    let grant_signature_status = match &grant.cred_signature {
        Some(_) => {
            match verify_grant_signature(grant) {
                Ok(()) => "verified",
                Err(_) => "verification_failed",
            }
        }
        None => "unsigned",
    };
    serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.grant_review",
        "grant_id": grant.grant_id,
        "grant_hash": grant_hash,
        "cred_id": grant.cred_id,
        "app_id": grant.app_id,
        "app_pubkey": grant.app_pubkey,
        "capabilities": grant.capabilities,
        "constraints": grant.constraints,
        "human_approval": grant.human_approval,
        "created_at": grant.created_at,
        "grant_signature_status": grant_signature_status,
        "summary": summary,
        "warnings": warnings
    })
}

pub(crate) fn grant_import(command: GrantImportCommand, store_path: Option<PathBuf>) -> Result<()> {
    let (grant, grant_hash) = read_grant_with_hash(&command.grant)?;
    let source_uri = command
        .source_uri
        .or_else(|| Some(command.grant.display().to_string()));
    let stored = import_grant(&grant, grant_hash, source_uri, store_path)?;
    print_json(&stored)
}

pub(crate) fn import_grant(
    grant: &CredPermissionGrant,
    grant_hash: String,
    source_uri: Option<String>,
    store_path: Option<PathBuf>,
) -> Result<StoredGrant> {
    let stored = StoredGrant::from_grant(grant, grant_hash, source_uri, now_unix()?);
    let store = record_store(store_path)?;
    store.append_grant(&stored)?;
    Ok(stored)
}

pub(crate) fn grant_decision(
    command: GrantDecisionCommand,
    store_path: Option<PathBuf>,
    decision: &'static str,
) -> Result<()> {
    let (grant, grant_hash) = read_grant_with_hash(&command.grant)?;
    let source_uri = command
        .source_uri
        .or_else(|| Some(command.grant.display().to_string()));
    let approval = decide_grant(
        &grant,
        grant_hash,
        decision,
        command.approval_id,
        command.reviewer,
        command.note,
        source_uri,
        store_path,
    );
    let approval = approval?;
    print_json(&approval)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_grant(
    grant: &CredPermissionGrant,
    grant_hash: String,
    decision: &'static str,
    approval_id: String,
    reviewer: Option<String>,
    note: Option<String>,
    source_uri: Option<String>,
    store_path: Option<PathBuf>,
) -> Result<GrantApproval> {
    let approval = GrantApproval::from_grant(
        grant,
        grant_hash,
        decision.to_owned(),
        approval_id,
        grant_review_summary(grant),
        grant_review_warnings(grant),
        reviewer,
        note,
        source_uri,
        now_unix()?,
    );
    let store = record_store(store_path)?;
    store.append_grant_approval(&approval)?;
    Ok(approval)
}

pub(crate) fn grant_list(store_path: Option<PathBuf>) -> Result<()> {
    let grants = record_store(store_path)?.list_grants()?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.grant_list",
        "grants": grants
    });
    print_json(&summary)
}

pub(crate) fn grant_approvals(store_path: Option<PathBuf>) -> Result<()> {
    let approvals = record_store(store_path)?.list_grant_approvals()?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.grant_approval_list",
        "approvals": approvals
    });
    print_json(&summary)
}

pub(crate) fn grant_approval_get(command: GrantApprovalGetCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path)?;
    let Some(approval) = store.get_grant_approval(&command.approval_id)? else {
        bail!("grant approval not found: {}", command.approval_id);
    };
    print_json(&approval)
}

pub(crate) fn grant_get(command: GrantGetCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path)?;
    let Some(grant) = store.get_grant(&command.grant_id)? else {
        bail!("grant not found: {}", command.grant_id);
    };
    print_json(&grant)
}

pub(crate) fn read_grant_with_hash(path: &PathBuf) -> Result<(CredPermissionGrant, String)> {
    let value = read_json(path)?;
    parse_grant_with_hash(value)
}

pub(crate) fn parse_grant_with_hash(value: Value) -> Result<(CredPermissionGrant, String)> {
    let grant: CredPermissionGrant =
        serde_json::from_value(value.clone()).context("grant must be a cred.permission_grant")?;
    grant.validate()?;
    verify_grant_signature(&grant)
        .context("grant signature verification failed")?;
    let grant_hash = canonical_hash_hex(&value)?;
    Ok((grant, grant_hash))
}

pub(crate) fn grant_review_summary(grant: &CredPermissionGrant) -> Vec<String> {
    let mut summary = Vec::new();
    summary.push(format!(
        "App {} can request: {}.",
        grant.app_id,
        grant.capabilities.join(", ")
    ));
    if let Some(audiences) = &grant.constraints.allowed_audiences {
        summary.push(format!("Allowed audiences: {}.", audiences.join(", ")));
    }
    if let Some(artifact_types) = &grant.constraints.allowed_artifact_types {
        summary.push(format!(
            "Allowed artifact types: {}.",
            artifact_types.join(", ")
        ));
    }
    match grant.constraints.max_uses {
        Some(max_uses) => summary.push(format!("Maximum uses: {max_uses}.")),
        None => summary.push("No maximum use count is set.".to_owned()),
    }
    match grant.constraints.expires_at {
        Some(expires_at) => summary.push(format!("Expires at Unix time {expires_at}.")),
        None => summary.push("No expiration is set.".to_owned()),
    }
    summary.push(format!(
        "Human approval mode requested by grant: {}.",
        grant.human_approval
    ));
    summary
}

pub(crate) fn grant_review_warnings(grant: &CredPermissionGrant) -> Vec<String> {
    let mut warnings = Vec::new();
    if grant.app_pubkey.is_none() {
        warnings.push("Grant does not bind an app public key.".to_owned());
    }
    if grant.cred_signature.is_none() {
        warnings.push("Grant is unsigned; local approval is the only trust root.".to_owned());
    }
    if grant.constraints.allowed_audiences.is_none() {
        warnings.push("Grant does not restrict audiences.".to_owned());
    }
    if grant.constraints.allowed_artifact_types.is_none() {
        warnings.push("Grant does not restrict artifact types.".to_owned());
    }
    if grant.constraints.max_uses.is_none() {
        warnings.push("Grant has no max_uses limit.".to_owned());
    }
    if grant.constraints.expires_at.is_none() {
        warnings.push("Grant does not expire.".to_owned());
    }
    if grant.constraints.allow_export == Some(true)
        || grant
            .capabilities
            .iter()
            .any(|capability| capability.ends_with(".export"))
    {
        warnings.push("Grant allows export-style capabilities.".to_owned());
    }
    if grant.human_approval == "none" {
        warnings.push("Grant does not request per-use human approval.".to_owned());
    }
    warnings
}

pub(crate) fn grant_check(command: GrantCheckCommand) -> Result<()> {
    let grant: CredPermissionGrant = serde_json::from_value(read_json(&command.grant)?)
        .context("grant must be a cred.permission_grant artifact")?;
    let request: CredActionRequest = serde_json::from_value(read_json(&command.request)?)
        .context("request must be a cred.action_request artifact")?;
    let now = match command.now {
        Some(now) => now,
        None => now_unix()?,
    };

    enforce_grant(
        &grant,
        &request,
        GrantUsage {
            now,
            uses_so_far: command.uses_so_far,
        },
    )?;

    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.grant_check_result",
        "allowed": true,
        "grant_id": grant.grant_id,
        "request_id": request.request_id,
        "app_id": request.app_id
    });
    print_json(&summary)
}
