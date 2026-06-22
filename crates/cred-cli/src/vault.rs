use crate::commands::VaultCommand;
use crate::util::{print_json, record_store};
use anyhow::Result;
use cred_store::{GrantApproval, PresentationAuditEntry, RecordStore, StoredGrant};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(crate) fn vault(command: VaultCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        VaultCommand::Inventory => vault_inventory(store_path),
    }
}

pub(crate) fn vault_inventory(store_path: Option<PathBuf>) -> Result<()> {
    let inventory = vault_inventory_value(store_path)?;
    print_json(&inventory)
}

pub(crate) fn vault_inventory_value(store_path: Option<PathBuf>) -> Result<VaultInventory> {
    let store = record_store(store_path)?;
    let records = store.list_records()?;
    let grants = store.list_grants()?;
    let grant_approvals = store.list_grant_approvals()?;
    let presentations = store.list_presentation_audit()?;
    let mut artifact_types = BTreeMap::new();
    let mut custody = BTreeMap::new();
    let mut privacy = BTreeMap::new();
    let mut grant_apps = BTreeMap::new();
    let mut grant_decisions = BTreeMap::new();
    let mut presentation_apps = BTreeMap::new();
    let mut disclosure_modes = BTreeMap::new();
    let mut holdings = Vec::with_capacity(records.len());
    let mut local_encrypted_present = 0_u64;
    let mut local_encrypted_missing = 0_u64;

    for record in records {
        increment_count(&mut artifact_types, &record.stored_artifact_type);
        increment_count(&mut custody, &record.custody);
        increment_count(&mut privacy, &record.privacy);

        let local_artifact = local_artifact_summary(&store, &record)?;
        if record.custody == "local_encrypted" {
            if local_artifact.present {
                local_encrypted_present += 1;
            } else {
                local_encrypted_missing += 1;
            }
        }

        holdings.push(InventoryHolding {
            record_id: record.record_id,
            cred_id: record.cred_id,
            category: artifact_category(&record.stored_artifact_type).to_owned(),
            stored_artifact_type: record.stored_artifact_type,
            artifact_hash: record.artifact_hash,
            artifact_uri: record.artifact_uri,
            privacy: record.privacy,
            custody: record.custody,
            source_app: record.source_app,
            created_at: record.created_at,
            labels: record.labels.unwrap_or_default(),
            local_artifact,
        });
    }

    for grant in &grants {
        increment_count(&mut grant_apps, &grant.app_id);
    }
    for approval in &grant_approvals {
        increment_count(&mut grant_decisions, &approval.decision);
    }
    for presentation in &presentations {
        increment_count(&mut presentation_apps, &presentation.app_id);
        for artifact in &presentation.artifacts {
            increment_count(&mut disclosure_modes, &artifact.disclosure);
        }
    }

    let inventory = VaultInventory {
        contract_version: "sophia/v1",
        artifact_type: "cred.vault_inventory",
        store_root: store.root().display().to_string(),
        total_records: holdings.len() as u64,
        total_grants: grants.len() as u64,
        total_grant_approvals: grant_approvals.len() as u64,
        total_presentations: presentations.len() as u64,
        artifact_types,
        custody,
        privacy,
        grant_apps,
        grant_decisions,
        presentation_apps,
        disclosure_modes,
        local_encrypted: LocalEncryptedSummary {
            present: local_encrypted_present,
            missing: local_encrypted_missing,
        },
        holdings,
        grants,
        grant_approvals,
        presentations,
    };
    Ok(inventory)
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultInventory {
    contract_version: &'static str,
    artifact_type: &'static str,
    store_root: String,
    total_records: u64,
    total_grants: u64,
    total_grant_approvals: u64,
    total_presentations: u64,
    artifact_types: BTreeMap<String, u64>,
    custody: BTreeMap<String, u64>,
    privacy: BTreeMap<String, u64>,
    grant_apps: BTreeMap<String, u64>,
    grant_decisions: BTreeMap<String, u64>,
    presentation_apps: BTreeMap<String, u64>,
    disclosure_modes: BTreeMap<String, u64>,
    local_encrypted: LocalEncryptedSummary,
    holdings: Vec<InventoryHolding>,
    grants: Vec<StoredGrant>,
    grant_approvals: Vec<GrantApproval>,
    presentations: Vec<PresentationAuditEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct LocalEncryptedSummary {
    present: u64,
    missing: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct InventoryHolding {
    record_id: String,
    cred_id: String,
    category: String,
    stored_artifact_type: String,
    artifact_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_uri: Option<String>,
    privacy: String,
    custody: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_app: Option<String>,
    created_at: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    labels: Vec<String>,
    local_artifact: LocalArtifactSummary,
}

#[derive(Debug, Serialize)]
pub(crate) struct LocalArtifactSummary {
    encrypted: bool,
    present: bool,
    status: String,
}

pub(crate) fn local_artifact_summary(
    store: &RecordStore,
    record: &cred_core::CredArtifactRecord,
) -> Result<LocalArtifactSummary> {
    if record.custody == "local_encrypted" {
        let present = store.encrypted_artifact_exists(record)?;
        return Ok(LocalArtifactSummary {
            encrypted: true,
            present,
            status: if present {
                "local_encrypted_present".to_owned()
            } else {
                "local_encrypted_missing".to_owned()
            },
        });
    }
    if record.custody == "external_reference" {
        return Ok(LocalArtifactSummary {
            encrypted: false,
            present: false,
            status: "external_reference".to_owned(),
        });
    }
    Ok(LocalArtifactSummary {
        encrypted: false,
        present: false,
        status: "metadata_only".to_owned(),
    })
}

pub(crate) fn artifact_category(artifact_type: &str) -> &str {
    artifact_type
        .split_once('.')
        .map_or(artifact_type, |(prefix, _)| prefix)
}

pub(crate) fn increment_count(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.to_owned()).or_insert(0) += 1;
}
