use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Parser, Subcommand};
use cred_core::{
    artifact_record, artifact_type, canonical_hash_hex, enforce_grant, manifest, validate_and_hash,
    CredActionRequest, CredEndpoint, CredPermissionGrant, CredPresentation, GrantUsage,
    PresentedArtifact,
};
use cred_store::RecordStore;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(name = "cred")]
#[command(about = "Cred local proof agent")]
struct Cli {
    #[arg(long, global = true, env = "CRED_STORE_DIR")]
    store: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit a cred.manifest artifact.
    Manifest(ManifestCommand),
    /// Validate and hash a Cred artifact.
    Inspect(ArtifactPath),
    /// Hash any JSON artifact using Cred canonical JSON.
    Hash(ArtifactPath),
    /// Build Cred artifacts from existing JSON.
    Record {
        #[command(subcommand)]
        command: RecordCommand,
    },
    /// Check an action request against a permission grant.
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// Build a cred.presentation from a request and artifact or stored record.
    Present(PresentCommand),
}

#[derive(Debug, Args)]
struct ArtifactPath {
    path: PathBuf,
}

#[derive(Debug, Args)]
struct ManifestCommand {
    #[arg(long)]
    cred_id: String,
    #[arg(long)]
    controller_public_key: String,
    #[arg(long = "capability", required = true)]
    capabilities: Vec<String>,
    #[arg(long, default_value = "stdio")]
    transport: String,
    #[arg(long)]
    endpoint_uri: Option<String>,
}

#[derive(Debug, Subcommand)]
enum RecordCommand {
    /// Store a durable cred.artifact_record for a JSON artifact.
    Add(RecordAddCommand),
    /// List stored cred.artifact_record metadata.
    List,
    /// Get one stored cred.artifact_record by ID.
    Get(RecordGetCommand),
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    /// Check whether a cred.action_request is allowed by a cred.permission_grant.
    Check(GrantCheckCommand),
}

#[derive(Debug, Args)]
struct RecordAddCommand {
    artifact: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long, default_value = "selective")]
    privacy: String,
    #[arg(long, default_value = "local_encrypted")]
    custody: String,
    #[arg(long)]
    source_app: Option<String>,
    #[arg(long = "label")]
    labels: Vec<String>,
}

#[derive(Debug, Args)]
struct RecordGetCommand {
    record_id: String,
}

#[derive(Debug, Args)]
struct PresentCommand {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long)]
    record_id: Option<String>,
    #[arg(long)]
    grant: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    uses_so_far: u64,
    #[arg(long)]
    now: Option<u64>,
    #[arg(long)]
    presentation_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long)]
    disclosure: Option<String>,
}

#[derive(Debug, Args)]
struct GrantCheckCommand {
    #[arg(long)]
    grant: PathBuf,
    #[arg(long)]
    request: PathBuf,
    #[arg(long, default_value_t = 0)]
    uses_so_far: u64,
    #[arg(long)]
    now: Option<u64>,
}

fn main() -> Result<()> {
    let Cli { store, command } = Cli::parse();
    match command {
        Command::Manifest(command) => print_manifest(command),
        Command::Inspect(path) => inspect(path.path),
        Command::Hash(path) => hash(path.path),
        Command::Record { command } => record(command, store),
        Command::Grant {
            command: GrantCommand::Check(command),
        } => grant_check(command),
        Command::Present(command) => present(command, store),
    }
}

fn print_manifest(command: ManifestCommand) -> Result<()> {
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

fn inspect(path: PathBuf) -> Result<()> {
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

fn hash(path: PathBuf) -> Result<()> {
    let value = read_json(&path)?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.hash_result",
        "input_artifact_type": artifact_type(&value).ok(),
        "artifact_hash": canonical_hash_hex(&value)?
    });
    print_json(&summary)
}

fn record(command: RecordCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        RecordCommand::Add(command) => record_add(command, store_path),
        RecordCommand::List => record_list(store_path),
        RecordCommand::Get(command) => record_get(command, store_path),
    }
}

fn record_add(command: RecordAddCommand, store_path: Option<PathBuf>) -> Result<()> {
    let value = read_json(&command.artifact)?;
    let stored_artifact_type = artifact_type(&value)
        .context("artifact must include artifact_type")?
        .to_owned();
    let artifact_hash = canonical_hash_hex(&value)?;
    let labels = if command.labels.is_empty() {
        None
    } else {
        Some(command.labels)
    };
    let record = artifact_record(
        command.record_id,
        command.cred_id,
        stored_artifact_type,
        artifact_hash,
        command.privacy,
        command.custody,
        command.source_app,
        now_unix()?,
        labels,
    );
    record.validate()?;
    record_store(store_path)?.append_record(&record)?;
    print_json(&record)
}

fn record_list(store_path: Option<PathBuf>) -> Result<()> {
    let records = record_store(store_path)?.list_records()?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.record_list",
        "records": records
    });
    print_json(&summary)
}

fn record_get(command: RecordGetCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path)?;
    let Some(record) = store.get_record(&command.record_id)? else {
        bail!("record not found: {}", command.record_id);
    };
    print_json(&record)
}

fn record_store(store_path: Option<PathBuf>) -> Result<RecordStore> {
    let root = match store_path {
        Some(path) => path,
        None => RecordStore::default_root()?,
    };
    Ok(RecordStore::new(root))
}

fn grant_check(command: GrantCheckCommand) -> Result<()> {
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

fn present(command: PresentCommand, store_path: Option<PathBuf>) -> Result<()> {
    let request_value = read_json(&command.request)?;
    let request: CredActionRequest = serde_json::from_value(request_value)
        .context("request must be a cred.action_request artifact")?;
    request.validate()?;

    let source = presentation_source(&command, store_path)?;
    ensure_request_allows_artifact(&request, &source.artifact_type)?;

    if let Some(grant_path) = &command.grant {
        let grant: CredPermissionGrant = serde_json::from_value(read_json(grant_path)?)
            .context("grant must be a cred.permission_grant artifact")?;
        let now = match command.now {
            Some(now) => now,
            None => now_unix()?,
        };
        enforce_presentation_grant(
            &grant,
            &request,
            &command.cred_id,
            &source.artifact_type,
            GrantUsage {
                now,
                uses_so_far: command.uses_so_far,
            },
        )?;
    }

    let presentation = CredPresentation {
        contract_version: "sophia/v1".to_owned(),
        artifact_type: "cred.presentation".to_owned(),
        presentation_id: command.presentation_id,
        cred_id: command.cred_id,
        request_id: request.request_id,
        grant_id: request.grant_id,
        app_id: request.app_id,
        created_at: now_unix()?,
        artifacts: vec![PresentedArtifact {
            artifact_type: source.artifact_type,
            artifact_hash: source.artifact_hash,
            record_id: source.record_id,
            disclosure: source.disclosure,
            artifact: source.artifact,
        }],
        cred_signature: None,
    };
    presentation.validate()?;
    print_json(&presentation)
}

#[derive(Debug)]
struct PresentationSource {
    artifact_type: String,
    artifact_hash: String,
    record_id: Option<String>,
    disclosure: String,
    artifact: Option<Value>,
}

fn presentation_source(
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

fn presentation_source_from_artifact(
    path: &PathBuf,
    disclosure: Option<&str>,
) -> Result<PresentationSource> {
    let artifact = read_json(path)?;
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

fn presentation_source_from_record(
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

fn enforce_presentation_grant(
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

fn ensure_request_allows_artifact(request: &CredActionRequest, artifact_type: &str) -> Result<()> {
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

fn read_json(path: &PathBuf) -> Result<Value> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse JSON {}", path.display()))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cred_core::{artifact_record, CredAction, CredGrantConstraints};

    #[test]
    fn record_backed_presentations_are_references() {
        let source = presentation_source_from_record(sample_record(), None).unwrap();

        assert_eq!(source.artifact_type, "witness.signed_attestation");
        assert_eq!(
            source.artifact_hash,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(source.record_id.as_deref(), Some("record-1"));
        assert_eq!(source.disclosure, "reference");
        assert!(source.artifact.is_none());
    }

    #[test]
    fn record_backed_presentations_reject_embedded_disclosure() {
        let err = presentation_source_from_record(sample_record(), Some("embedded")).unwrap_err();

        assert!(err
            .to_string()
            .contains("record-backed presentations cannot use embedded disclosure"));
    }

    #[test]
    fn presentation_grant_allows_matching_artifact_type() {
        enforce_presentation_grant(
            &sample_grant(Some(vec!["witness.signed_attestation".to_owned()])),
            &sample_request(Some("witness.signed_attestation")),
            "cred:local:test",
            "witness.signed_attestation",
            GrantUsage {
                now: 10,
                uses_so_far: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn presentation_grant_denies_unallowed_presented_artifact_type() {
        let err = enforce_presentation_grant(
            &sample_grant(Some(vec!["cred.presentation".to_owned()])),
            &sample_request(None),
            "cred:local:test",
            "witness.signed_attestation",
            GrantUsage {
                now: 10,
                uses_so_far: 0,
            },
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("permission grant denied presentation"));
    }

    #[test]
    fn request_denies_unrequested_artifact_type() {
        let err = ensure_request_allows_artifact(
            &sample_request(Some("cred.presentation")),
            "witness.signed_attestation",
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("request does not allow presented artifact type"));
    }

    fn sample_record() -> cred_core::CredArtifactRecord {
        artifact_record(
            "record-1".to_owned(),
            "cred:local:test".to_owned(),
            "witness.signed_attestation".to_owned(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            "selective".to_owned(),
            "local_encrypted".to_owned(),
            Some("app:witness:test".to_owned()),
            1,
            Some(vec!["witness".to_owned()]),
        )
    }

    fn sample_request(artifact_type: Option<&str>) -> CredActionRequest {
        CredActionRequest {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.action_request".to_owned(),
            request_id: "request-1".to_owned(),
            app_id: "app:prestige:test".to_owned(),
            grant_id: Some("grant-1".to_owned()),
            requested_at: 1,
            purpose: Some("test presentation".to_owned()),
            actions: vec![CredAction {
                kind: "witness.present_attestation".to_owned(),
                audience: None,
                semantic: None,
                artifact_type: artifact_type.map(str::to_owned),
                hash: None,
                payload_hash: None,
                pool_id: None,
                reason: None,
            }],
        }
    }

    fn sample_grant(allowed_artifact_types: Option<Vec<String>>) -> CredPermissionGrant {
        CredPermissionGrant {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.permission_grant".to_owned(),
            grant_id: "grant-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            app_id: "app:prestige:test".to_owned(),
            app_pubkey: None,
            capabilities: vec!["witness.present_attestation".to_owned()],
            constraints: CredGrantConstraints {
                allowed_audiences: None,
                allowed_artifact_types,
                max_uses: None,
                expires_at: None,
                allow_export: None,
            },
            human_approval: "once".to_owned(),
            created_at: 1,
            cred_signature: None,
        }
    }
}
