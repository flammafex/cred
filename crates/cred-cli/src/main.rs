use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Parser, Subcommand};
use cred_core::{
    artifact_record, artifact_type, canonical_hash_hex, canonical_json, enforce_grant, manifest,
    public_key_from_secret_hex, sign_presentation, validate_and_hash,
    verify_presentation_signature, CredActionRequest, CredEndpoint, CredPermissionGrant,
    CredPresentation, GrantUsage, PresentedArtifact,
};
use cred_store::{GrantApproval, PresentationAuditEntry, RecordStore, StoredGrant};
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
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
    /// Verify a signed cred.presentation.
    Verify(ArtifactPath),
    /// Manage local controller keys.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Work with Witness artifacts through Cred.
    Witness {
        #[command(subcommand)]
        command: WitnessCommand,
    },
    /// Work with non-consuming Freebird artifacts through Cred.
    Freebird {
        #[command(subcommand)]
        command: FreebirdCommand,
    },
    /// Work with presentation-safe Matchlock artifacts through Cred.
    Matchlock {
        #[command(subcommand)]
        command: MatchlockCommand,
    },
    /// Work with Social Graph attestations through Cred.
    #[command(name = "social_graph")]
    SocialGraph {
        #[command(subcommand)]
        command: SocialGraphCommand,
    },
    /// Build Cred artifacts from existing JSON.
    Record {
        #[command(subcommand)]
        command: RecordCommand,
    },
    /// Inspect local vault holdings without decrypting artifacts.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Check an action request against a permission grant.
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// Build a cred.presentation from a request and artifact or stored record.
    Present(PresentCommand),
    /// Run Cred as a local app-facing service.
    Serve {
        #[command(subcommand)]
        command: ServeCommand,
    },
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
    /// Decrypt and print a local encrypted artifact by record ID.
    Reveal(RecordRevealCommand),
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Summarize local records, custody modes, and encrypted blob presence.
    Inventory,
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    /// Print a human-readable review summary for a cred.permission_grant.
    Review(GrantReviewCommand),
    /// Import a cred.permission_grant into the local store.
    Import(GrantImportCommand),
    /// Approve an exact cred.permission_grant hash.
    Approve(GrantDecisionCommand),
    /// Deny an exact cred.permission_grant hash.
    Deny(GrantDecisionCommand),
    /// List stored permission grants.
    List,
    /// Get one stored permission grant by ID.
    Get(GrantGetCommand),
    /// List local grant approval and denial records.
    Approvals,
    /// Get one local grant approval or denial record by ID.
    ApprovalGet(GrantApprovalGetCommand),
    /// Check whether a cred.action_request is allowed by a cred.permission_grant.
    Check(GrantCheckCommand),
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generate a local Ed25519 controller secret key.
    Generate(KeyGenerateCommand),
    /// Print the public key for a local controller secret key.
    Public(KeyPathCommand),
}

#[derive(Debug, Subcommand)]
enum WitnessCommand {
    /// Import a witness.signed_attestation into Cred records.
    Import(WitnessImportCommand),
    /// Present an imported Witness attestation by reference.
    Present(WitnessPresentCommand),
}

#[derive(Debug, Subcommand)]
enum FreebirdCommand {
    /// Import a freebird.check_request into Cred records.
    ImportCheck(FreebirdImportCheckCommand),
    /// Present an imported non-consuming Freebird check request by reference.
    PresentCheck(FreebirdPresentCheckCommand),
}

#[derive(Debug, Subcommand)]
enum MatchlockCommand {
    /// Import a presentation-safe Matchlock artifact into Cred records.
    ImportArtifact(MatchlockImportArtifactCommand),
    /// Present an imported Matchlock artifact by reference.
    PresentArtifact(MatchlockPresentArtifactCommand),
}

#[derive(Debug, Subcommand)]
enum SocialGraphCommand {
    /// Import a social_graph.attestation into Cred records.
    ImportAttestation(SocialGraphImportAttestationCommand),
    /// Present an imported social_graph.attestation embedded in a signed presentation.
    PresentAttestation(SocialGraphPresentAttestationCommand),
}

#[derive(Debug, Subcommand)]
enum ServeCommand {
    /// Serve newline-delimited JSON requests over stdin/stdout.
    Stdio,
}

#[derive(Debug, Args)]
struct KeyGenerateCommand {
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    secret_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct KeyPathCommand {
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    secret_key: Option<PathBuf>,
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
    #[arg(long, default_value = "external_reference")]
    custody: String,
    #[arg(long)]
    artifact_uri: Option<String>,
    #[arg(long)]
    source_app: Option<String>,
    #[arg(long = "label")]
    labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct WitnessImportCommand {
    attestation: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long, default_value = "selective")]
    privacy: String,
    #[arg(long, default_value = "external_reference")]
    custody: String,
    #[arg(long)]
    artifact_uri: Option<String>,
    #[arg(long, default_value = "app:witness")]
    source_app: String,
    #[arg(long = "label")]
    labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct WitnessPresentCommand {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    grant: Option<PathBuf>,
    #[arg(long)]
    approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
struct FreebirdImportCheckCommand {
    check_request: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long, default_value = "private")]
    privacy: String,
    #[arg(long, default_value = "external_reference")]
    custody: String,
    #[arg(long)]
    artifact_uri: Option<String>,
    #[arg(long, default_value = "app:freebird")]
    source_app: String,
    #[arg(long = "label")]
    labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct FreebirdPresentCheckCommand {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    grant: Option<PathBuf>,
    #[arg(long)]
    approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
struct MatchlockImportArtifactCommand {
    artifact: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long, default_value = "private")]
    privacy: String,
    #[arg(long, default_value = "external_reference")]
    custody: String,
    #[arg(long)]
    artifact_uri: Option<String>,
    #[arg(long, default_value = "app:matchlock")]
    source_app: String,
    #[arg(long = "label")]
    labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct MatchlockPresentArtifactCommand {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    grant: Option<PathBuf>,
    #[arg(long)]
    approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
struct SocialGraphImportAttestationCommand {
    attestation: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long, default_value = "selective")]
    privacy: String,
    #[arg(long, default_value = "local_encrypted")]
    custody: String,
    #[arg(long)]
    artifact_uri: Option<String>,
    #[arg(long = "label")]
    labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct SocialGraphPresentAttestationCommand {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    grant: PathBuf,
    #[arg(long)]
    approval_id: String,
    #[arg(long)]
    record_id: String,
    #[arg(long)]
    presentation_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long)]
    request_binding_hash: String,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: PathBuf,
    #[arg(long)]
    now: Option<u64>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct RecordGetCommand {
    record_id: String,
}

#[derive(Debug, Args)]
struct RecordRevealCommand {
    record_id: String,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
struct GrantReviewCommand {
    grant: PathBuf,
}

#[derive(Debug, Args)]
struct GrantImportCommand {
    grant: PathBuf,
    #[arg(long)]
    source_uri: Option<String>,
}

#[derive(Debug, Args)]
struct GrantDecisionCommand {
    grant: PathBuf,
    #[arg(long)]
    approval_id: String,
    #[arg(long)]
    reviewer: Option<String>,
    #[arg(long)]
    note: Option<String>,
    #[arg(long)]
    source_uri: Option<String>,
}

#[derive(Debug, Args)]
struct GrantGetCommand {
    grant_id: String,
}

#[derive(Debug, Args)]
struct GrantApprovalGetCommand {
    approval_id: String,
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
    #[arg(long)]
    approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
        Command::Verify(path) => verify(path.path),
        Command::Key { command } => key(command, store),
        Command::Witness { command } => witness(command, store),
        Command::Freebird { command } => freebird(command, store),
        Command::Matchlock { command } => matchlock(command, store),
        Command::SocialGraph { command } => social_graph(command, store),
        Command::Record { command } => record(command, store),
        Command::Vault { command } => vault(command, store),
        Command::Grant { command } => grant(command, store),
        Command::Present(command) => present(command, store),
        Command::Serve { command } => serve(command, store),
    }
}

fn serve(command: ServeCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        ServeCommand::Stdio => serve_stdio(store_path),
    }
}

#[derive(Debug, Deserialize)]
struct ServiceRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize)]
struct ServiceGrantParams {
    grant: Value,
    source_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServiceGrantDecisionParams {
    grant: Value,
    approval_id: String,
    reviewer: Option<String>,
    note: Option<String>,
    source_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServicePresentParams {
    request: Value,
    artifact: Option<Value>,
    record_id: Option<String>,
    grant: Option<Value>,
    approval_id: Option<String>,
    signing_key: Option<PathBuf>,
    sign: Option<bool>,
    now: Option<u64>,
    presentation_id: String,
    cred_id: String,
    disclosure: Option<String>,
}

fn serve_stdio(store_path: Option<PathBuf>) -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<ServiceRequest>(&line) {
            Ok(request) => {
                let id = request.id.clone();
                service_response(
                    id,
                    handle_service_request(request, store_path.clone())
                        .context("service method failed"),
                )
            }
            Err(error) => service_response(
                Value::Null,
                Err(anyhow::anyhow!("invalid service request JSON: {error}")),
            ),
        };
        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }

    Ok(())
}

fn service_response(id: Value, result: Result<Value>) -> Value {
    match result {
        Ok(result) => serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "cred.service_response",
            "id": id,
            "ok": true,
            "result": result
        }),
        Err(error) => serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "cred.service_response",
            "id": id,
            "ok": false,
            "error": {
                "message": format!("{error:#}")
            }
        }),
    }
}

fn handle_service_request(request: ServiceRequest, store_path: Option<PathBuf>) -> Result<Value> {
    match request.method.as_str() {
        "cred.service_info" => service_info(store_path),
        "cred.vault_inventory" => to_json_value(vault_inventory_value(store_path)?),
        "cred.grant_review" => service_grant_review(request.params),
        "cred.grant_import" => service_grant_import(request.params, store_path),
        "cred.grant_approve" => service_grant_decision(request.params, store_path, "approved"),
        "cred.grant_deny" => service_grant_decision(request.params, store_path, "denied"),
        "cred.grant_approvals" => {
            let approvals = record_store(store_path)?.list_grant_approvals()?;
            to_json_value(serde_json::json!({
                "contract_version": "sophia/v1",
                "artifact_type": "cred.grant_approval_list",
                "approvals": approvals
            }))
        }
        "cred.present" => service_present(request.params, store_path),
        other => bail!("unsupported service method: {other}"),
    }
}

fn service_info(store_path: Option<PathBuf>) -> Result<Value> {
    let store = record_store(store_path)?;
    Ok(serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.service_info",
        "transport": "stdio",
        "store_root": store.root().display().to_string(),
        "methods": [
            "cred.service_info",
            "cred.vault_inventory",
            "cred.grant_review",
            "cred.grant_import",
            "cred.grant_approve",
            "cred.grant_deny",
            "cred.grant_approvals",
            "cred.present"
        ],
        "presentation_signing_default": true
    }))
}

fn service_grant_review(params: Value) -> Result<Value> {
    let params: ServiceGrantParams = service_params(params)?;
    let (grant, grant_hash) = parse_grant_with_hash(params.grant)?;
    Ok(grant_review_value(&grant, grant_hash))
}

fn service_grant_import(params: Value, store_path: Option<PathBuf>) -> Result<Value> {
    let params: ServiceGrantParams = service_params(params)?;
    let (grant, grant_hash) = parse_grant_with_hash(params.grant)?;
    to_json_value(import_grant(
        &grant,
        grant_hash,
        params.source_uri,
        store_path,
    )?)
}

fn service_grant_decision(
    params: Value,
    store_path: Option<PathBuf>,
    decision: &'static str,
) -> Result<Value> {
    let params: ServiceGrantDecisionParams = service_params(params)?;
    let (grant, grant_hash) = parse_grant_with_hash(params.grant)?;
    to_json_value(decide_grant(
        &grant,
        grant_hash,
        decision,
        params.approval_id,
        params.reviewer,
        params.note,
        params.source_uri,
        store_path,
    )?)
}

fn service_present(params: Value, store_path: Option<PathBuf>) -> Result<Value> {
    let params: ServicePresentParams = service_params(params)?;
    let request = parse_action_request(params.request)?;
    let source = service_presentation_source(
        params.artifact,
        params.record_id,
        &params.cred_id,
        params.disclosure.as_deref(),
        store_path.clone(),
    )?;
    let grant = params.grant.map(parse_grant_with_hash).transpose()?;
    let signing_key = if params.sign.unwrap_or(true) {
        Some(match params.signing_key {
            Some(path) => path,
            None => controller_secret_key_path(None, store_path.clone())?,
        })
    } else {
        None
    };

    to_json_value(build_presentation(PresentationBuild {
        request,
        source,
        grant,
        approval_id: params.approval_id,
        signing_key,
        now: params.now,
        presentation_id: params.presentation_id,
        cred_id: params.cred_id,
        store_path,
    })?)
}

fn service_presentation_source(
    artifact: Option<Value>,
    record_id: Option<String>,
    cred_id: &str,
    disclosure: Option<&str>,
    store_path: Option<PathBuf>,
) -> Result<PresentationSource> {
    match (artifact, record_id) {
        (Some(_), Some(_)) => bail!("params must include either artifact or record_id, not both"),
        (None, None) => bail!("params must include either artifact or record_id"),
        (Some(artifact), None) => presentation_source_from_value(artifact, disclosure),
        (None, Some(record_id)) => {
            let store = record_store(store_path)?;
            let Some(record) = store.get_record(&record_id)? else {
                bail!("record not found: {record_id}");
            };
            ensure!(
                record.cred_id == cred_id,
                "record cred_id does not match presentation cred_id"
            );
            presentation_source_from_record(record, disclosure)
        }
    }
}

fn service_params<T: DeserializeOwned>(params: Value) -> Result<T> {
    serde_json::from_value(params).context("invalid service params")
}

fn to_json_value<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).context("encode service result")
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

fn verify(path: PathBuf) -> Result<()> {
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

fn key(command: KeyCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        KeyCommand::Generate(command) => key_generate(command, store_path),
        KeyCommand::Public(command) => key_public(command, store_path),
    }
}

fn key_generate(command: KeyGenerateCommand, store_path: Option<PathBuf>) -> Result<()> {
    let path = controller_secret_key_path(command.secret_key, store_path)?;
    let secret_key = generate_secret_key_hex()?;
    write_secret_key(&path, &secret_key)?;
    let public_key = public_key_from_secret_hex(&secret_key)?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.key_result",
        "scheme": "ed25519",
        "public_key": public_key,
        "secret_key_path": path
    });
    print_json(&summary)
}

fn key_public(command: KeyPathCommand, store_path: Option<PathBuf>) -> Result<()> {
    let path = controller_secret_key_path(command.secret_key, store_path)?;
    let secret_key = read_secret_key(&path)?;
    let public_key = public_key_from_secret_hex(&secret_key)?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.key_result",
        "scheme": "ed25519",
        "public_key": public_key,
        "secret_key_path": path
    });
    print_json(&summary)
}

fn witness(command: WitnessCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        WitnessCommand::Import(command) => witness_import(command, store_path),
        WitnessCommand::Present(command) => witness_present(command, store_path),
    }
}

fn witness_import(command: WitnessImportCommand, store_path: Option<PathBuf>) -> Result<()> {
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

fn witness_present(command: WitnessPresentCommand, store_path: Option<PathBuf>) -> Result<()> {
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

fn ensure_witness_signed_attestation(value: &Value) -> Result<()> {
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

fn freebird(command: FreebirdCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        FreebirdCommand::ImportCheck(command) => freebird_import_check(command, store_path),
        FreebirdCommand::PresentCheck(command) => freebird_present_check(command, store_path),
    }
}

fn freebird_import_check(
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

fn freebird_present_check(
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

fn ensure_freebird_check_request(value: &Value) -> Result<()> {
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

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn social_graph(command: SocialGraphCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        SocialGraphCommand::ImportAttestation(command) => {
            social_graph_import_attestation(command, store_path)
        }
        SocialGraphCommand::PresentAttestation(command) => {
            social_graph_present_attestation(command, store_path)
        }
    }
}

fn social_graph_import_attestation(
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

fn social_graph_present_attestation(
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
    // Derive uses_so_far from the store rather than trusting a caller-supplied
    // value. Note: social_graph presentations are not yet appended to the
    // audit log (see AGENTS.md risk #3), so this may undercount until that is
    // fixed. It is still more correct than accepting 0 from the caller.
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

    let mut presentation = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.presentation",
        "presentation_id": command.presentation_id,
        "cred_id": command.cred_id,
        "request_id": request.request_id,
        "grant_id": grant.grant_id,
        "app_id": request.app_id,
        "created_at": now_unix()?,
        "artifacts": [{
            "artifact_type": "social_graph.attestation",
            "artifact_hash": record.artifact_hash,
            "record_id": record.record_id,
            "disclosure": "embedded",
            "artifact": attestation
        }],
        "request_binding_hash": command.request_binding_hash
    });
    let secret_key_hex = read_secret_key(&command.signing_key)?;
    let secret_key = hex::decode(secret_key_hex.trim()).context("decode controller secret key")?;
    let secret_key: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller secret key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    let signature = signing_key.sign(&canonical_json(&presentation)?);
    presentation["presentation_signature"] = Value::String(hex::encode(signature.to_bytes()));
    print_json(&presentation)
}

fn ensure_social_graph_attestation(value: &Value) -> Result<()> {
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
    ensure_non_empty_string_field(object, "attester_id")?;
    ensure_non_empty_string_field(object, "policy_id")?;
    Ok(())
}

fn read_record_artifact(
    store: &RecordStore,
    record: &cred_core::CredArtifactRecord,
    vault_passphrase: Option<&str>,
) -> Result<Value> {
    match record.custody.as_str() {
        "local_encrypted" => store
            .read_encrypted_artifact(
                record,
                vault_passphrase.context(
                    "local_encrypted custody requires --vault-passphrase or CRED_VAULT_PASSPHRASE",
                )?,
            )
            .context("read encrypted artifact"),
        "external_reference" => {
            let uri = record
                .artifact_uri
                .as_ref()
                .context("external_reference record missing artifact_uri")?;
            read_json(&PathBuf::from(uri))
        }
        other => bail!("unsupported custody for social graph presentation: {other}"),
    }
}

fn ensure_lower_hex(value: &str, field: &str, expected_bytes: usize) -> Result<()> {
    ensure!(
        value.len() == expected_bytes * 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{field} must be lowercase hex for exactly {expected_bytes} bytes"
    );
    Ok(())
}

fn matchlock(command: MatchlockCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        MatchlockCommand::ImportArtifact(command) => matchlock_import_artifact(command, store_path),
        MatchlockCommand::PresentArtifact(command) => {
            matchlock_present_artifact(command, store_path)
        }
    }
}

fn matchlock_import_artifact(
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

fn matchlock_present_artifact(
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

fn ensure_matchlock_presentation_safe_artifact(value: &Value) -> Result<()> {
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

fn ensure_matchlock_safe_artifact_type(artifact_type: &str) -> Result<()> {
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

fn ensure_only_fields(
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

fn string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Matchlock artifact missing or invalid {field}"))
}

fn ensure_non_empty_string_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<()> {
    ensure!(
        !string_field(object, field)?.is_empty(),
        "Matchlock artifact {field} must be non-empty"
    );
    Ok(())
}

fn ensure_optional_const_string_field(
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

fn ensure_lower_hex_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
    expected_bytes: usize,
) -> Result<()> {
    ensure_lower_hex_value(string_field(object, field)?, field, expected_bytes)
}

fn ensure_optional_lower_hex_field(
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

fn ensure_lower_hex_value(value: &str, field: &'static str, expected_bytes: usize) -> Result<()> {
    ensure!(
        value.len() == expected_bytes * 2
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !value.bytes().any(|byte| byte.is_ascii_uppercase()),
        "Matchlock artifact {field} must be lowercase hex for exactly {expected_bytes} bytes"
    );
    Ok(())
}

fn ensure_base64_field(object: &serde_json::Map<String, Value>, field: &'static str) -> Result<()> {
    let value = string_field(object, field)?;
    ensure!(
        !value.is_empty() && value.bytes().all(is_base64_byte),
        "Matchlock artifact {field} must be non-empty base64"
    );
    Ok(())
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
}

fn record(command: RecordCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        RecordCommand::Add(command) => record_add(command, store_path),
        RecordCommand::List => record_list(store_path),
        RecordCommand::Get(command) => record_get(command, store_path),
        RecordCommand::Reveal(command) => record_reveal(command, store_path),
    }
}

fn record_add(command: RecordAddCommand, store_path: Option<PathBuf>) -> Result<()> {
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

fn store_record_with_optional_artifact(
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

fn record_reveal(command: RecordRevealCommand, store_path: Option<PathBuf>) -> Result<()> {
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

fn record_store(store_path: Option<PathBuf>) -> Result<RecordStore> {
    let root = match store_path {
        Some(path) => path,
        None => RecordStore::default_root()?,
    };
    Ok(RecordStore::new(root))
}

fn artifact_uri_for_custody(
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

fn vault(command: VaultCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        VaultCommand::Inventory => vault_inventory(store_path),
    }
}

fn vault_inventory(store_path: Option<PathBuf>) -> Result<()> {
    let inventory = vault_inventory_value(store_path)?;
    print_json(&inventory)
}

fn vault_inventory_value(store_path: Option<PathBuf>) -> Result<VaultInventory> {
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
struct VaultInventory {
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
struct LocalEncryptedSummary {
    present: u64,
    missing: u64,
}

#[derive(Debug, Serialize)]
struct InventoryHolding {
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
struct LocalArtifactSummary {
    encrypted: bool,
    present: bool,
    status: String,
}

fn local_artifact_summary(
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

fn artifact_category(artifact_type: &str) -> &str {
    artifact_type
        .split_once('.')
        .map_or(artifact_type, |(prefix, _)| prefix)
}

fn increment_count(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.to_owned()).or_insert(0) += 1;
}

fn grant(command: GrantCommand, store_path: Option<PathBuf>) -> Result<()> {
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

fn grant_review(command: GrantReviewCommand) -> Result<()> {
    let (grant, grant_hash) = read_grant_with_hash(&command.grant)?;
    let review = grant_review_value(&grant, grant_hash);
    print_json(&review)
}

fn grant_review_value(grant: &CredPermissionGrant, grant_hash: String) -> Value {
    let summary = grant_review_summary(grant);
    let warnings = grant_review_warnings(grant);
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
        "summary": summary,
        "warnings": warnings
    })
}

fn grant_import(command: GrantImportCommand, store_path: Option<PathBuf>) -> Result<()> {
    let (grant, grant_hash) = read_grant_with_hash(&command.grant)?;
    let source_uri = command
        .source_uri
        .or_else(|| Some(command.grant.display().to_string()));
    let stored = import_grant(&grant, grant_hash, source_uri, store_path)?;
    print_json(&stored)
}

fn import_grant(
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

fn grant_decision(
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
fn decide_grant(
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

fn grant_list(store_path: Option<PathBuf>) -> Result<()> {
    let grants = record_store(store_path)?.list_grants()?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.grant_list",
        "grants": grants
    });
    print_json(&summary)
}

fn grant_approvals(store_path: Option<PathBuf>) -> Result<()> {
    let approvals = record_store(store_path)?.list_grant_approvals()?;
    let summary = serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.grant_approval_list",
        "approvals": approvals
    });
    print_json(&summary)
}

fn grant_approval_get(command: GrantApprovalGetCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path)?;
    let Some(approval) = store.get_grant_approval(&command.approval_id)? else {
        bail!("grant approval not found: {}", command.approval_id);
    };
    print_json(&approval)
}

fn grant_get(command: GrantGetCommand, store_path: Option<PathBuf>) -> Result<()> {
    let store = record_store(store_path)?;
    let Some(grant) = store.get_grant(&command.grant_id)? else {
        bail!("grant not found: {}", command.grant_id);
    };
    print_json(&grant)
}

fn read_grant_with_hash(path: &PathBuf) -> Result<(CredPermissionGrant, String)> {
    let value = read_json(path)?;
    parse_grant_with_hash(value)
}

fn parse_grant_with_hash(value: Value) -> Result<(CredPermissionGrant, String)> {
    let grant: CredPermissionGrant =
        serde_json::from_value(value.clone()).context("grant must be a cred.permission_grant")?;
    grant.validate()?;
    let grant_hash = canonical_hash_hex(&value)?;
    Ok((grant, grant_hash))
}

fn grant_review_summary(grant: &CredPermissionGrant) -> Vec<String> {
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

fn grant_review_warnings(grant: &CredPermissionGrant) -> Vec<String> {
    let mut warnings = Vec::new();
    if grant.app_pubkey.is_none() {
        warnings.push("Grant does not bind an app public key.".to_owned());
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

struct PresentationBuild {
    request: CredActionRequest,
    source: PresentationSource,
    grant: Option<(CredPermissionGrant, String)>,
    approval_id: Option<String>,
    signing_key: Option<PathBuf>,
    now: Option<u64>,
    presentation_id: String,
    cred_id: String,
    store_path: Option<PathBuf>,
}

fn build_presentation(input: PresentationBuild) -> Result<CredPresentation> {
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

fn require_approved_grant(
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
    presentation_source_from_value(artifact, disclosure)
}

fn presentation_source_from_value(
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

fn read_action_request(path: &PathBuf) -> Result<CredActionRequest> {
    parse_action_request(read_json(path)?)
}

fn parse_action_request(value: Value) -> Result<CredActionRequest> {
    let request: CredActionRequest =
        serde_json::from_value(value).context("request must be a cred.action_request artifact")?;
    request.validate()?;
    Ok(request)
}

fn read_json(path: &PathBuf) -> Result<Value> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse JSON {}", path.display()))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn controller_secret_key_path(
    secret_key_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
) -> Result<PathBuf> {
    match secret_key_path {
        Some(path) => Ok(path),
        None => Ok(record_store(store_path)?.root().join("controller_sk.hex")),
    }
}

fn generate_secret_key_hex() -> Result<String> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read controller secret key entropy")?;
    Ok(hex_encode(&bytes))
}

fn read_secret_key(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(text.trim().to_owned())
}

fn write_secret_key(path: &Path, secret_key: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(secret_key.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn test_import_attestation() {
        let root = temp_store_root("social-graph-import");
        social_graph_import_attestation(
            SocialGraphImportAttestationCommand {
                attestation: social_graph_example("social-graph-attestation.json"),
                record_id: "record-social-graph-attestation-1".to_owned(),
                cred_id: "cred:local:example".to_owned(),
                privacy: "selective".to_owned(),
                custody: "external_reference".to_owned(),
                artifact_uri: Some(
                    social_graph_example("social-graph-attestation.json")
                        .display()
                        .to_string(),
                ),
                labels: Vec::new(),
                vault_passphrase: None,
            },
            Some(root.clone()),
        )
        .unwrap();

        let record = RecordStore::new(&root)
            .get_record("record-social-graph-attestation-1")
            .unwrap()
            .unwrap();
        assert_eq!(record.stored_artifact_type, "social_graph.attestation");
        assert_eq!(record.privacy, "selective");
        assert_eq!(record.source_app.as_deref(), Some("attester:example:v1"));
        assert_eq!(
            record.labels.as_deref().unwrap(),
            &["social_graph".to_owned(), "clout-trust-v1".to_owned()]
        );
        cleanup(root);
    }

    #[test]
    fn test_present_attestation() {
        let attestation =
            read_json(&social_graph_example("social-graph-attestation.json")).unwrap();
        let request = read_json(&social_graph_example(
            "social-graph-presentation-request.json",
        ))
        .unwrap();
        let request: CredActionRequest = serde_json::from_value(request).unwrap();
        let grant = read_json(&social_graph_example("social-graph-permission-grant.json")).unwrap();
        let grant: CredPermissionGrant = serde_json::from_value(grant).unwrap();
        enforce_presentation_grant(
            &grant,
            &request,
            "cred:local:example",
            "social_graph.attestation",
            GrantUsage {
                now: 1718999800,
                uses_so_far: 0,
            },
        )
        .unwrap();
        let secret_key = [0x22; 32];
        let signing_key = SigningKey::from_bytes(&secret_key);
        let mut presentation = serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "cred.presentation",
            "presentation_id": "presentation-social-graph-1",
            "cred_id": "cred:local:example",
            "request_id": request.request_id,
            "grant_id": grant.grant_id,
            "app_id": request.app_id,
            "created_at": 1718999800_u64,
            "artifacts": [{
                "artifact_type": "social_graph.attestation",
                "artifact_hash": canonical_hash_hex(&attestation).unwrap(),
                "record_id": "record-social-graph-attestation-1",
                "disclosure": "embedded",
                "artifact": attestation
            }],
            "request_binding_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        });
        let signature = signing_key.sign(&canonical_json(&presentation).unwrap());
        presentation["presentation_signature"] = Value::String(hex::encode(signature.to_bytes()));

        assert_eq!(
            presentation["request_binding_hash"].as_str().unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(presentation["presentation_signature"].as_str().is_some());
        let mut unsigned = presentation.clone();
        unsigned
            .as_object_mut()
            .unwrap()
            .remove("presentation_signature");
        let signature_bytes: [u8; 64] =
            hex::decode(presentation["presentation_signature"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        VerifyingKey::from_bytes(&signing_key.verifying_key().to_bytes())
            .unwrap()
            .verify(
                &canonical_json(&unsigned).unwrap(),
                &Signature::from_bytes(&signature_bytes),
            )
            .unwrap();
    }

    #[test]
    fn test_present_rejects_invalid_grant() {
        let request = social_graph_request();
        let mut grant = social_graph_grant();
        grant.capabilities = vec!["freebird.present".to_owned()];
        assert!(enforce_presentation_grant(
            &grant,
            &request,
            "cred:local:example",
            "social_graph.attestation",
            GrantUsage {
                now: 1718999800,
                uses_so_far: 0
            },
        )
        .unwrap_err()
        .to_string()
        .contains("permission grant denied"));
    }

    #[test]
    fn test_present_rejects_expired_grant() {
        let request = social_graph_request();
        let mut grant = social_graph_grant();
        grant.constraints.expires_at = Some(1);
        let err = enforce_presentation_grant(
            &grant,
            &request,
            "cred:local:example",
            "social_graph.attestation",
            GrantUsage {
                now: 1718999800,
                uses_so_far: 0,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("expired"));
    }

    #[test]
    fn presentation_requires_local_grant_approval() {
        let root = temp_store_root("requires-approval");
        let grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        let grant_hash = grant_hash(&grant);

        let err =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, None).unwrap_err();
        assert!(err.to_string().contains("no local approval record"));

        let store = RecordStore::new(&root);
        let approval = sample_approval(&grant, &grant_hash, "approved", "approval-1");
        store.append_grant_approval(&approval).unwrap();

        let approved =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, None).unwrap();
        assert_eq!(approved.approval_id, "approval-1");

        cleanup(root);
    }

    #[test]
    fn latest_denial_blocks_even_with_pinned_approval() {
        let root = temp_store_root("latest-approval");
        let grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        let grant_hash = grant_hash(&grant);
        let store = RecordStore::new(&root);
        store
            .append_grant_approval(&sample_approval(
                &grant,
                &grant_hash,
                "approved",
                "approval-1",
            ))
            .unwrap();
        store
            .append_grant_approval(&sample_approval(&grant, &grant_hash, "denied", "denial-1"))
            .unwrap();

        let err =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("permission grant was not approved"));

        let pinned_err =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, Some("approval-1"))
                .unwrap_err();
        assert!(pinned_err
            .to_string()
            .contains("permission grant was not approved"));

        cleanup(root);
    }

    #[test]
    fn pinned_approval_must_match_current_grant_hash() {
        let root = temp_store_root("approval-hash-mismatch");
        let grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        let changed_grant = sample_grant(Some(vec!["cred.presentation".to_owned()]));
        let original_hash = grant_hash(&grant);
        let changed_hash = grant_hash(&changed_grant);
        let store = RecordStore::new(&root);
        store
            .append_grant_approval(&sample_approval(
                &grant,
                &original_hash,
                "approved",
                "approval-1",
            ))
            .unwrap();

        let err = require_approved_grant(
            Some(root.clone()),
            &changed_grant,
            &changed_hash,
            Some("approval-1"),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match current grant hash"));

        cleanup(root);
    }

    #[test]
    fn witness_adapter_accepts_signed_attestation() {
        ensure_witness_signed_attestation(&sample_witness_attestation()).unwrap();
    }

    #[test]
    fn witness_adapter_rejects_other_artifacts() {
        let err = ensure_witness_signed_attestation(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "cred.presentation",
            "attestation": {},
            "signatures": {}
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("expected artifact_type witness.signed_attestation"));
    }

    #[test]
    fn witness_adapter_rejects_incomplete_attestation() {
        let err = ensure_witness_signed_attestation(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "witness.signed_attestation",
            "attestation": {}
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("witness.signed_attestation missing signatures"));
    }

    #[test]
    fn freebird_adapter_accepts_check_request() {
        ensure_freebird_check_request(&sample_freebird_check_request()).unwrap();
    }

    #[test]
    fn freebird_adapter_rejects_consuming_verify_request() {
        let err = ensure_freebird_check_request(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "freebird.verify_request",
            "token_b64": "AQIDBAUGBwgJCgsMDQ4PEA"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("non-consuming and rejects freebird.verify_request"));
    }

    #[test]
    fn freebird_adapter_rejects_invalid_token_shape() {
        let err = ensure_freebird_check_request(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "freebird.check_request",
            "token_b64": "not=base64url"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("token_b64 must be non-empty base64url"));
    }

    #[test]
    fn matchlock_adapter_accepts_commitment() {
        ensure_matchlock_presentation_safe_artifact(&sample_matchlock_commitment()).unwrap();
    }

    #[test]
    fn matchlock_adapter_rejects_raw_match_token() {
        let err = ensure_matchlock_presentation_safe_artifact(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "matchlock.match_token",
            "pool_id": "test-pool",
            "domain": "matchlock-match-v1",
            "token": "bbfee0cd9a72d348a1a4dafee9ad8c055f02c79e0d341ff4aa425583030492bf"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("rejects raw matchlock.match_token durable records"));
    }

    #[test]
    fn matchlock_adapter_rejects_private_artifact_fields() {
        let err = ensure_matchlock_presentation_safe_artifact(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "matchlock.commitment",
            "pool_id": "test-pool",
            "commitment": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "private_key": "77076d0a7318a57d3c16c17251b26645c6c2f6929f0a4b5745a0435c9b7bd30d"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("unexpected Matchlock artifact field"));
    }

    fn sample_witness_attestation() -> Value {
        serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "witness.signed_attestation",
            "attestation": {
                "tree_size": 1
            },
            "signatures": {
                "kind": "multisig",
                "signatures": [
                    {
                        "witness_id": "witness:local:1",
                        "signature": "11"
                    }
                ]
            }
        })
    }

    fn sample_freebird_check_request() -> Value {
        serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "freebird.check_request",
            "token_b64": "AQIDBAUGBwgJCgsMDQ4PEA"
        })
    }

    fn sample_matchlock_commitment() -> Value {
        serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "matchlock.commitment",
            "pool_id": "test-pool",
            "commitment": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "hashes_raw_token_bytes": true
        })
    }

    #[test]
    fn store_enforced_max_uses_blocks_replay() {
        let root = temp_store_root("max-uses-enforcement");
        let store = RecordStore::new(&root);

        // Grant with max_uses = 1
        let mut grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        grant.constraints.max_uses = Some(1);
        let hash = grant_hash(&grant);

        // Approve the grant
        let approval = sample_approval(&grant, &hash, "approved", "approval-1");
        store.append_grant_approval(&approval).unwrap();

        let request = sample_request(Some("witness.signed_attestation"));
        let source = presentation_source_from_record(sample_record(), None).unwrap();

        // First presentation should succeed (0 prior uses)
        let first = build_presentation(PresentationBuild {
            request: request.clone(),
            source: source.clone(),
            grant: Some((grant.clone(), hash.clone())),
            approval_id: Some("approval-1".to_owned()),
            signing_key: None,
            now: Some(10),
            presentation_id: "presentation-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            store_path: Some(root.clone()),
        })
        .unwrap();
        assert_eq!(first.presentation_id, "presentation-1");

        // Second presentation under the same grant must fail (1 prior use, max 1)
        let err = build_presentation(PresentationBuild {
            request,
            source,
            grant: Some((grant, hash)),
            approval_id: Some("approval-1".to_owned()),
            signing_key: None,
            now: Some(10),
            presentation_id: "presentation-2".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            store_path: Some(root.clone()),
        })
        .unwrap_err();

        assert!(format!("{err:#}").contains("max_uses has been reached"));

        cleanup(root);
    }

    fn sample_record() -> cred_core::CredArtifactRecord {
        artifact_record(
            "record-1".to_owned(),
            "cred:local:test".to_owned(),
            "witness.signed_attestation".to_owned(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            Some("examples/witness-signed-attestation.json".to_owned()),
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

    fn social_graph_example(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(name)
    }

    fn social_graph_request() -> CredActionRequest {
        serde_json::from_value(
            read_json(&social_graph_example(
                "social-graph-presentation-request.json",
            ))
            .unwrap(),
        )
        .unwrap()
    }

    fn social_graph_grant() -> CredPermissionGrant {
        serde_json::from_value(
            read_json(&social_graph_example("social-graph-permission-grant.json")).unwrap(),
        )
        .unwrap()
    }

    fn grant_hash(grant: &CredPermissionGrant) -> String {
        canonical_hash_hex(&serde_json::to_value(grant).unwrap()).unwrap()
    }

    fn sample_approval(
        grant: &CredPermissionGrant,
        grant_hash: &str,
        decision: &str,
        approval_id: &str,
    ) -> GrantApproval {
        GrantApproval::from_grant(
            grant,
            grant_hash.to_owned(),
            decision.to_owned(),
            approval_id.to_owned(),
            grant_review_summary(grant),
            grant_review_warnings(grant),
            None,
            None,
            None,
            2,
        )
    }

    fn temp_store_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cred-cli-{name}-{nanos}"))
    }

    fn cleanup(root: PathBuf) {
        let _ = fs::remove_dir_all(root);
    }
}
