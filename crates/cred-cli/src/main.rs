use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use cred_core::{
    artifact_record, artifact_type, canonical_hash_hex, manifest, validate_and_hash,
    CredActionRequest, CredEndpoint, CredPresentation, PresentedArtifact,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(name = "cred")]
#[command(about = "Cred local proof agent")]
struct Cli {
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
    /// Build a mocked cred.presentation from a request and artifact.
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
    /// Build a cred.artifact_record for a JSON artifact.
    Add(RecordAddCommand),
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
struct PresentCommand {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    artifact: PathBuf,
    #[arg(long)]
    presentation_id: String,
    #[arg(long)]
    cred_id: String,
    #[arg(long, default_value = "embedded")]
    disclosure: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Manifest(command) => print_manifest(command),
        Command::Inspect(path) => inspect(path.path),
        Command::Hash(path) => hash(path.path),
        Command::Record {
            command: RecordCommand::Add(command),
        } => record_add(command),
        Command::Present(command) => present(command),
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

fn record_add(command: RecordAddCommand) -> Result<()> {
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
    print_json(&record)
}

fn present(command: PresentCommand) -> Result<()> {
    let request_value = read_json(&command.request)?;
    let request: CredActionRequest = serde_json::from_value(request_value)
        .context("request must be a cred.action_request artifact")?;
    if request.contract_version != "sophia/v1" || request.artifact_type != "cred.action_request" {
        anyhow::bail!("request must be a cred.action_request artifact");
    }

    let artifact = read_json(&command.artifact)?;
    let artifact_type = artifact_type(&artifact)
        .context("presented artifact must include artifact_type")?
        .to_owned();
    let artifact_hash = canonical_hash_hex(&artifact)?;
    let embedded = if command.disclosure == "embedded" {
        Some(artifact)
    } else {
        None
    };

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
            artifact_type,
            artifact_hash,
            record_id: None,
            disclosure: command.disclosure,
            artifact: embedded,
        }],
        cred_signature: None,
    };
    print_json(&presentation)
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
