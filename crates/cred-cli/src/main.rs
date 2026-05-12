use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Parser, Subcommand};
use cred_core::{
    artifact_record, artifact_type, canonical_hash_hex, enforce_grant, manifest,
    public_key_from_secret_hex, sign_presentation, validate_and_hash,
    verify_presentation_signature, CredActionRequest, CredEndpoint, CredPermissionGrant,
    CredPresentation, GrantUsage, PresentedArtifact,
};
use cred_store::RecordStore;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
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
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
struct PresentCommand {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long)]
    record_id: Option<String>,
    #[arg(long)]
    grant: Option<PathBuf>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    signing_key: Option<PathBuf>,
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
        Command::Verify(path) => verify(path.path),
        Command::Key { command } => key(command, store),
        Command::Witness { command } => witness(command, store),
        Command::Freebird { command } => freebird(command, store),
        Command::Matchlock { command } => matchlock(command, store),
        Command::Record { command } => record(command, store),
        Command::Vault { command } => vault(command, store),
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
            signing_key: command.signing_key,
            uses_so_far: command.uses_so_far,
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
            signing_key: command.signing_key,
            uses_so_far: command.uses_so_far,
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
            signing_key: command.signing_key,
            uses_so_far: command.uses_so_far,
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
    let store = record_store(store_path)?;
    let records = store.list_records()?;
    let mut artifact_types = BTreeMap::new();
    let mut custody = BTreeMap::new();
    let mut privacy = BTreeMap::new();
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

    let inventory = VaultInventory {
        contract_version: "sophia/v1",
        artifact_type: "cred.vault_inventory",
        store_root: store.root().display().to_string(),
        total_records: holdings.len() as u64,
        artifact_types,
        custody,
        privacy,
        local_encrypted: LocalEncryptedSummary {
            present: local_encrypted_present,
            missing: local_encrypted_missing,
        },
        holdings,
    };
    print_json(&inventory)
}

#[derive(Debug, Serialize)]
struct VaultInventory {
    contract_version: &'static str,
    artifact_type: &'static str,
    store_root: String,
    total_records: u64,
    artifact_types: BTreeMap<String, u64>,
    custody: BTreeMap<String, u64>,
    privacy: BTreeMap<String, u64>,
    local_encrypted: LocalEncryptedSummary,
    holdings: Vec<InventoryHolding>,
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

    let mut presentation = CredPresentation {
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
    if let Some(signing_key) = command.signing_key {
        let secret_key = read_secret_key(&signing_key)?;
        presentation = sign_presentation(presentation, &secret_key)?;
        verify_presentation_signature(&presentation)?;
    }
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
}
