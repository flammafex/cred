use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "cred")]
#[command(about = "Cred local proof agent")]
pub struct Cli {
    #[arg(long, global = true, env = "CRED_STORE_DIR")]
    pub(crate) store: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
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
pub(crate) struct ArtifactPath {
    pub(crate) path: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct ManifestCommand {
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long)]
    pub(crate) controller_public_key: String,
    #[arg(long = "capability", required = true)]
    pub(crate) capabilities: Vec<String>,
    #[arg(long, default_value = "stdio")]
    pub(crate) transport: String,
    #[arg(long)]
    pub(crate) endpoint_uri: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RecordCommand {
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
pub(crate) enum VaultCommand {
    /// Summarize local records, custody modes, and encrypted blob presence.
    Inventory,
}

#[derive(Debug, Subcommand)]
pub(crate) enum GrantCommand {
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
pub(crate) enum KeyCommand {
    /// Generate a local Ed25519 controller secret key.
    Generate(KeyGenerateCommand),
    /// Print the public key for a local controller secret key.
    Public(KeyPathCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum WitnessCommand {
    /// Import a witness.signed_attestation into Cred records.
    Import(WitnessImportCommand),
    /// Present an imported Witness attestation by reference.
    Present(WitnessPresentCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum FreebirdCommand {
    /// Import a freebird.check_request into Cred records.
    ImportCheck(FreebirdImportCheckCommand),
    /// Present an imported non-consuming Freebird check request by reference.
    PresentCheck(FreebirdPresentCheckCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum MatchlockCommand {
    /// Import a presentation-safe Matchlock artifact into Cred records.
    ImportArtifact(MatchlockImportArtifactCommand),
    /// Present an imported Matchlock artifact by reference.
    PresentArtifact(MatchlockPresentArtifactCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum SocialGraphCommand {
    /// Import a social_graph.attestation into Cred records.
    ImportAttestation(SocialGraphImportAttestationCommand),
    /// Present an imported social_graph.attestation embedded in a signed presentation.
    PresentAttestation(SocialGraphPresentAttestationCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServeCommand {
    /// Serve newline-delimited JSON requests over stdin/stdout.
    Stdio,
    /// Serve JSON requests over HTTP (localhost only).
    Http(ServeHttpCommand),
}

#[derive(Debug, Args)]
pub(crate) struct ServeHttpCommand {
    /// Port to listen on.
    #[arg(long, default_value = "7331")]
    pub(crate) port: u16,
    /// Bind address (defaults to localhost only).
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) bind: String,
}

#[derive(Debug, Args)]
pub(crate) struct KeyGenerateCommand {
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    pub(crate) secret_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct KeyPathCommand {
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    pub(crate) secret_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct RecordAddCommand {
    pub(crate) artifact: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long, default_value = "selective")]
    pub(crate) privacy: String,
    #[arg(long, default_value = "external_reference")]
    pub(crate) custody: String,
    #[arg(long)]
    pub(crate) artifact_uri: Option<String>,
    #[arg(long)]
    pub(crate) source_app: Option<String>,
    #[arg(long = "label")]
    pub(crate) labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    pub(crate) vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct WitnessImportCommand {
    pub(crate) attestation: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long, default_value = "selective")]
    pub(crate) privacy: String,
    #[arg(long, default_value = "external_reference")]
    pub(crate) custody: String,
    #[arg(long)]
    pub(crate) artifact_uri: Option<String>,
    #[arg(long, default_value = "app:witness")]
    pub(crate) source_app: String,
    #[arg(long = "label")]
    pub(crate) labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    pub(crate) vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct WitnessPresentCommand {
    #[arg(long)]
    pub(crate) request: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) grant: Option<PathBuf>,
    #[arg(long)]
    pub(crate) approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    pub(crate) signing_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) now: Option<u64>,
    #[arg(long)]
    pub(crate) presentation_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long)]
    pub(crate) disclosure: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct FreebirdImportCheckCommand {
    pub(crate) check_request: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long, default_value = "private")]
    pub(crate) privacy: String,
    #[arg(long, default_value = "external_reference")]
    pub(crate) custody: String,
    #[arg(long)]
    pub(crate) artifact_uri: Option<String>,
    #[arg(long, default_value = "app:freebird")]
    pub(crate) source_app: String,
    #[arg(long = "label")]
    pub(crate) labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    pub(crate) vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct FreebirdPresentCheckCommand {
    #[arg(long)]
    pub(crate) request: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) grant: Option<PathBuf>,
    #[arg(long)]
    pub(crate) approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    pub(crate) signing_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) now: Option<u64>,
    #[arg(long)]
    pub(crate) presentation_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long)]
    pub(crate) disclosure: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct MatchlockImportArtifactCommand {
    pub(crate) artifact: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long, default_value = "private")]
    pub(crate) privacy: String,
    #[arg(long, default_value = "external_reference")]
    pub(crate) custody: String,
    #[arg(long)]
    pub(crate) artifact_uri: Option<String>,
    #[arg(long, default_value = "app:matchlock")]
    pub(crate) source_app: String,
    #[arg(long = "label")]
    pub(crate) labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    pub(crate) vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct MatchlockPresentArtifactCommand {
    #[arg(long)]
    pub(crate) request: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) grant: Option<PathBuf>,
    #[arg(long)]
    pub(crate) approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    pub(crate) signing_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) now: Option<u64>,
    #[arg(long)]
    pub(crate) presentation_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long)]
    pub(crate) disclosure: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SocialGraphImportAttestationCommand {
    pub(crate) attestation: PathBuf,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long, default_value = "selective")]
    pub(crate) privacy: String,
    #[arg(long, default_value = "local_encrypted")]
    pub(crate) custody: String,
    #[arg(long)]
    pub(crate) artifact_uri: Option<String>,
    #[arg(long = "label")]
    pub(crate) labels: Vec<String>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    pub(crate) vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SocialGraphPresentAttestationCommand {
    #[arg(long)]
    pub(crate) request: PathBuf,
    #[arg(long)]
    pub(crate) grant: PathBuf,
    #[arg(long)]
    pub(crate) approval_id: String,
    #[arg(long)]
    pub(crate) record_id: String,
    #[arg(long)]
    pub(crate) presentation_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long)]
    pub(crate) request_binding_hash: String,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    pub(crate) signing_key: PathBuf,
    #[arg(long)]
    pub(crate) now: Option<u64>,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    pub(crate) vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RecordGetCommand {
    pub(crate) record_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct RecordRevealCommand {
    pub(crate) record_id: String,
    #[arg(long, env = "CRED_VAULT_PASSPHRASE")]
    pub(crate) vault_passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct GrantReviewCommand {
    pub(crate) grant: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct GrantImportCommand {
    pub(crate) grant: PathBuf,
    #[arg(long)]
    pub(crate) source_uri: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct GrantDecisionCommand {
    pub(crate) grant: PathBuf,
    #[arg(long)]
    pub(crate) approval_id: String,
    #[arg(long)]
    pub(crate) reviewer: Option<String>,
    #[arg(long)]
    pub(crate) note: Option<String>,
    #[arg(long)]
    pub(crate) source_uri: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct GrantGetCommand {
    pub(crate) grant_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct GrantApprovalGetCommand {
    pub(crate) approval_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct PresentCommand {
    #[arg(long)]
    pub(crate) request: PathBuf,
    #[arg(long)]
    pub(crate) artifact: Option<PathBuf>,
    #[arg(long)]
    pub(crate) record_id: Option<String>,
    #[arg(long)]
    pub(crate) grant: Option<PathBuf>,
    #[arg(long)]
    pub(crate) approval_id: Option<String>,
    #[arg(long, env = "CRED_CONTROLLER_SK")]
    pub(crate) signing_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) now: Option<u64>,
    #[arg(long)]
    pub(crate) presentation_id: String,
    #[arg(long)]
    pub(crate) cred_id: String,
    #[arg(long)]
    pub(crate) disclosure: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct GrantCheckCommand {
    #[arg(long)]
    pub(crate) grant: PathBuf,
    #[arg(long)]
    pub(crate) request: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub(crate) uses_so_far: u64,
    #[arg(long)]
    pub(crate) now: Option<u64>,
}
