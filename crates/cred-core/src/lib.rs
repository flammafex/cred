use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const CONTRACT_VERSION: &str = "sophia/v1";

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("artifact must be a JSON object")]
    NotObject,
    #[error("missing or invalid artifact_type")]
    MissingArtifactType,
    #[error("unsupported Cred artifact_type: {0}")]
    UnsupportedArtifactType(String),
    #[error("artifact contract_version must be sophia/v1")]
    WrongContractVersion,
    #[error("invalid Cred artifact: {0}")]
    InvalidArtifact(#[from] serde_json::Error),
    #[error("canonical JSON does not support floating point numbers in Cred v1")]
    FloatNumber,
    #[error("{0} must be non-empty")]
    EmptyField(&'static str),
    #[error("{field} must be lowercase hex for exactly {expected_bytes} bytes")]
    InvalidHex {
        field: &'static str,
        expected_bytes: usize,
    },
    #[error("{0} must contain at least one item")]
    EmptyArray(&'static str),
    #[error("{field} contains duplicate value: {value}")]
    DuplicateValue { field: &'static str, value: String },
    #[error("invalid capability: {0}")]
    InvalidCapability(String),
    #[error("{field} has unsupported value: {value}")]
    InvalidEnum { field: &'static str, value: String },
    #[error("permission grant app_id does not match request app_id")]
    GrantAppMismatch,
    #[error("permission request must include the matching grant_id")]
    MissingGrantId,
    #[error("permission request grant_id does not match grant")]
    GrantIdMismatch,
    #[error("permission grant is expired")]
    GrantExpired,
    #[error("permission grant max_uses has been reached")]
    GrantUseLimitExceeded,
    #[error("requested capability is not granted: {0}")]
    CapabilityNotGranted(String),
    #[error("requested audience is not allowed: {0}")]
    AudienceNotAllowed(String),
    #[error("requested artifact type is not allowed: {0}")]
    ArtifactTypeNotAllowed(String),
    #[error("requested export is not allowed by grant")]
    ExportNotAllowed,
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("missing presentation signature")]
    MissingPresentationSignature,
    #[error("presentation signature verification failed")]
    SignatureVerificationFailed,
    #[error("embedded disclosure requires an artifact")]
    EmbeddedArtifactMissing,
    #[error("embedded artifact hash does not match artifact_hash")]
    EmbeddedArtifactHashMismatch,
    #[error("grant binds an app public key but request is missing app_signature")]
    MissingRequestSignature,
    #[error("request app_signature verification failed")]
    RequestSignatureVerificationFailed,
    #[error("grant cred_signature verification failed")]
    GrantSignatureVerificationFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredManifest {
    pub contract_version: String,
    pub artifact_type: String,
    pub cred_id: String,
    pub controller: CredController,
    pub capabilities: Vec<String>,
    pub storage: CredStorage,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<CredEndpoint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredController {
    pub scheme: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredStorage {
    pub encrypted_at_rest: bool,
    pub exportable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredEndpoint {
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredPermissionGrant {
    pub contract_version: String,
    pub artifact_type: String,
    pub grant_id: String,
    pub cred_id: String,
    pub app_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_pubkey: Option<String>,
    pub capabilities: Vec<String>,
    pub constraints: CredGrantConstraints,
    pub human_approval: String,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_signature: Option<CredSignature>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredGrantConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_audiences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_artifact_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_export: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredSignature {
    pub scheme: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredActionRequest {
    pub contract_version: String,
    pub artifact_type: String,
    pub request_id: String,
    pub app_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub requested_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub actions: Vec<CredAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_signature: Option<CredSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredAction {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredPresentation {
    pub contract_version: String,
    pub artifact_type: String,
    pub presentation_id: String,
    pub cred_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub app_id: String,
    pub created_at: u64,
    pub artifacts: Vec<PresentedArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_binding_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_signature: Option<CredSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PresentedArtifact {
    pub artifact_type: String,
    pub artifact_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    pub disclosure: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredArtifactRecord {
    pub contract_version: String,
    pub artifact_type: String,
    pub record_id: String,
    pub cred_id: String,
    pub stored_artifact_type: String,
    pub artifact_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_hash: Option<String>,
    pub privacy: String,
    pub custody: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_app: Option<String>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredArtifactKind {
    Manifest,
    PermissionGrant,
    ActionRequest,
    Presentation,
    ArtifactRecord,
}

impl CredArtifactKind {
    pub fn artifact_type(self) -> &'static str {
        match self {
            CredArtifactKind::Manifest => "cred.manifest",
            CredArtifactKind::PermissionGrant => "cred.permission_grant",
            CredArtifactKind::ActionRequest => "cred.action_request",
            CredArtifactKind::Presentation => "cred.presentation",
            CredArtifactKind::ArtifactRecord => "cred.artifact_record",
        }
    }
}

impl TryFrom<&str> for CredArtifactKind {
    type Error = CredError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "cred.manifest" => Ok(Self::Manifest),
            "cred.permission_grant" => Ok(Self::PermissionGrant),
            "cred.action_request" => Ok(Self::ActionRequest),
            "cred.presentation" => Ok(Self::Presentation),
            "cred.artifact_record" => Ok(Self::ArtifactRecord),
            other => Err(CredError::UnsupportedArtifactType(other.to_owned())),
        }
    }
}

pub struct GrantUsage {
    pub now: u64,
    pub uses_so_far: u64,
}

pub fn artifact_type(value: &Value) -> Result<&str, CredError> {
    value
        .as_object()
        .ok_or(CredError::NotObject)?
        .get("artifact_type")
        .and_then(Value::as_str)
        .ok_or(CredError::MissingArtifactType)
}

pub fn validate_cred_artifact(value: &Value) -> Result<CredArtifactKind, CredError> {
    let object = value.as_object().ok_or(CredError::NotObject)?;
    if object.get("contract_version").and_then(Value::as_str) != Some(CONTRACT_VERSION) {
        return Err(CredError::WrongContractVersion);
    }

    let kind = CredArtifactKind::try_from(artifact_type(value)?)?;
    match kind {
        CredArtifactKind::Manifest => {
            serde_json::from_value::<CredManifest>(value.clone())?.validate()?;
        }
        CredArtifactKind::PermissionGrant => {
            serde_json::from_value::<CredPermissionGrant>(value.clone())?.validate()?;
        }
        CredArtifactKind::ActionRequest => {
            serde_json::from_value::<CredActionRequest>(value.clone())?.validate()?;
        }
        CredArtifactKind::Presentation => {
            let presentation = serde_json::from_value::<CredPresentation>(value.clone())?;
            presentation.validate()?;
            if presentation.cred_signature.is_some() {
                verify_presentation_signature(&presentation)?;
            }
        }
        CredArtifactKind::ArtifactRecord => {
            serde_json::from_value::<CredArtifactRecord>(value.clone())?.validate()?;
        }
    }
    Ok(kind)
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CredError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out.into_bytes())
}

pub fn canonical_hash_hex(value: &Value) -> Result<String, CredError> {
    let canonical = canonical_json(value)?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

pub fn validate_and_hash(value: &Value) -> Result<(CredArtifactKind, String), CredError> {
    let kind = validate_cred_artifact(value)?;
    let hash = canonical_hash_hex(value)?;
    Ok((kind, hash))
}

pub fn public_key_from_secret_hex(secret_key_hex: &str) -> Result<String, CredError> {
    let secret_key = decode_hex_array::<32>(secret_key_hex.trim(), "secret_key")?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

pub fn sign_presentation(
    mut presentation: CredPresentation,
    secret_key_hex: &str,
) -> Result<CredPresentation, CredError> {
    let secret_key = decode_hex_array::<32>(secret_key_hex.trim(), "secret_key")?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    presentation.cred_signature = None;
    let payload = presentation_signature_payload(&presentation)?;
    let signature = signing_key.sign(&payload);
    presentation.cred_signature = Some(CredSignature {
        scheme: "ed25519".to_owned(),
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    });
    presentation.validate()?;
    Ok(presentation)
}

pub fn verify_presentation_signature(presentation: &CredPresentation) -> Result<(), CredError> {
    presentation.validate()?;
    let signature = presentation
        .cred_signature
        .as_ref()
        .ok_or(CredError::MissingPresentationSignature)?;
    let public_key = decode_hex_array::<32>(&signature.public_key, "signature.public_key")?;
    let signature_bytes = decode_hex_array::<64>(&signature.signature, "signature.signature")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| CredError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = presentation_signature_payload(presentation)?;

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CredError::SignatureVerificationFailed)
}

pub fn presentation_signature_payload(
    presentation: &CredPresentation,
) -> Result<Vec<u8>, CredError> {
    let mut unsigned = presentation.clone();
    unsigned.cred_signature = None;
    unsigned.validate()?;
    let value = serde_json::to_value(unsigned)?;
    canonical_json(&value)
}

/// Computes the canonical JSON payload for a grant signature.
/// The signature field is omitted from the signed payload, matching the
/// presentation signature pattern.
pub fn grant_signature_payload(grant: &CredPermissionGrant) -> Result<Vec<u8>, CredError> {
    let mut unsigned = grant.clone();
    unsigned.cred_signature = None;
    unsigned.validate()?;
    let value = serde_json::to_value(unsigned)?;
    canonical_json(&value)
}

/// Verifies a grant's `cred_signature` if present. Grants without a
/// `cred_signature` are valid — local approval remains the trust root.
/// The signature is treated as provenance only, not authorization.
pub fn verify_grant_signature(grant: &CredPermissionGrant) -> Result<(), CredError> {
    grant.validate()?;
    let Some(signature) = &grant.cred_signature else {
        return Ok(());
    };
    let public_key = decode_hex_array::<32>(&signature.public_key, "signature.public_key")?;
    let signature_bytes = decode_hex_array::<64>(&signature.signature, "signature.signature")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| CredError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = grant_signature_payload(grant)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CredError::GrantSignatureVerificationFailed)
}

/// Computes the canonical JSON payload for an action request signature.
/// The `app_signature` field is omitted from the signed payload.
pub fn action_request_signature_payload(request: &CredActionRequest) -> Result<Vec<u8>, CredError> {
    let mut unsigned = request.clone();
    unsigned.app_signature = None;
    unsigned.validate()?;
    let value = serde_json::to_value(unsigned)?;
    canonical_json(&value)
}

/// Verifies that an action request was signed by the holder of the
/// `app_pubkey` bound in the grant. Called by `enforce_grant` when
/// `grant.app_pubkey` is present.
pub fn verify_action_request_signature(
    request: &CredActionRequest,
    expected_app_pubkey: &str,
) -> Result<(), CredError> {
    request.validate()?;
    let signature = request
        .app_signature
        .as_ref()
        .ok_or(CredError::MissingRequestSignature)?;
    if signature.public_key != expected_app_pubkey {
        return Err(CredError::RequestSignatureVerificationFailed);
    }
    let public_key = decode_hex_array::<32>(&signature.public_key, "signature.public_key")?;
    let signature_bytes = decode_hex_array::<64>(&signature.signature, "signature.signature")?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| CredError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = action_request_signature_payload(request)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CredError::RequestSignatureVerificationFailed)
}

/// Signs an action request with an app secret key. Used for testing
/// and by apps that need to produce signed requests.
pub fn sign_action_request(
    mut request: CredActionRequest,
    secret_key_hex: &str,
) -> Result<CredActionRequest, CredError> {
    let secret_key = decode_hex_array::<32>(secret_key_hex.trim(), "secret_key")?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    request.app_signature = None;
    let payload = action_request_signature_payload(&request)?;
    let signature = signing_key.sign(&payload);
    request.app_signature = Some(CredSignature {
        scheme: "ed25519".to_owned(),
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    });
    request.validate()?;
    Ok(request)
}

/// Signs a permission grant with a secret key. Used for testing and
/// by grant issuers that want to bind provenance to a grant.
pub fn sign_grant(
    mut grant: CredPermissionGrant,
    secret_key_hex: &str,
) -> Result<CredPermissionGrant, CredError> {
    let secret_key = decode_hex_array::<32>(secret_key_hex.trim(), "secret_key")?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    grant.cred_signature = None;
    let payload = grant_signature_payload(&grant)?;
    let signature = signing_key.sign(&payload);
    grant.cred_signature = Some(CredSignature {
        scheme: "ed25519".to_owned(),
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    });
    grant.validate()?;
    Ok(grant)
}

pub fn enforce_grant(
    grant: &CredPermissionGrant,
    request: &CredActionRequest,
    usage: GrantUsage,
) -> Result<(), CredError> {
    grant.validate()?;
    request.validate()?;

    if grant.app_id != request.app_id {
        return Err(CredError::GrantAppMismatch);
    }
    match &request.grant_id {
        Some(request_grant_id) if request_grant_id == &grant.grant_id => {}
        Some(_) => return Err(CredError::GrantIdMismatch),
        None => return Err(CredError::MissingGrantId),
    }

    // If the grant binds an app public key, the request must be signed by
    // the holder of that key. Grants without app_pubkey remain in legacy
    // mode (local approval only).
    if let Some(app_pubkey) = &grant.app_pubkey {
        verify_action_request_signature(request, app_pubkey)?;
    }

    if let Some(expires_at) = grant.constraints.expires_at {
        if usage.now > expires_at || request.requested_at > expires_at {
            return Err(CredError::GrantExpired);
        }
    }
    if let Some(max_uses) = grant.constraints.max_uses {
        if usage.uses_so_far >= max_uses {
            return Err(CredError::GrantUseLimitExceeded);
        }
    }

    for action in &request.actions {
        if !grant
            .capabilities
            .iter()
            .any(|capability| capability == &action.kind)
        {
            return Err(CredError::CapabilityNotGranted(action.kind.clone()));
        }
        if let Some(audience) = &action.audience {
            if let Some(allowed) = &grant.constraints.allowed_audiences {
                if !allowed.iter().any(|candidate| candidate == audience) {
                    return Err(CredError::AudienceNotAllowed(audience.clone()));
                }
            }
        }
        if let Some(artifact_type) = &action.artifact_type {
            if let Some(allowed) = &grant.constraints.allowed_artifact_types {
                if !allowed.iter().any(|candidate| candidate == artifact_type) {
                    return Err(CredError::ArtifactTypeNotAllowed(artifact_type.clone()));
                }
            }
        }
        if action.kind.ends_with(".export") && grant.constraints.allow_export != Some(true) {
            return Err(CredError::ExportNotAllowed);
        }
    }

    Ok(())
}

impl CredManifest {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_base(&self.contract_version, &self.artifact_type, "cred.manifest")?;
        validate_non_empty(&self.cred_id, "cred_id")?;
        self.controller.validate()?;
        validate_capabilities(&self.capabilities, "capabilities")?;
        if let Some(endpoints) = &self.endpoints {
            for endpoint in endpoints {
                endpoint.validate()?;
            }
        }
        Ok(())
    }
}

impl CredController {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_enum("controller.scheme", &self.scheme, &["ed25519"])?;
        validate_hex(&self.public_key, "controller.public_key", 32)
    }
}

impl CredEndpoint {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_enum(
            "endpoint.transport",
            &self.transport,
            &["stdio", "http", "unix", "websocket"],
        )?;
        if let Some(uri) = &self.uri {
            validate_non_empty(uri, "endpoint.uri")?;
        }
        Ok(())
    }
}

impl CredPermissionGrant {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_base(
            &self.contract_version,
            &self.artifact_type,
            "cred.permission_grant",
        )?;
        validate_non_empty(&self.grant_id, "grant_id")?;
        validate_non_empty(&self.cred_id, "cred_id")?;
        validate_non_empty(&self.app_id, "app_id")?;
        if let Some(app_pubkey) = &self.app_pubkey {
            validate_hex(app_pubkey, "app_pubkey", 32)?;
        }
        validate_capabilities(&self.capabilities, "capabilities")?;
        self.constraints.validate()?;
        validate_enum(
            "human_approval",
            &self.human_approval,
            &["per_use", "once", "none"],
        )?;
        if let Some(signature) = &self.cred_signature {
            signature.validate("cred_signature")?;
        }
        Ok(())
    }
}

impl CredGrantConstraints {
    pub fn validate(&self) -> Result<(), CredError> {
        if let Some(audiences) = &self.allowed_audiences {
            validate_non_empty_unique_strings(audiences, "constraints.allowed_audiences")?;
        }
        if let Some(artifact_types) = &self.allowed_artifact_types {
            validate_non_empty_unique_strings(
                artifact_types,
                "constraints.allowed_artifact_types",
            )?;
        }
        if self.max_uses == Some(0) {
            return Err(CredError::InvalidEnum {
                field: "constraints.max_uses",
                value: "0".to_owned(),
            });
        }
        Ok(())
    }
}

impl CredSignature {
    pub fn validate(&self, field: &'static str) -> Result<(), CredError> {
        validate_enum(field, &self.scheme, &["ed25519"])?;
        validate_hex(&self.public_key, "signature.public_key", 32)?;
        validate_hex(&self.signature, "signature.signature", 64)
    }
}

impl CredActionRequest {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_base(
            &self.contract_version,
            &self.artifact_type,
            "cred.action_request",
        )?;
        validate_non_empty(&self.request_id, "request_id")?;
        validate_non_empty(&self.app_id, "app_id")?;
        if let Some(grant_id) = &self.grant_id {
            validate_non_empty(grant_id, "grant_id")?;
        }
        if let Some(purpose) = &self.purpose {
            validate_non_empty(purpose, "purpose")?;
        }
        if self.actions.is_empty() {
            return Err(CredError::EmptyArray("actions"));
        }
        for action in &self.actions {
            action.validate()?;
        }
        if let Some(signature) = &self.app_signature {
            signature.validate("app_signature")?;
        }
        Ok(())
    }
}

impl CredAction {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_capability(&self.kind)?;
        if let Some(audience) = &self.audience {
            validate_non_empty(audience, "action.audience")?;
        }
        if let Some(semantic) = &self.semantic {
            validate_enum(
                "action.semantic",
                semantic,
                &["consuming_verify", "non_consuming_check", "not_used"],
            )?;
        }
        if let Some(artifact_type) = &self.artifact_type {
            validate_non_empty(artifact_type, "action.artifact_type")?;
        }
        if let Some(hash) = &self.hash {
            validate_hex(hash, "action.hash", 32)?;
        }
        if let Some(payload_hash) = &self.payload_hash {
            validate_hex(payload_hash, "action.payload_hash", 32)?;
        }
        if let Some(pool_id) = &self.pool_id {
            validate_non_empty(pool_id, "action.pool_id")?;
        }
        if let Some(reason) = &self.reason {
            validate_non_empty(reason, "action.reason")?;
        }
        Ok(())
    }
}

impl CredPresentation {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_base(
            &self.contract_version,
            &self.artifact_type,
            "cred.presentation",
        )?;
        validate_non_empty(&self.presentation_id, "presentation_id")?;
        validate_non_empty(&self.cred_id, "cred_id")?;
        validate_non_empty(&self.request_id, "request_id")?;
        if let Some(grant_id) = &self.grant_id {
            validate_non_empty(grant_id, "grant_id")?;
        }
        validate_non_empty(&self.app_id, "app_id")?;
        if self.artifacts.is_empty() {
            return Err(CredError::EmptyArray("artifacts"));
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        if let Some(request_binding_hash) = &self.request_binding_hash {
            validate_hex(request_binding_hash, "request_binding_hash", 32)?;
        }
        if let Some(signature) = &self.cred_signature {
            signature.validate("cred_signature")?;
        }
        Ok(())
    }
}

impl PresentedArtifact {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_non_empty(&self.artifact_type, "presented_artifact.artifact_type")?;
        validate_hex(&self.artifact_hash, "presented_artifact.artifact_hash", 32)?;
        if let Some(record_id) = &self.record_id {
            validate_non_empty(record_id, "presented_artifact.record_id")?;
        }
        validate_enum(
            "presented_artifact.disclosure",
            &self.disclosure,
            &["embedded", "reference", "redacted"],
        )?;

        match self.disclosure.as_str() {
            "embedded" => {
                let artifact = self
                    .artifact
                    .as_ref()
                    .ok_or(CredError::EmbeddedArtifactMissing)?;
                let computed = canonical_hash_hex(artifact)?;
                if computed != self.artifact_hash {
                    return Err(CredError::EmbeddedArtifactHashMismatch);
                }
            }
            "reference" => {
                if self.record_id.is_none() {
                    return Err(CredError::EmptyField("presented_artifact.record_id"));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl CredArtifactRecord {
    pub fn validate(&self) -> Result<(), CredError> {
        validate_base(
            &self.contract_version,
            &self.artifact_type,
            "cred.artifact_record",
        )?;
        validate_non_empty(&self.record_id, "record_id")?;
        validate_non_empty(&self.cred_id, "cred_id")?;
        validate_non_empty(&self.stored_artifact_type, "stored_artifact_type")?;
        validate_hex(&self.artifact_hash, "artifact_hash", 32)?;
        if let Some(artifact_uri) = &self.artifact_uri {
            validate_non_empty(artifact_uri, "artifact_uri")?;
        }
        if let Some(subject_hash) = &self.subject_hash {
            validate_hex(subject_hash, "subject_hash", 32)?;
        }
        validate_enum(
            "privacy",
            &self.privacy,
            &["public", "selective", "private", "secret"],
        )?;
        validate_enum(
            "custody",
            &self.custody,
            &[
                "local_encrypted",
                "external_reference",
                "ephemeral",
                "secret_derived",
            ],
        )?;
        if self.custody == "external_reference" && self.artifact_uri.is_none() {
            return Err(CredError::EmptyField("artifact_uri"));
        }
        if let Some(source_app) = &self.source_app {
            validate_non_empty(source_app, "source_app")?;
        }
        if let Some(labels) = &self.labels {
            validate_non_empty_unique_strings(labels, "labels")?;
        }
        Ok(())
    }
}

fn validate_base(
    contract_version: &str,
    artifact_type: &str,
    expected_artifact_type: &'static str,
) -> Result<(), CredError> {
    if contract_version != CONTRACT_VERSION {
        return Err(CredError::WrongContractVersion);
    }
    if artifact_type != expected_artifact_type {
        return Err(CredError::UnsupportedArtifactType(artifact_type.to_owned()));
    }
    Ok(())
}

fn validate_non_empty(value: &str, field: &'static str) -> Result<(), CredError> {
    if value.is_empty() {
        return Err(CredError::EmptyField(field));
    }
    Ok(())
}

fn validate_hex(value: &str, field: &'static str, expected_bytes: usize) -> Result<(), CredError> {
    let expected_len = expected_bytes * 2;
    if value.len() != expected_len || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CredError::InvalidHex {
            field,
            expected_bytes,
        });
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(CredError::InvalidHex {
            field,
            expected_bytes,
        });
    }
    Ok(())
}

fn decode_hex_array<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], CredError> {
    validate_hex(value, field, N)?;
    let bytes = hex::decode(value).map_err(|_| CredError::InvalidHex {
        field,
        expected_bytes: N,
    })?;
    bytes.try_into().map_err(|_| CredError::InvalidHex {
        field,
        expected_bytes: N,
    })
}

fn validate_enum(
    field: &'static str,
    value: &str,
    allowed: &[&'static str],
) -> Result<(), CredError> {
    if allowed.iter().any(|candidate| candidate == &value) {
        return Ok(());
    }
    Err(CredError::InvalidEnum {
        field,
        value: value.to_owned(),
    })
}

fn validate_capabilities(values: &[String], field: &'static str) -> Result<(), CredError> {
    if values.is_empty() {
        return Err(CredError::EmptyArray(field));
    }
    validate_unique_strings(values, field)?;
    for value in values {
        validate_capability(value)?;
    }
    Ok(())
}

fn validate_capability(value: &str) -> Result<(), CredError> {
    let mut parts = value.split('.');
    let first = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| CredError::InvalidCapability(value.to_owned()))?;
    if !first
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase())
    {
        return Err(CredError::InvalidCapability(value.to_owned()));
    }
    if !first
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(CredError::InvalidCapability(value.to_owned()));
    }

    let mut has_suffix = false;
    for part in parts {
        if part.is_empty()
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(CredError::InvalidCapability(value.to_owned()));
        }
        has_suffix = true;
    }
    if !has_suffix {
        return Err(CredError::InvalidCapability(value.to_owned()));
    }
    Ok(())
}

fn validate_non_empty_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), CredError> {
    if values.is_empty() {
        return Err(CredError::EmptyArray(field));
    }
    for value in values {
        validate_non_empty(value, field)?;
    }
    validate_unique_strings(values, field)
}

fn validate_unique_strings(values: &[String], field: &'static str) -> Result<(), CredError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(CredError::DuplicateValue {
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), CredError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if let Some(n) = number.as_i64() {
                out.push_str(&n.to_string());
            } else if let Some(n) = number.as_u64() {
                out.push_str(&n.to_string());
            } else {
                return Err(CredError::FloatNumber);
            }
        }
        Value::String(text) => out.push_str(&serde_json::to_string(text)?),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(object) => write_canonical_object(object, out)?,
    }
    Ok(())
}

fn write_canonical_object(object: &Map<String, Value>, out: &mut String) -> Result<(), CredError> {
    let sorted: BTreeMap<&String, &Value> = object.iter().collect();
    out.push('{');
    for (index, (key, value)) in sorted.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(key)?);
        out.push(':');
        write_canonical(value, out)?;
    }
    out.push('}');
    Ok(())
}

pub fn manifest(
    cred_id: String,
    controller_public_key: String,
    capabilities: Vec<String>,
    created_at: u64,
    endpoints: Option<Vec<CredEndpoint>>,
) -> CredManifest {
    CredManifest {
        contract_version: CONTRACT_VERSION.to_owned(),
        artifact_type: CredArtifactKind::Manifest.artifact_type().to_owned(),
        cred_id,
        controller: CredController {
            scheme: "ed25519".to_owned(),
            public_key: controller_public_key,
        },
        capabilities,
        storage: CredStorage {
            encrypted_at_rest: true,
            exportable: true,
        },
        created_at,
        endpoints,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn artifact_record(
    record_id: String,
    cred_id: String,
    stored_artifact_type: String,
    artifact_hash: String,
    artifact_uri: Option<String>,
    privacy: String,
    custody: String,
    source_app: Option<String>,
    created_at: u64,
    labels: Option<Vec<String>>,
) -> CredArtifactRecord {
    CredArtifactRecord {
        contract_version: CONTRACT_VERSION.to_owned(),
        artifact_type: CredArtifactKind::ArtifactRecord.artifact_type().to_owned(),
        record_id,
        cred_id,
        stored_artifact_type,
        artifact_hash,
        artifact_uri,
        subject_hash: None,
        privacy,
        custody,
        source_app,
        created_at,
        labels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = serde_json::json!({
            "b": true,
            "a": [2, 1],
            "c": { "z": "last", "m": "middle" }
        });

        let canonical = String::from_utf8(canonical_json(&value).unwrap()).unwrap();
        assert_eq!(
            canonical,
            r#"{"a":[2,1],"b":true,"c":{"m":"middle","z":"last"}}"#
        );
    }

    #[test]
    fn validates_manifest() {
        let value = serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "cred.manifest",
            "cred_id": "cred:local:test",
            "controller": {
                "scheme": "ed25519",
                "public_key": "1111111111111111111111111111111111111111111111111111111111111111"
            },
            "capabilities": ["store.artifact"],
            "storage": {
                "encrypted_at_rest": true,
                "exportable": true
            },
            "created_at": 1767225600
        });

        let (kind, hash) = validate_and_hash(&value).unwrap();
        assert_eq!(kind, CredArtifactKind::Manifest);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn rejects_invalid_capability_shape() {
        let value = serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "cred.manifest",
            "cred_id": "cred:local:test",
            "controller": {
                "scheme": "ed25519",
                "public_key": "1111111111111111111111111111111111111111111111111111111111111111"
            },
            "capabilities": ["Freebird.present"],
            "storage": {
                "encrypted_at_rest": true,
                "exportable": true
            },
            "created_at": 1767225600
        });

        assert!(matches!(
            validate_cred_artifact(&value),
            Err(CredError::InvalidCapability(_))
        ));
    }

    #[test]
    fn grant_allows_matching_request() {
        let grant = example_grant();
        let request = example_request();

        enforce_grant(
            &grant,
            &request,
            GrantUsage {
                now: 1767225601,
                uses_so_far: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn grant_rejects_wrong_app() {
        let grant = example_grant();
        let mut request = example_request();
        request.app_id = "app:clout:local".to_owned();

        assert!(matches!(
            enforce_grant(
                &grant,
                &request,
                GrantUsage {
                    now: 1767225601,
                    uses_so_far: 0,
                },
            ),
            Err(CredError::GrantAppMismatch)
        ));
    }

    #[test]
    fn grant_rejects_ungranted_capability() {
        let grant = example_grant();
        let mut request = example_request();
        request.actions.push(CredAction {
            kind: "sign.payload".to_owned(),
            audience: None,
            semantic: None,
            artifact_type: None,
            hash: None,
            payload_hash: Some(
                "f2ca1bb6c7e907d06dafe4687e579fce7d08f0f2514ee1f2787e118c67d84fbf".to_owned(),
            ),
            pool_id: None,
            reason: None,
        });

        assert!(matches!(
            enforce_grant(
                &grant,
                &request,
                GrantUsage {
                    now: 1767225601,
                    uses_so_far: 0,
                },
            ),
            Err(CredError::CapabilityNotGranted(kind)) if kind == "sign.payload"
        ));
    }

    #[test]
    fn grant_rejects_expired_or_exhausted_grant() {
        let grant = example_grant();
        let request = example_request();

        assert!(matches!(
            enforce_grant(
                &grant,
                &request,
                GrantUsage {
                    now: 4102444801,
                    uses_so_far: 0,
                },
            ),
            Err(CredError::GrantExpired)
        ));

        assert!(matches!(
            enforce_grant(
                &grant,
                &request,
                GrantUsage {
                    now: 1767225601,
                    uses_so_far: 3,
                },
            ),
            Err(CredError::GrantUseLimitExceeded)
        ));
    }

    #[test]
    fn signs_and_verifies_presentation() {
        let secret_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let signed = sign_presentation(example_presentation(), secret_key).unwrap();
        let signature = signed.cred_signature.as_ref().unwrap();

        assert_eq!(signature.scheme, "ed25519");
        assert_eq!(
            signature.public_key,
            public_key_from_secret_hex(secret_key).unwrap()
        );
        verify_presentation_signature(&signed).unwrap();

        let value = serde_json::to_value(&signed).unwrap();
        validate_cred_artifact(&value).unwrap();
    }

    #[test]
    fn rejects_tampered_presentation_signature() {
        let signed = sign_presentation(
            example_presentation(),
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let mut tampered = signed;
        tampered.app_id = "app:clout:local".to_owned();

        assert!(matches!(
            verify_presentation_signature(&tampered),
            Err(CredError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn embedded_artifact_hash_mismatch_is_rejected() {
        let mut presentation = example_presentation();
        presentation.artifacts[0].disclosure = "embedded".to_owned();
        presentation.artifacts[0].artifact = Some(serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "witness.signed_attestation",
            "attestation": { "hash": "f2ca1bb6c7e907d06dafe4687e579fce7d08f0f2514ee1f2787e118c67d84fbf" }
        }));
        // artifact_hash is still "1111..." which won't match the embedded artifact

        assert!(matches!(
            presentation.validate(),
            Err(CredError::EmbeddedArtifactHashMismatch)
        ));
    }

    #[test]
    fn embedded_disclosure_requires_artifact() {
        let mut presentation = example_presentation();
        presentation.artifacts[0].disclosure = "embedded".to_owned();
        presentation.artifacts[0].artifact = None;
        presentation.artifacts[0].record_id = None;

        assert!(matches!(
            presentation.validate(),
            Err(CredError::EmbeddedArtifactMissing)
        ));
    }

    #[test]
    fn reference_disclosure_requires_record_id() {
        let mut presentation = example_presentation();
        presentation.artifacts[0].disclosure = "reference".to_owned();
        presentation.artifacts[0].record_id = None;

        assert!(matches!(
            presentation.validate(),
            Err(CredError::EmptyField("presented_artifact.record_id"))
        ));
    }

    #[test]
    fn embedded_artifact_with_matching_hash_passes() {
        let artifact = serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "witness.signed_attestation",
            "attestation": { "hash": "f2ca1bb6c7e907d06dafe4687e579fce7d08f0f2514ee1f2787e118c67d84fbf" }
        });
        let hash = canonical_hash_hex(&artifact).unwrap();

        let mut presentation = example_presentation();
        presentation.artifacts[0].disclosure = "embedded".to_owned();
        presentation.artifacts[0].artifact = Some(artifact);
        presentation.artifacts[0].artifact_hash = hash;
        presentation.artifacts[0].record_id = None;

        presentation.validate().unwrap();
    }

    #[test]
    fn verify_grant_signature_accepts_unsigned_grant() {
        let grant = example_grant();
        assert!(grant.cred_signature.is_none());
        verify_grant_signature(&grant).unwrap();
    }

    #[test]
    fn verify_grant_signature_accepts_validly_signed_grant() {
        let secret_key = "3333333333333333333333333333333333333333333333333333333333333333";
        let grant = sign_grant(example_grant(), secret_key).unwrap();
        verify_grant_signature(&grant).unwrap();
    }

    #[test]
    fn verify_grant_signature_rejects_tampered_grant() {
        let secret_key = "3333333333333333333333333333333333333333333333333333333333333333";
        let mut grant = sign_grant(example_grant(), secret_key).unwrap();
        grant.app_id = "app:clout:local".to_owned();
        assert!(matches!(
            verify_grant_signature(&grant),
            Err(CredError::GrantSignatureVerificationFailed)
        ));
    }

    #[test]
    fn enforce_grant_requires_app_signature_when_grant_binds_pubkey() {
        let secret_key = "4444444444444444444444444444444444444444444444444444444444444444";
        let app_pubkey = public_key_from_secret_hex(secret_key).unwrap();
        let mut grant = example_grant();
        grant.app_pubkey = Some(app_pubkey);

        // Unsigned request must be rejected.
        let request = example_request();
        assert!(matches!(
            enforce_grant(
                &grant,
                &request,
                GrantUsage {
                    now: 1767225601,
                    uses_so_far: 0,
                },
            ),
            Err(CredError::MissingRequestSignature)
        ));

        // Signed request must pass.
        let signed_request = sign_action_request(example_request(), secret_key).unwrap();
        enforce_grant(
            &grant,
            &signed_request,
            GrantUsage {
                now: 1767225601,
                uses_so_far: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn enforce_grant_rejects_request_signed_by_wrong_key() {
        let app_secret = "4444444444444444444444444444444444444444444444444444444444444444";
        let app_pubkey = public_key_from_secret_hex(app_secret).unwrap();
        let mut grant = example_grant();
        grant.app_pubkey = Some(app_pubkey);

        // Sign with a different key.
        let wrong_key = "5555555555555555555555555555555555555555555555555555555555555555";
        let signed_request = sign_action_request(example_request(), wrong_key).unwrap();

        assert!(matches!(
            enforce_grant(
                &grant,
                &signed_request,
                GrantUsage {
                    now: 1767225601,
                    uses_so_far: 0,
                },
            ),
            Err(CredError::RequestSignatureVerificationFailed)
        ));
    }

    #[test]
    fn enforce_grant_allows_unsigned_request_when_grant_has_no_pubkey() {
        let grant = example_grant();
        assert!(grant.app_pubkey.is_none());
        let request = example_request();
        assert!(request.app_signature.is_none());
        enforce_grant(
            &grant,
            &request,
            GrantUsage {
                now: 1767225601,
                uses_so_far: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn external_reference_records_require_uri() {
        let record = artifact_record(
            "record-1".to_owned(),
            "cred:local:test".to_owned(),
            "witness.signed_attestation".to_owned(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            None,
            "selective".to_owned(),
            "external_reference".to_owned(),
            None,
            1,
            None,
        );

        assert!(matches!(
            record.validate(),
            Err(CredError::EmptyField("artifact_uri"))
        ));
    }

    fn example_grant() -> CredPermissionGrant {
        CredPermissionGrant {
            contract_version: CONTRACT_VERSION.to_owned(),
            artifact_type: "cred.permission_grant".to_owned(),
            grant_id: "grant-prestige-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            app_id: "app:prestige:local".to_owned(),
            app_pubkey: None,
            capabilities: vec![
                "freebird.present".to_owned(),
                "witness.timestamp".to_owned(),
            ],
            constraints: CredGrantConstraints {
                allowed_audiences: Some(vec!["prestige".to_owned()]),
                allowed_artifact_types: Some(vec!["witness.signed_attestation".to_owned()]),
                max_uses: Some(3),
                expires_at: Some(4102444800),
                allow_export: Some(false),
            },
            human_approval: "per_use".to_owned(),
            created_at: 1767225600,
            cred_signature: None,
        }
    }

    fn example_request() -> CredActionRequest {
        CredActionRequest {
            contract_version: CONTRACT_VERSION.to_owned(),
            artifact_type: "cred.action_request".to_owned(),
            request_id: "request-vote-1".to_owned(),
            app_id: "app:prestige:local".to_owned(),
            grant_id: Some("grant-prestige-1".to_owned()),
            requested_at: 1767225601,
            purpose: Some("cast vote".to_owned()),
            actions: vec![
                CredAction {
                    kind: "freebird.present".to_owned(),
                    audience: Some("prestige".to_owned()),
                    semantic: Some("consuming_verify".to_owned()),
                    artifact_type: None,
                    hash: None,
                    payload_hash: None,
                    pool_id: None,
                    reason: None,
                },
                CredAction {
                    kind: "witness.timestamp".to_owned(),
                    audience: None,
                    semantic: None,
                    artifact_type: Some("witness.signed_attestation".to_owned()),
                    hash: Some(
                        "f2ca1bb6c7e907d06dafe4687e579fce7d08f0f2514ee1f2787e118c67d84fbf"
                            .to_owned(),
                    ),
                    payload_hash: None,
                    pool_id: None,
                    reason: None,
                },
            ],
            app_signature: None,
        }
    }

    fn example_presentation() -> CredPresentation {
        CredPresentation {
            contract_version: CONTRACT_VERSION.to_owned(),
            artifact_type: "cred.presentation".to_owned(),
            presentation_id: "presentation-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            request_id: "request-vote-1".to_owned(),
            grant_id: Some("grant-prestige-1".to_owned()),
            app_id: "app:prestige:local".to_owned(),
            created_at: 1767225602,
            artifacts: vec![PresentedArtifact {
                artifact_type: "witness.signed_attestation".to_owned(),
                artifact_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
                record_id: Some("record-1".to_owned()),
                disclosure: "reference".to_owned(),
                artifact: None,
            }],
            request_binding_hash: None,
            cred_signature: None,
        }
    }
}
