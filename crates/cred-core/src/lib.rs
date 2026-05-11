use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
            serde_json::from_value::<CredManifest>(value.clone())?;
        }
        CredArtifactKind::PermissionGrant => {
            serde_json::from_value::<CredPermissionGrant>(value.clone())?;
        }
        CredArtifactKind::ActionRequest => {
            serde_json::from_value::<CredActionRequest>(value.clone())?;
        }
        CredArtifactKind::Presentation => {
            serde_json::from_value::<CredPresentation>(value.clone())?;
        }
        CredArtifactKind::ArtifactRecord => {
            serde_json::from_value::<CredArtifactRecord>(value.clone())?;
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

pub fn artifact_record(
    record_id: String,
    cred_id: String,
    stored_artifact_type: String,
    artifact_hash: String,
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
}
