use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use cred_core::{
    artifact_type, canonical_hash_hex, canonical_json, CredArtifactRecord, CredPermissionGrant,
    CredPresentation,
};
use fs2::FileExt;
use scrypt::{scrypt, Params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const RECORDS_FILE: &str = "records.jsonl";
const GRANTS_FILE: &str = "grants.jsonl";
const GRANT_APPROVALS_FILE: &str = "grant_approvals.jsonl";
const PRESENTATION_AUDIT_FILE: &str = "presentation_audit.jsonl";
const BLOBS_DIR: &str = "blobs";
const BLOB_URI_PREFIX: &str = "cred-vault://blobs/";
const BLOB_ARTIFACT_TYPE: &str = "cred.encrypted_artifact_blob";
const ENCRYPTION_SCHEME: &str = "xchacha20poly1305+scrypt";
const SALT_BYTES: usize = 16;
const XCHACHA_NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Cred record: {0}")]
    Cred(#[from] cred_core::CredError),
    #[error("invalid JSON record at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("failed to encode record JSON: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("store file is busy; another writer holds the lock")]
    StoreBusy,
    #[error("record already exists: {0}")]
    DuplicateRecord(String),
    #[error("grant already exists: {0}")]
    DuplicateGrant(String),
    #[error("grant approval already exists: {0}")]
    DuplicateGrantApproval(String),
    #[error("presentation audit entry already exists: {0}")]
    DuplicatePresentation(String),
    #[error("HOME is not set; pass --store")]
    MissingHome,
    #[error("encrypted artifact requires local_encrypted custody")]
    NotLocalEncrypted,
    #[error("record artifact_uri does not point to its Cred vault blob")]
    InvalidVaultUri,
    #[error("vault passphrase is required")]
    MissingVaultPassphrase,
    #[error("encrypted artifact hash mismatch")]
    ArtifactHashMismatch,
    #[error("failed to encrypt or decrypt vault blob")]
    Crypto,
    #[error("invalid vault blob: {0}")]
    InvalidVaultBlob(String),
    #[error("invalid vault KDF parameters")]
    InvalidKdfParams,
    #[error("failed to derive vault key")]
    Kdf,
    #[error("invalid hex in vault blob field {field}: {source}")]
    Hex {
        field: &'static str,
        source: hex::FromHexError,
    },
}

#[derive(Debug, Clone)]
pub struct RecordStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredGrant {
    pub contract_version: String,
    pub artifact_type: String,
    pub grant_id: String,
    pub cred_id: String,
    pub app_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_pubkey: Option<String>,
    pub capabilities: Vec<String>,
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
    pub human_approval: String,
    pub grant_hash: String,
    pub created_at: u64,
    pub imported_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantApproval {
    pub contract_version: String,
    pub artifact_type: String,
    pub approval_id: String,
    pub grant_id: String,
    pub grant_hash: String,
    pub cred_id: String,
    pub app_id: String,
    pub decision: String,
    pub capabilities: Vec<String>,
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
    pub human_approval: String,
    pub summary: Vec<String>,
    pub warnings: Vec<String>,
    pub reviewed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PresentationAuditEntry {
    pub contract_version: String,
    pub artifact_type: String,
    pub presentation_id: String,
    pub presentation_hash: String,
    pub cred_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub app_id: String,
    pub presented_at: u64,
    pub artifacts: Vec<PresentationAuditArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PresentationAuditArtifact {
    pub artifact_type: String,
    pub artifact_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    pub disclosure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedArtifactBlob {
    pub contract_version: String,
    pub artifact_type: String,
    pub stored_artifact_type: String,
    pub plaintext_hash: String,
    pub encryption: VaultEncryption,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultEncryption {
    pub scheme: String,
    pub kdf: String,
    pub scrypt_log_n: u8,
    pub scrypt_r: u32,
    pub scrypt_p: u32,
    pub salt_hex: String,
    pub nonce_hex: String,
}

impl RecordStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn default_root() -> Result<PathBuf, StoreError> {
        if let Some(path) = env::var_os("CRED_STORE_DIR") {
            return Ok(PathBuf::from(path));
        }

        let home = env::var_os("HOME").ok_or(StoreError::MissingHome)?;
        Ok(PathBuf::from(home).join(".local/share/cred"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn vault_blob_uri(record_id: &str) -> String {
        format!("{BLOB_URI_PREFIX}{}", blob_filename(record_id))
    }

    pub fn append_record(&self, record: &CredArtifactRecord) -> Result<(), StoreError> {
        record.validate()?;
        if self.get_record(&record.record_id)?.is_some() {
            return Err(StoreError::DuplicateRecord(record.record_id.clone()));
        }

        fs::create_dir_all(&self.root)?;
        self.append_json_line(self.records_path(), record)
    }

    pub fn list_records(&self) -> Result<Vec<CredArtifactRecord>, StoreError> {
        let path = self.records_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        lock_shared(&file)?;
        let mut reader = BufReader::new(file);
        let mut records = Vec::new();

        for (index, line) in reader.by_ref().lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: CredArtifactRecord =
                serde_json::from_str(&line).map_err(|source| StoreError::Json {
                    line: index + 1,
                    source,
                })?;
            record.validate()?;
            records.push(record);
        }

        let file = reader.into_inner();
        file.unlock()?;

        Ok(records)
    }

    pub fn get_record(&self, record_id: &str) -> Result<Option<CredArtifactRecord>, StoreError> {
        Ok(self
            .list_records()?
            .into_iter()
            .find(|record| record.record_id == record_id))
    }

    pub fn append_grant(&self, grant: &StoredGrant) -> Result<(), StoreError> {
        if self.get_grant(&grant.grant_id)?.is_some() {
            return Err(StoreError::DuplicateGrant(grant.grant_id.clone()));
        }
        self.append_json_line(self.grants_path(), grant)
    }

    pub fn list_grants(&self) -> Result<Vec<StoredGrant>, StoreError> {
        self.read_json_lines(self.grants_path())
    }

    pub fn get_grant(&self, grant_id: &str) -> Result<Option<StoredGrant>, StoreError> {
        Ok(self
            .list_grants()?
            .into_iter()
            .find(|grant| grant.grant_id == grant_id))
    }

    pub fn append_grant_approval(&self, approval: &GrantApproval) -> Result<(), StoreError> {
        if self.get_grant_approval(&approval.approval_id)?.is_some() {
            return Err(StoreError::DuplicateGrantApproval(
                approval.approval_id.clone(),
            ));
        }
        self.append_json_line(self.grant_approvals_path(), approval)
    }

    pub fn list_grant_approvals(&self) -> Result<Vec<GrantApproval>, StoreError> {
        self.read_json_lines(self.grant_approvals_path())
    }

    pub fn get_grant_approval(
        &self,
        approval_id: &str,
    ) -> Result<Option<GrantApproval>, StoreError> {
        Ok(self
            .list_grant_approvals()?
            .into_iter()
            .find(|approval| approval.approval_id == approval_id))
    }

    pub fn append_presentation_audit(
        &self,
        entry: &PresentationAuditEntry,
    ) -> Result<(), StoreError> {
        if self
            .list_presentation_audit()?
            .into_iter()
            .any(|candidate| candidate.presentation_id == entry.presentation_id)
        {
            return Err(StoreError::DuplicatePresentation(
                entry.presentation_id.clone(),
            ));
        }
        self.append_json_line(self.presentation_audit_path(), entry)
    }

    pub fn list_presentation_audit(&self) -> Result<Vec<PresentationAuditEntry>, StoreError> {
        self.read_json_lines(self.presentation_audit_path())
    }

    /// Count prior presentation audit entries for a given grant_id.
    ///
    /// This is the store-derived usage count used to enforce `max_uses`
    /// on permission grants, replacing the previous caller-supplied
    /// `uses_so_far` parameter. Presentations made without a grant
    /// (`grant_id == None`) are not counted.
    pub fn count_presentations_for_grant(&self, grant_id: &str) -> Result<u64, StoreError> {
        Ok(self
            .list_presentation_audit()?
            .into_iter()
            .filter(|entry| entry.grant_id.as_deref() == Some(grant_id))
            .count() as u64)
    }

    pub fn write_encrypted_artifact(
        &self,
        record: &CredArtifactRecord,
        artifact: &serde_json::Value,
        passphrase: &str,
    ) -> Result<(), StoreError> {
        if passphrase.is_empty() {
            return Err(StoreError::MissingVaultPassphrase);
        }
        if record.custody != "local_encrypted" {
            return Err(StoreError::NotLocalEncrypted);
        }
        record.validate()?;
        self.ensure_expected_vault_uri(record)?;
        let plaintext_hash = canonical_hash_hex(artifact)?;
        if plaintext_hash != record.artifact_hash {
            return Err(StoreError::ArtifactHashMismatch);
        }
        let stored_artifact_type = artifact_type(artifact)?.to_owned();
        if stored_artifact_type != record.stored_artifact_type {
            return Err(StoreError::InvalidVaultBlob(
                "stored_artifact_type does not match plaintext artifact_type".to_owned(),
            ));
        }

        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; XCHACHA_NONCE_BYTES];
        fill_random(&mut salt)?;
        fill_random(&mut nonce)?;

        let mut key = derive_vault_key(passphrase, &salt, scrypt_params()?)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut plaintext = canonical_json(artifact)?;
        let aad = vault_aad(record);
        let ciphertext = match cipher.encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: aad.as_bytes(),
            },
        ) {
            Ok(ciphertext) => ciphertext,
            Err(_) => {
                plaintext.zeroize();
                key.zeroize();
                return Err(StoreError::Crypto);
            }
        };
        plaintext.zeroize();
        key.zeroize();

        let blob = EncryptedArtifactBlob {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: BLOB_ARTIFACT_TYPE.to_owned(),
            stored_artifact_type,
            plaintext_hash,
            encryption: VaultEncryption {
                scheme: ENCRYPTION_SCHEME.to_owned(),
                kdf: "scrypt".to_owned(),
                scrypt_log_n: SCRYPT_LOG_N,
                scrypt_r: SCRYPT_R,
                scrypt_p: SCRYPT_P,
                salt_hex: hex::encode(salt),
                nonce_hex: hex::encode(nonce),
            },
            ciphertext_hex: hex::encode(ciphertext),
        };

        let path = self.vault_blob_path(record)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path)?;
        serde_json::to_writer_pretty(&mut file, &blob).map_err(StoreError::Encode)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    pub fn read_encrypted_artifact(
        &self,
        record: &CredArtifactRecord,
        passphrase: &str,
    ) -> Result<serde_json::Value, StoreError> {
        if passphrase.is_empty() {
            return Err(StoreError::MissingVaultPassphrase);
        }
        if record.custody != "local_encrypted" {
            return Err(StoreError::NotLocalEncrypted);
        }
        record.validate()?;
        self.ensure_expected_vault_uri(record)?;

        let blob_text = fs::read_to_string(self.vault_blob_path(record)?)?;
        let blob: EncryptedArtifactBlob = serde_json::from_str(&blob_text)
            .map_err(|source| StoreError::Json { line: 1, source })?;
        validate_blob(&blob, record)?;

        let salt = decode_blob_hex(&blob.encryption.salt_hex, "salt_hex")?;
        let nonce = decode_blob_hex(&blob.encryption.nonce_hex, "nonce_hex")?;
        if salt.len() != SALT_BYTES || nonce.len() != XCHACHA_NONCE_BYTES {
            return Err(StoreError::InvalidVaultBlob(
                "unexpected salt or nonce length".to_owned(),
            ));
        }
        let ciphertext = decode_blob_hex(&blob.ciphertext_hex, "ciphertext_hex")?;
        let params = Params::new(
            blob.encryption.scrypt_log_n,
            blob.encryption.scrypt_r,
            blob.encryption.scrypt_p,
        )
        .map_err(|_| StoreError::InvalidKdfParams)?;
        let mut key = derive_vault_key(passphrase, &salt, params)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let aad = vault_aad(record);
        let mut plaintext = match cipher.decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_ref(),
                aad: aad.as_bytes(),
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                key.zeroize();
                return Err(StoreError::Crypto);
            }
        };
        key.zeroize();

        let value: serde_json::Value = match serde_json::from_slice(&plaintext) {
            Ok(value) => value,
            Err(source) => {
                plaintext.zeroize();
                return Err(StoreError::Json { line: 1, source });
            }
        };
        plaintext.zeroize();
        if canonical_hash_hex(&value)? != record.artifact_hash {
            return Err(StoreError::ArtifactHashMismatch);
        }
        Ok(value)
    }

    pub fn encrypted_artifact_exists(
        &self,
        record: &CredArtifactRecord,
    ) -> Result<bool, StoreError> {
        if record.custody != "local_encrypted" {
            return Ok(false);
        }
        Ok(self.vault_blob_path(record)?.exists())
    }

    fn ensure_expected_vault_uri(&self, record: &CredArtifactRecord) -> Result<(), StoreError> {
        if record.artifact_uri.as_deref() == Some(&Self::vault_blob_uri(&record.record_id)) {
            Ok(())
        } else {
            Err(StoreError::InvalidVaultUri)
        }
    }

    fn vault_blob_path(&self, record: &CredArtifactRecord) -> Result<PathBuf, StoreError> {
        self.ensure_expected_vault_uri(record)?;
        Ok(self
            .root
            .join(BLOBS_DIR)
            .join(blob_filename(&record.record_id)))
    }

    fn records_path(&self) -> PathBuf {
        self.root.join(RECORDS_FILE)
    }

    fn grants_path(&self) -> PathBuf {
        self.root.join(GRANTS_FILE)
    }

    fn grant_approvals_path(&self) -> PathBuf {
        self.root.join(GRANT_APPROVALS_FILE)
    }

    fn presentation_audit_path(&self) -> PathBuf {
        self.root.join(PRESENTATION_AUDIT_FILE)
    }

    fn append_json_line<T: Serialize>(&self, path: PathBuf, value: &T) -> Result<(), StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        lock_exclusive(&file)?;

        let result: Result<(), StoreError> = (|| {
            serde_json::to_writer(&mut file, value).map_err(StoreError::Encode)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        })();
        let unlock_result = file.unlock().map_err(StoreError::Io);

        result?;
        unlock_result?;
        Ok(())
    }

    fn read_json_lines<T: DeserializeOwned>(&self, path: PathBuf) -> Result<Vec<T>, StoreError> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        lock_shared(&file)?;
        let mut reader = BufReader::new(file);
        let mut values = Vec::new();

        for (index, line) in reader.by_ref().lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            values.push(
                serde_json::from_str(&line).map_err(|source| StoreError::Json {
                    line: index + 1,
                    source,
                })?,
            );
        }

        let file = reader.into_inner();
        file.unlock()?;

        Ok(values)
    }
}

fn lock_exclusive(file: &File) -> Result<(), StoreError> {
    file.try_lock_exclusive().map_err(lock_error)
}

fn lock_shared(file: &File) -> Result<(), StoreError> {
    file.try_lock_shared().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => StoreError::StoreBusy,
        std::fs::TryLockError::Error(error) => StoreError::Io(error),
    })
}

fn lock_error(error: std::io::Error) -> StoreError {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        StoreError::StoreBusy
    } else {
        StoreError::Io(error)
    }
}

impl StoredGrant {
    pub fn from_grant(
        grant: &CredPermissionGrant,
        grant_hash: String,
        source_uri: Option<String>,
        imported_at: u64,
    ) -> Self {
        Self {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.stored_grant".to_owned(),
            grant_id: grant.grant_id.clone(),
            cred_id: grant.cred_id.clone(),
            app_id: grant.app_id.clone(),
            app_pubkey: grant.app_pubkey.clone(),
            capabilities: grant.capabilities.clone(),
            allowed_audiences: grant.constraints.allowed_audiences.clone(),
            allowed_artifact_types: grant.constraints.allowed_artifact_types.clone(),
            max_uses: grant.constraints.max_uses,
            expires_at: grant.constraints.expires_at,
            allow_export: grant.constraints.allow_export,
            human_approval: grant.human_approval.clone(),
            grant_hash,
            created_at: grant.created_at,
            imported_at,
            source_uri,
        }
    }
}

impl GrantApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn from_grant(
        grant: &CredPermissionGrant,
        grant_hash: String,
        decision: String,
        approval_id: String,
        summary: Vec<String>,
        warnings: Vec<String>,
        reviewer: Option<String>,
        notes: Option<String>,
        source_uri: Option<String>,
        reviewed_at: u64,
    ) -> Self {
        Self {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.grant_approval".to_owned(),
            approval_id,
            grant_id: grant.grant_id.clone(),
            grant_hash,
            cred_id: grant.cred_id.clone(),
            app_id: grant.app_id.clone(),
            decision,
            capabilities: grant.capabilities.clone(),
            allowed_audiences: grant.constraints.allowed_audiences.clone(),
            allowed_artifact_types: grant.constraints.allowed_artifact_types.clone(),
            max_uses: grant.constraints.max_uses,
            expires_at: grant.constraints.expires_at,
            allow_export: grant.constraints.allow_export,
            human_approval: grant.human_approval.clone(),
            summary,
            warnings,
            reviewed_at,
            reviewer,
            notes,
            source_uri,
        }
    }
}

impl PresentationAuditEntry {
    pub fn from_presentation(
        presentation: &CredPresentation,
        presentation_hash: String,
        approval_id: Option<String>,
    ) -> Self {
        Self {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.presentation_audit".to_owned(),
            presentation_id: presentation.presentation_id.clone(),
            presentation_hash,
            cred_id: presentation.cred_id.clone(),
            request_id: presentation.request_id.clone(),
            grant_id: presentation.grant_id.clone(),
            approval_id,
            app_id: presentation.app_id.clone(),
            presented_at: presentation.created_at,
            artifacts: presentation
                .artifacts
                .iter()
                .map(|artifact| PresentationAuditArtifact {
                    artifact_type: artifact.artifact_type.clone(),
                    artifact_hash: artifact.artifact_hash.clone(),
                    record_id: artifact.record_id.clone(),
                    disclosure: artifact.disclosure.clone(),
                })
                .collect(),
        }
    }
}

fn scrypt_params() -> Result<Params, StoreError> {
    Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P).map_err(|_| StoreError::InvalidKdfParams)
}

fn derive_vault_key(
    passphrase: &str,
    salt: &[u8],
    params: Params,
) -> Result<[u8; KEY_BYTES], StoreError> {
    let mut key = [0_u8; KEY_BYTES];
    scrypt(passphrase.as_bytes(), salt, &params, &mut key).map_err(|_| StoreError::Kdf)?;
    Ok(key)
}

fn fill_random(bytes: &mut [u8]) -> Result<(), StoreError> {
    File::open("/dev/urandom")?.read_exact(bytes)?;
    Ok(())
}

fn blob_filename(record_id: &str) -> String {
    format!("{}.json", hex::encode(Sha256::digest(record_id.as_bytes())))
}

fn vault_aad(record: &CredArtifactRecord) -> String {
    format!(
        "cred-vault-v1:{}:{}:{}",
        record.record_id, record.stored_artifact_type, record.artifact_hash
    )
}

fn validate_blob(
    blob: &EncryptedArtifactBlob,
    record: &CredArtifactRecord,
) -> Result<(), StoreError> {
    if blob.contract_version != "sophia/v1"
        || blob.artifact_type != BLOB_ARTIFACT_TYPE
        || blob.stored_artifact_type != record.stored_artifact_type
        || blob.plaintext_hash != record.artifact_hash
        || blob.encryption.scheme != ENCRYPTION_SCHEME
        || blob.encryption.kdf != "scrypt"
    {
        return Err(StoreError::InvalidVaultBlob(
            "blob header does not match record".to_owned(),
        ));
    }
    Ok(())
}

fn decode_blob_hex(value: &str, field: &'static str) -> Result<Vec<u8>, StoreError> {
    hex::decode(value).map_err(|source| StoreError::Hex { field, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cred_core::{artifact_record, CredGrantConstraints, PresentedArtifact};
    use proptest::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn appends_lists_and_gets_records() {
        let root = temp_store_root("append-list-get");
        let store = RecordStore::new(&root);
        let record = sample_record("record-1");

        store.append_record(&record).unwrap();

        let records = store.list_records().unwrap();
        assert_eq!(records, vec![record.clone()]);
        assert_eq!(store.get_record("record-1").unwrap(), Some(record));
        assert_eq!(store.get_record("missing").unwrap(), None);

        cleanup(root);
    }

    #[test]
    fn rejects_duplicate_record_ids() {
        let root = temp_store_root("duplicates");
        let store = RecordStore::new(&root);
        let record = sample_record("record-1");

        store.append_record(&record).unwrap();
        let err = store.append_record(&record).unwrap_err();

        assert!(matches!(err, StoreError::DuplicateRecord(id) if id == "record-1"));

        cleanup(root);
    }

    #[test]
    fn append_returns_store_busy_when_records_file_is_locked() {
        let root = temp_store_root("busy-records");
        fs::create_dir_all(&root).unwrap();
        let locked_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(root.join(RECORDS_FILE))
            .unwrap();
        locked_file.lock_exclusive().unwrap();

        let store = RecordStore::new(&root);
        let err = store.append_record(&sample_record("record-1")).unwrap_err();

        assert!(matches!(err, StoreError::StoreBusy));
        locked_file.unlock().unwrap();
        cleanup(root);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn prop_append_returns_store_busy_when_records_file_is_locked(record_id in "[a-z]{1,20}") {
            let root = temp_store_root("prop-busy-records");
            fs::create_dir_all(&root).unwrap();
            let locked_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(root.join(RECORDS_FILE))
                .unwrap();
            locked_file.lock_exclusive().unwrap();

            let store = RecordStore::new(&root);
            let err = store.append_record(&sample_record(&record_id)).unwrap_err();

            prop_assert!(matches!(err, StoreError::StoreBusy));
            locked_file.unlock().unwrap();
            cleanup(root);
        }

        #[test]
        fn prop_duplicate_record_ids_are_rejected(record_id in "[a-z]{1,20}") {
            let root = temp_store_root("prop-duplicates");
            let store = RecordStore::new(&root);
            let record = sample_record(&record_id);

            store.append_record(&record).unwrap();
            let err = store.append_record(&record).unwrap_err();

            prop_assert!(matches!(err, StoreError::DuplicateRecord(id) if id == record_id));
            cleanup(root);
        }

        #[test]
        fn prop_sequential_appends_all_persist_in_order(
            record_ids in proptest::collection::vec("[a-z]{1,20}", 1..=20)
                .prop_filter("record ids must be unique", |ids| {
                    let mut sorted = ids.clone();
                    sorted.sort();
                    sorted.dedup();
                    sorted.len() == ids.len()
                })
        ) {
            let root = temp_store_root("prop-sequential-append");
            let store = RecordStore::new(&root);
            let records: Vec<_> = record_ids.iter().map(|id| sample_record(id)).collect();

            for record in &records {
                store.append_record(record).unwrap();
            }

            prop_assert_eq!(store.list_records().unwrap(), records);
            cleanup(root);
        }
    }

    #[test]
    fn synced_locked_append_still_persists_valid_jsonl() {
        let root = temp_store_root("synced-append");
        let store = RecordStore::new(&root);
        let record_1 = sample_record("record-1");
        let record_2 = sample_record("record-2");

        store.append_record(&record_1).unwrap();
        store.append_record(&record_2).unwrap();

        assert_eq!(store.list_records().unwrap(), vec![record_1, record_2]);
        cleanup(root);
    }

    #[test]
    fn appends_lists_and_gets_grants() {
        let root = temp_store_root("grants");
        let store = RecordStore::new(&root);
        let grant = sample_grant();
        let grant_hash = canonical_hash_hex(&serde_json::to_value(&grant).unwrap()).unwrap();
        let stored = StoredGrant::from_grant(
            &grant,
            grant_hash.clone(),
            Some("examples/permission-grant.json".to_owned()),
            2,
        );

        store.append_grant(&stored).unwrap();

        assert_eq!(store.list_grants().unwrap(), vec![stored.clone()]);
        assert_eq!(store.get_grant("grant-1").unwrap(), Some(stored.clone()));
        assert_eq!(store.get_grant("missing").unwrap(), None);
        assert_eq!(stored.grant_hash, grant_hash);
        assert_eq!(
            stored.allowed_artifact_types.as_deref(),
            Some(&["witness.signed_attestation".to_owned()][..])
        );

        cleanup(root);
    }

    #[test]
    fn rejects_duplicate_grant_ids() {
        let root = temp_store_root("duplicate-grants");
        let store = RecordStore::new(&root);
        let grant = sample_grant();
        let stored = StoredGrant::from_grant(
            &grant,
            canonical_hash_hex(&serde_json::to_value(&grant).unwrap()).unwrap(),
            None,
            2,
        );

        store.append_grant(&stored).unwrap();
        let err = store.append_grant(&stored).unwrap_err();

        assert!(matches!(err, StoreError::DuplicateGrant(id) if id == "grant-1"));

        cleanup(root);
    }

    #[test]
    fn appends_lists_and_gets_grant_approvals() {
        let root = temp_store_root("grant-approvals");
        let store = RecordStore::new(&root);
        let grant = sample_grant();
        let grant_hash = canonical_hash_hex(&serde_json::to_value(&grant).unwrap()).unwrap();
        let approval = GrantApproval::from_grant(
            &grant,
            grant_hash.clone(),
            "approved".to_owned(),
            "approval-1".to_owned(),
            vec!["App app:prestige:test can request witness.present_attestation.".to_owned()],
            vec!["Grant does not bind an app public key.".to_owned()],
            Some("local-user".to_owned()),
            Some("reviewed in smoke".to_owned()),
            Some("examples/permission-grant.json".to_owned()),
            2,
        );

        store.append_grant_approval(&approval).unwrap();

        assert_eq!(
            store.list_grant_approvals().unwrap(),
            vec![approval.clone()]
        );
        assert_eq!(
            store.get_grant_approval("approval-1").unwrap(),
            Some(approval.clone())
        );
        assert_eq!(store.get_grant_approval("missing").unwrap(), None);
        assert_eq!(approval.grant_hash, grant_hash);

        cleanup(root);
    }

    #[test]
    fn rejects_duplicate_grant_approval_ids() {
        let root = temp_store_root("duplicate-grant-approvals");
        let store = RecordStore::new(&root);
        let grant = sample_grant();
        let approval = GrantApproval::from_grant(
            &grant,
            canonical_hash_hex(&serde_json::to_value(&grant).unwrap()).unwrap(),
            "approved".to_owned(),
            "approval-1".to_owned(),
            Vec::new(),
            Vec::new(),
            None,
            None,
            None,
            2,
        );

        store.append_grant_approval(&approval).unwrap();
        let err = store.append_grant_approval(&approval).unwrap_err();

        assert!(matches!(err, StoreError::DuplicateGrantApproval(id) if id == "approval-1"));

        cleanup(root);
    }

    #[test]
    fn appends_lists_and_rejects_duplicate_presentation_audit_entries() {
        let root = temp_store_root("presentation-audit");
        let store = RecordStore::new(&root);
        let presentation = sample_presentation();
        let presentation_hash =
            canonical_hash_hex(&serde_json::to_value(&presentation).unwrap()).unwrap();
        let entry = PresentationAuditEntry::from_presentation(
            &presentation,
            presentation_hash,
            Some("approval-1".to_owned()),
        );

        store.append_presentation_audit(&entry).unwrap();

        assert_eq!(
            store.list_presentation_audit().unwrap(),
            vec![entry.clone()]
        );
        assert_eq!(entry.artifacts[0].record_id.as_deref(), Some("record-1"));
        assert_eq!(entry.artifacts[0].disclosure, "reference");
        assert_eq!(entry.approval_id.as_deref(), Some("approval-1"));
        let err = store.append_presentation_audit(&entry).unwrap_err();
        assert!(matches!(err, StoreError::DuplicatePresentation(id) if id == "presentation-1"));

        cleanup(root);
    }

    #[test]
    fn counts_presentations_for_grant() {
        let root = temp_store_root("count-presentations");
        let store = RecordStore::new(&root);

        // Three presentations under grant-1, one under grant-2, one without a grant.
        for (id, grant_id) in [
            ("pres-1", Some("grant-1")),
            ("pres-2", Some("grant-1")),
            ("pres-3", Some("grant-1")),
            ("pres-4", Some("grant-2")),
            ("pres-5", None),
        ] {
            let mut presentation = sample_presentation();
            presentation.presentation_id = id.to_owned();
            presentation.grant_id = grant_id.map(|g| g.to_owned());
            let hash =
                canonical_hash_hex(&serde_json::to_value(&presentation).unwrap()).unwrap();
            let entry = PresentationAuditEntry::from_presentation(&presentation, hash, None);
            store.append_presentation_audit(&entry).unwrap();
        }

        assert_eq!(store.count_presentations_for_grant("grant-1").unwrap(), 3);
        assert_eq!(store.count_presentations_for_grant("grant-2").unwrap(), 1);
        assert_eq!(store.count_presentations_for_grant("grant-absent").unwrap(), 0);

        cleanup(root);
    }

    #[test]
    fn reports_invalid_json_lines() {
        let root = temp_store_root("invalid-json");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(RECORDS_FILE), "{not-json}\n").unwrap();

        let err = RecordStore::new(&root).list_records().unwrap_err();

        assert!(matches!(err, StoreError::Json { line: 1, .. }));

        cleanup(root);
    }

    #[test]
    fn encrypts_and_decrypts_local_artifact_blob() {
        let root = temp_store_root("encrypted-blob");
        let store = RecordStore::new(&root);
        let artifact = sample_artifact();
        let record = encrypted_record("record-secret-1", canonical_hash_hex(&artifact).unwrap());

        store
            .write_encrypted_artifact(&record, &artifact, "correct horse")
            .unwrap();
        store.append_record(&record).unwrap();

        let blob_path = store.vault_blob_path(&record).unwrap();
        let blob_text = fs::read_to_string(&blob_path).unwrap();
        assert!(blob_text.contains(BLOB_ARTIFACT_TYPE));
        assert!(!blob_text.contains("tree_size"));

        let decrypted = store
            .read_encrypted_artifact(&record, "correct horse")
            .unwrap();
        assert_eq!(decrypted, artifact);

        cleanup(root);
    }

    #[test]
    fn rejects_wrong_vault_passphrase() {
        let root = temp_store_root("wrong-passphrase");
        let store = RecordStore::new(&root);
        let artifact = sample_artifact();
        let record = encrypted_record("record-secret-1", canonical_hash_hex(&artifact).unwrap());

        store
            .write_encrypted_artifact(&record, &artifact, "correct horse")
            .unwrap();
        let err = store
            .read_encrypted_artifact(&record, "wrong horse")
            .unwrap_err();

        assert!(matches!(err, StoreError::Crypto));

        cleanup(root);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]

        #[test]
        fn prop_encrypt_decrypt_round_trip(
            record_id in "[a-z]{1,20}",
            name in "[a-z]{1,20}",
            count in any::<i64>()
        ) {
            let root = temp_store_root("prop-encrypted-round-trip");
            let store = RecordStore::new(&root);
            let artifact = serde_json::json!({
                "contract_version": "sophia/v1",
                "artifact_type": "witness.signed_attestation",
                "name": name,
                "count": count
            });
            let record = encrypted_record(&record_id, canonical_hash_hex(&artifact).unwrap());

            store.write_encrypted_artifact(&record, &artifact, "correct horse").unwrap();
            let decrypted = store.read_encrypted_artifact(&record, "correct horse").unwrap();

            prop_assert_eq!(decrypted, artifact);
            cleanup(root);
        }

        #[test]
        fn prop_wrong_passphrase_fails(
            record_id in "[a-z]{1,20}",
            value in any::<i64>(),
            passphrase in "[a-z]{1,20}",
            wrong_passphrase in "[a-z]{1,20}"
        ) {
            prop_assume!(passphrase != wrong_passphrase);
            let root = temp_store_root("prop-wrong-passphrase");
            let store = RecordStore::new(&root);
            let artifact = serde_json::json!({
                "contract_version": "sophia/v1",
                "artifact_type": "witness.signed_attestation",
                "value": value
            });
            let record = encrypted_record(&record_id, canonical_hash_hex(&artifact).unwrap());

            store.write_encrypted_artifact(&record, &artifact, &passphrase).unwrap();
            let err = store.read_encrypted_artifact(&record, &wrong_passphrase).unwrap_err();

            prop_assert!(matches!(err, StoreError::Crypto));
            cleanup(root);
        }

        #[test]
        fn prop_ciphertext_tampering_fails(
            record_id in "[a-z]{1,20}",
            value in any::<i64>(),
            tamper_position in any::<usize>()
        ) {
            let root = temp_store_root("prop-tampered-ciphertext");
            let store = RecordStore::new(&root);
            let artifact = serde_json::json!({
                "contract_version": "sophia/v1",
                "artifact_type": "witness.signed_attestation",
                "value": value
            });
            let record = encrypted_record(&record_id, canonical_hash_hex(&artifact).unwrap());

            store.write_encrypted_artifact(&record, &artifact, "correct horse").unwrap();
            let blob_path = store.vault_blob_path(&record).unwrap();
            let mut blob: EncryptedArtifactBlob =
                serde_json::from_str(&fs::read_to_string(&blob_path).unwrap()).unwrap();
            let mut ciphertext = hex::decode(&blob.ciphertext_hex).unwrap();
            prop_assert!(!ciphertext.is_empty());
            let index = tamper_position % ciphertext.len();
            ciphertext[index] ^= 0x01;
            blob.ciphertext_hex = hex::encode(ciphertext);
            fs::write(&blob_path, serde_json::to_vec_pretty(&blob).unwrap()).unwrap();

            let err = store.read_encrypted_artifact(&record, "correct horse").unwrap_err();

            prop_assert!(matches!(err, StoreError::Crypto));
            cleanup(root);
        }
    }

    #[test]
    fn reports_encrypted_blob_presence() {
        let root = temp_store_root("blob-presence");
        let store = RecordStore::new(&root);
        let artifact = sample_artifact();
        let record = encrypted_record("record-secret-1", canonical_hash_hex(&artifact).unwrap());

        assert!(!store.encrypted_artifact_exists(&record).unwrap());
        store
            .write_encrypted_artifact(&record, &artifact, "correct horse")
            .unwrap();
        assert!(store.encrypted_artifact_exists(&record).unwrap());

        cleanup(root);
    }

    fn sample_record(record_id: &str) -> CredArtifactRecord {
        artifact_record(
            record_id.to_owned(),
            "cred:local:test".to_owned(),
            "cred.presentation".to_owned(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            None,
            "selective".to_owned(),
            "local_encrypted".to_owned(),
            Some("app:test".to_owned()),
            1,
            Some(vec!["test".to_owned()]),
        )
    }

    fn encrypted_record(record_id: &str, artifact_hash: String) -> CredArtifactRecord {
        artifact_record(
            record_id.to_owned(),
            "cred:local:test".to_owned(),
            "witness.signed_attestation".to_owned(),
            artifact_hash,
            Some(RecordStore::vault_blob_uri(record_id)),
            "selective".to_owned(),
            "local_encrypted".to_owned(),
            Some("app:test".to_owned()),
            1,
            Some(vec!["test".to_owned()]),
        )
    }

    fn sample_artifact() -> serde_json::Value {
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

    fn sample_grant() -> CredPermissionGrant {
        CredPermissionGrant {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.permission_grant".to_owned(),
            grant_id: "grant-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            app_id: "app:prestige:test".to_owned(),
            app_pubkey: None,
            capabilities: vec!["witness.present_attestation".to_owned()],
            constraints: CredGrantConstraints {
                allowed_audiences: Some(vec!["prestige".to_owned()]),
                allowed_artifact_types: Some(vec!["witness.signed_attestation".to_owned()]),
                max_uses: Some(3),
                expires_at: Some(4_102_444_800),
                allow_export: Some(false),
            },
            human_approval: "per_use".to_owned(),
            created_at: 1,
            cred_signature: None,
        }
    }

    fn sample_presentation() -> CredPresentation {
        CredPresentation {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.presentation".to_owned(),
            presentation_id: "presentation-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            request_id: "request-1".to_owned(),
            grant_id: Some("grant-1".to_owned()),
            app_id: "app:prestige:test".to_owned(),
            created_at: 3,
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

    fn temp_store_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("cred-store-{name}-{}-{nanos}", std::process::id()))
    }

    fn cleanup(root: PathBuf) {
        let _ = fs::remove_dir_all(root);
    }
}
