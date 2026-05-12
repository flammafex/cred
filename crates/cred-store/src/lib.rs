use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use cred_core::{artifact_type, canonical_hash_hex, canonical_json, CredArtifactRecord};
use scrypt::{scrypt, Params};
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
    #[error("record already exists: {0}")]
    DuplicateRecord(String),
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
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.records_path())?;
        serde_json::to_writer(&mut file, record).map_err(StoreError::Encode)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    pub fn list_records(&self) -> Result<Vec<CredArtifactRecord>, StoreError> {
        let path = self.records_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (index, line) in reader.lines().enumerate() {
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

        Ok(records)
    }

    pub fn get_record(&self, record_id: &str) -> Result<Option<CredArtifactRecord>, StoreError> {
        Ok(self
            .list_records()?
            .into_iter()
            .find(|record| record.record_id == record_id))
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
    use cred_core::artifact_record;
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
