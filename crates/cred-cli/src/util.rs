use anyhow::{bail, ensure, Context, Result};
use cred_store::RecordStore;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn read_record_artifact(
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

pub(crate) fn ensure_lower_hex(value: &str, field: &str, expected_bytes: usize) -> Result<()> {
    ensure!(
        value.len() == expected_bytes * 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{field} must be lowercase hex for exactly {expected_bytes} bytes"
    );
    Ok(())
}
pub(crate) fn record_store(store_path: Option<PathBuf>) -> Result<RecordStore> {
    let root = match store_path {
        Some(path) => path,
        None => RecordStore::default_root()?,
    };
    Ok(RecordStore::new(root))
}
pub(crate) fn read_json(path: &PathBuf) -> Result<Value> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse JSON {}", path.display()))
}

pub(crate) fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub(crate) fn controller_secret_key_path(
    secret_key_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
) -> Result<PathBuf> {
    match secret_key_path {
        Some(path) => Ok(path),
        None => Ok(record_store(store_path)?.root().join("controller_sk.hex")),
    }
}

pub(crate) fn generate_secret_key_hex() -> Result<String> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read controller secret key entropy")?;
    Ok(hex_encode(&bytes))
}

pub(crate) fn read_secret_key(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(text.trim().to_owned())
}

pub(crate) fn write_secret_key(path: &Path, secret_key: &str) -> Result<()> {
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

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before Unix epoch")?
        .as_secs())
}
