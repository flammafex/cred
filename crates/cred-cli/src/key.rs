use crate::commands::*;
use crate::util::{controller_secret_key_path, generate_secret_key_hex, print_json, read_secret_key, write_secret_key};
use anyhow::Result;
use cred_core::public_key_from_secret_hex;
use std::path::PathBuf;

pub(crate) fn key(command: KeyCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        KeyCommand::Generate(command) => key_generate(command, store_path),
        KeyCommand::Public(command) => key_public(command, store_path),
    }
}

pub(crate) fn key_generate(command: KeyGenerateCommand, store_path: Option<PathBuf>) -> Result<()> {
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

pub(crate) fn key_public(command: KeyPathCommand, store_path: Option<PathBuf>) -> Result<()> {
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
