pub(crate) mod http;

use crate::commands::*;
use crate::grant::{grant_review_value, import_grant, parse_grant_with_hash};
use crate::presentation::{build_presentation, parse_action_request, presentation_source_from_record, presentation_source_from_value, PresentationBuild, PresentationSource};
use crate::util::{controller_secret_key_path, record_store};
use crate::vault::vault_inventory_value;
use anyhow::{bail, ensure, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

pub(crate) fn serve(command: ServeCommand, store_path: Option<PathBuf>) -> Result<()> {
    match command {
        ServeCommand::Stdio => serve_stdio(store_path),
        ServeCommand::Http(command) => crate::service::http::serve_http(command, store_path),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ServiceRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ServiceGrantParams {
    grant: Value,
    source_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ServicePresentParams {
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

pub(crate) fn serve_stdio(store_path: Option<PathBuf>) -> Result<()> {
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
                    handle_service_request(request, store_path.clone(), "stdio")
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

pub(crate) fn service_response(id: Value, result: Result<Value>) -> Value {
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

pub(crate) fn handle_service_request(
    request: ServiceRequest,
    store_path: Option<PathBuf>,
    transport: &str,
) -> Result<Value> {
    match request.method.as_str() {
        "cred.service_info" => service_info(store_path, transport),
        "cred.vault_inventory" => to_json_value(vault_inventory_value(store_path)?),
        "cred.grant_review" => service_grant_review(request.params),
        "cred.grant_import" => service_grant_import(request.params, store_path),
        "cred.grant_approvals" => {
            let approvals = record_store(store_path)?.list_grant_approvals()?;
            to_json_value(serde_json::json!({
                "contract_version": "sophia/v1",
                "artifact_type": "cred.grant_approval_list",
                "approvals": approvals
            }))
        }
        "cred.present" => service_present(request.params, store_path),
        // grant_approve and grant_deny are intentionally not exposed on the
        // app-facing stdio channel. Approvals must be made via the CLI
        // (cred grant approve / cred grant deny) so that a stdin-controlling
        // process cannot self-approve grants.
        other => bail!("unsupported service method: {other}"),
    }
}

pub(crate) fn service_info(store_path: Option<PathBuf>, transport: &str) -> Result<Value> {
    let store = record_store(store_path)?;
    Ok(serde_json::json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.service_info",
        "transport": transport,
        "store_root": store.root().display().to_string(),
        "methods": [
            "cred.service_info",
            "cred.vault_inventory",
            "cred.grant_review",
            "cred.grant_import",
            "cred.grant_approvals",
            "cred.present"
        ],
        "presentation_signing_default": true
    }))
}

pub(crate) fn service_grant_review(params: Value) -> Result<Value> {
    let params: ServiceGrantParams = service_params(params)?;
    let (grant, grant_hash) = parse_grant_with_hash(params.grant)?;
    Ok(grant_review_value(&grant, grant_hash))
}

pub(crate) fn service_grant_import(params: Value, store_path: Option<PathBuf>) -> Result<Value> {
    let params: ServiceGrantParams = service_params(params)?;
    let (grant, grant_hash) = parse_grant_with_hash(params.grant)?;
    to_json_value(import_grant(
        &grant,
        grant_hash,
        params.source_uri,
        store_path,
    )?)
}

pub(crate) fn service_present(params: Value, store_path: Option<PathBuf>) -> Result<Value> {
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

pub(crate) fn service_presentation_source(
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

pub(crate) fn service_params<T: DeserializeOwned>(params: Value) -> Result<T> {
    serde_json::from_value(params).context("invalid service params")
}

pub(crate) fn to_json_value<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).context("encode service result")
}
