use crate::commands::ServeHttpCommand;
use crate::service::{handle_service_request, service_response, ServiceRequest};
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) fn serve_http(command: ServeHttpCommand, store_path: Option<PathBuf>) -> Result<()> {
    let bind_addr = format!("{}:{}", command.bind, command.port);
    let state = Arc::new(store_path);

    let app = Router::new()
        .route("/", post(handle_request))
        .route("/health", post(handle_request))
        .with_state(state);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        eprintln!("cred http service listening on {bind_addr}");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

async fn handle_request(
    State(store_path): State<Arc<Option<PathBuf>>>,
    Json(request): Json<Value>,
) -> impl IntoResponse {
    let id = request
        .get("id")
        .cloned()
        .unwrap_or(Value::Null);

    let result = match serde_json::from_value::<ServiceRequest>(request) {
        Ok(service_request) => {
            handle_service_request(service_request, store_path.as_ref().clone(), "http")
                .map_err(|e| anyhow::anyhow!("{e:#}"))
        }
        Err(error) => Err(anyhow::anyhow!("invalid service request JSON: {error}")),
    };

    let response = service_response(id, result);
    (StatusCode::OK, Json(response))
}
