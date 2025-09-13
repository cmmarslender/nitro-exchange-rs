use axum::http::StatusCode;
use axum::{extract::State, http, routing::post, Json, Router};
use bytes::Bytes;
use clap::Parser;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::client::conn;
use hyper::Request;
use hyper_util::rt::tokio::TokioIo;
use log::info;
use nitro_exchange_common::{DecryptRequest, DecryptResponse, HandshakeRequest, HandshakeResponse};
use serde::{de::DeserializeOwned, Serialize};
use std::net::SocketAddr;
use tokio_vsock::VsockAddr;
use tokio_vsock::VsockStream;
use tower_http::cors::{Any, CorsLayer};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(long, default_value = "3001")]
    port: u16,

    #[arg(long, default_value = "5")]
    cid: u32,

    #[arg(long, default_value = "5000")]
    vsock_port: u32,
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub cid: u32,
    pub vsock_port: u32,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();

    let cors = CorsLayer::new()
        .allow_methods([http::Method::POST])
        .allow_origin(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/handshake", post(handshake))
        .route("/decrypt", post(decrypt))
        .with_state(ProxyConfig {
            cid: cli.cid,
            vsock_port: cli.vsock_port,
        })
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handshake(
    State(proxy_config): State<ProxyConfig>,
    Json(payload): Json<HandshakeRequest>,
) -> Result<Json<HandshakeResponse>, (StatusCode, String)> {
    proxy_request(proxy_config.clone(), "/handshake", payload).await
}

// Handler that either processes locally or proxies to vsock
async fn decrypt(
    State(proxy_config): State<ProxyConfig>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, String)> {
    proxy_request(proxy_config.clone(), "/decrypt", payload).await
}

async fn proxy_request<Req, Resp>(
    proxy_config: ProxyConfig,
    endpoint: &str,
    payload: Req,
) -> Result<Json<Resp>, (StatusCode, String)>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    // Connect to enclave vsock
    let addr = VsockAddr::new(proxy_config.cid, proxy_config.vsock_port);
    let stream = VsockStream::connect(addr).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("vsock connect failed: {e}"),
        )
    })?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = conn::http1::handshake(io).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("http handshake failed: {e}"),
        )
    })?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("connection error: {err:?}");
        }
    });

    // Create HTTP request
    let json_body = serde_json::to_string(&payload).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("json serialization failed: {e}"),
        )
    })?;

    let req: Request<Full<Bytes>> = Request::builder()
        .method("POST")
        .uri(endpoint)
        .header("content-type", "application/json")
        .body(Full::from(Bytes::from(json_body)))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("request build failed: {e}"),
            )
        })?;

    // Send to enclave
    let resp = sender.send_request(req).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("request failed: {e}"),
        )
    })?;

    // Parse response
    let body_bytes = resp
        .collect()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("body read failed: {e}"),
            )
        })?
        .to_bytes();

    let response: Resp = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("json parse failed: {e}"),
        )
    })?;

    Ok(Json(response))
}
