use crate::{
    AppState, DecryptRequest, DecryptResponse, HandshakeRequest, HandshakeResponse, INFO_STRING,
    ProxyConfig,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use axum::http::StatusCode;
use axum::serve::Listener;
use axum::{Json, Router, extract::State, http, routing::post};
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use hkdf::Hkdf;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::Request;
use hyper::client::conn;
use hyper_util::rt::tokio::TokioIo;
use log::info;
use p256::elliptic_curve::rand_core::OsRng;
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio_vsock::VsockStream;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

#[cfg(feature = "insecure-logs")]
macro_rules! sensitivelog {
    ($($arg:tt)*) => {
        log::log!(target: "insecure", log::Level::Info, $($arg)*);
    };
}

#[cfg(not(feature = "insecure-logs"))]
macro_rules! sensitivelog {
    ($($arg:tt)*) => {};
}

pub(crate) async fn run_server(port: u16, vsock: bool, proxy: bool, cid: u32, vsock_port: u32) {
    env_logger::init();

    let proxy_config = if proxy {
        Some(ProxyConfig { cid, vsock_port })
    } else {
        None
    };

    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        proxy_config,
    };

    let cors = CorsLayer::new()
        .allow_methods([http::Method::POST])
        .allow_origin(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/handshake", post(handshake_handler))
        .route("/decrypt", post(decrypt_handler))
        .with_state(state)
        .layer(cors);

    if vsock {
        let addr = VsockAddr::new(VMADDR_CID_ANY, u32::from(port));
        let listener = VsockListener::bind(addr).expect("failed to bind vsock");
        let acceptor = VsockAcceptor::new(listener);
        info!("Listening on cid: {VMADDR_CID_ANY}, port: {port}");
        axum::serve(acceptor, app).await.unwrap();
    } else {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        info!("Listening on {addr}");
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}

// Handler that either processes locally or proxies to vsock
async fn handshake_handler(
    State(state): State<AppState>,
    Json(payload): Json<HandshakeRequest>,
) -> Result<Json<HandshakeResponse>, (StatusCode, String)> {
    if let Some(proxy_config) = &state.proxy_config {
        // Proxy mode: forward to vsock
        proxy_request(proxy_config.clone(), "/handshake", payload).await
    } else {
        // Local mode: process directly
        handshake_local(&state, &payload)
    }
}

// Handler that either processes locally or proxies to vsock
async fn decrypt_handler(
    State(state): State<AppState>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, String)> {
    if let Some(proxy_config) = &state.proxy_config {
        proxy_request(proxy_config.clone(), "/decrypt", payload).await
    } else {
        decrypt_local(&state, &payload)
    }
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

fn handshake_local(
    state: &AppState,
    payload: &HandshakeRequest,
) -> Result<Json<HandshakeResponse>, (StatusCode, String)> {
    // Make sure we're using the known/agreed upon info
    if payload.info != INFO_STRING {
        return Err((StatusCode::BAD_REQUEST, "invalid info string".into()));
    }

    // Read the clients public key
    let client_pub_bytes = general_purpose::STANDARD
        .decode(&payload.public_key)
        .expect("invalid base64 publicKey");
    let client_point = EncodedPoint::from_bytes(&client_pub_bytes).expect("bad public key");
    let client_pub =
        PublicKey::from_sec1_bytes(client_point.as_bytes()).expect("Invalid public key");

    // Generate our own ephemeral keypair for this session
    let server_secret = EphemeralSecret::random(&mut OsRng);
    let server_public = EncodedPoint::from(server_secret.public_key());
    let server_pub_b64 = general_purpose::STANDARD.encode(server_public.as_bytes());

    // Derive the shared secret from our secret key and the clients public key
    let shared = server_secret.diffie_hellman(&client_pub);
    let shared_secret_bytes = shared.raw_secret_bytes();

    // HKDF using the client provided salt + info
    let salt = general_purpose::STANDARD
        .decode(&payload.salt)
        .expect("invalid base64 salt");
    let info = payload.info.as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret_bytes);
    let mut okm = [0u8; 32]; // 32 bytes = AES-256
    hk.expand(info, &mut okm).unwrap();

    // Store the private key with the session ID for lookup on later requests
    let session_id = Uuid::new_v4().to_string();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), okm.to_vec());
    }

    sensitivelog!(
        "Session ID: {} | Private Key: {}",
        session_id,
        general_purpose::STANDARD.encode(okm)
    );

    Ok(Json(HandshakeResponse {
        session_id,
        public_key: server_pub_b64,
    }))
}

fn decrypt_local(
    state: &AppState,
    payload: &DecryptRequest,
) -> Result<Json<DecryptResponse>, (StatusCode, String)> {
    // Look up the session key to get the shared aes key
    let key_bytes = {
        let sessions = state.sessions.lock().unwrap();
        sessions
            .get(&payload.session_id)
            .cloned()
            .ok_or((StatusCode::BAD_REQUEST, "invalid session id".into()))?
    };

    // Set up AES
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Get the ciphertext, initialization vector from the request
    let ct_bytes = general_purpose::STANDARD
        .decode(&payload.ciphertext)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid ciphertext".into()))?;
    let iv_bytes = general_purpose::STANDARD
        .decode(&payload.initialization_vector)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "invalid initialization vector".into(),
            )
        })?;

    if iv_bytes.len() != 12 {
        return Err((StatusCode::BAD_REQUEST, "IV must be 12 bytes".into()));
    }
    let nonce = Nonce::from_slice(&iv_bytes);

    // Do the decrypt
    let plaintext_bytes = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|_| (StatusCode::BAD_REQUEST, "decryption failed".into()))?;
    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "decryption failed".into()))?;

    sensitivelog!(
        "Ciphertext: {} | Plaintext: {plaintext}",
        payload.ciphertext
    );

    Ok(Json(DecryptResponse { plaintext }))
}

// Adapts the vsock listener to work with axum
struct VsockAcceptor {
    inner: VsockListener,
}

impl VsockAcceptor {
    fn new(listener: VsockListener) -> Self {
        Self { inner: listener }
    }
}

impl Listener for VsockAcceptor {
    type Io = tokio_vsock::VsockStream;
    type Addr = tokio_vsock::VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        self.inner.accept().await.expect("vsock accept failed")
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
