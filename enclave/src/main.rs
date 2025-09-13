use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::nsm_init;
use aws_nitro_enclaves_nsm_api::driver::nsm_process_request;
use axum::http::StatusCode;
use axum::serve::Listener;
use axum::{extract::State, http, routing::post, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use hkdf::Hkdf;
use log::info;
use nitro_exchange_common::{
    DecryptRequest, DecryptResponse, HandshakeRequest, HandshakeResponse, INFO_STRING,
};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use serde_bytes::ByteBuf;
use sha2::Sha256;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
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

#[derive(Clone)]
pub struct AppState {
    // Store session_id -> AES key mapping
    pub sessions: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(long, default_value = "3001")]
    port: u16,

    #[arg(long)]
    vsock: bool,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let Cli { vsock, port } = Cli::parse();

    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let cors = CorsLayer::new()
        .allow_methods([http::Method::POST])
        .allow_origin(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/handshake", post(handshake))
        .route("/decrypt", post(decrypt))
        .with_state(state)
        .layer(cors);

    if vsock {
        let addr = VsockAddr::new(VMADDR_CID_ANY, u32::from(port));
        let listener = VsockListener::bind(addr).expect("failed to bind vsock");
        let acceptor = VsockAcceptor::new(listener);
        info!("Listening on cid, port: {port}");
        axum::serve(acceptor, app).await.unwrap();
    } else {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        info!("Listening on {addr}");
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}

async fn handshake(
    State(state): State<AppState>,
    Json(payload): Json<HandshakeRequest>,
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

    let attestation_doc = get_attestation(Some(server_public.as_bytes().to_vec()));
    let attestation = match attestation_doc {
        Ok(doc) => Some(general_purpose::STANDARD.encode(doc.as_slice())),
        Err(err) => {
            log::warn!("Attestation Failed: {err}");
            None
        }
    };

    sensitivelog!(
        "Session ID: {} | Private Key: {}",
        session_id,
        general_purpose::STANDARD.encode(okm)
    );

    Ok(Json(HandshakeResponse {
        session_id,
        public_key: server_pub_b64,
        attestation,
    }))
}

async fn decrypt(
    State(state): State<AppState>,
    Json(payload): Json<DecryptRequest>,
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

fn get_attestation(user_data: Option<Vec<u8>>) -> Result<Vec<u8>, io::Error> {
    let fd = nsm_init();
    if fd < 0 {
        return Err(io::Error::other("failed to open /dev/nsm"));
    }

    let req = Request::Attestation {
        user_data: user_data.map(ByteBuf::from),
        nonce: None,
        public_key: None,
    };

    let resp: Response = nsm_process_request(fd, req);

    match resp {
        Response::Attestation { document } => Ok(document),
        Response::Error(err) => Err(io::Error::other(format!("NSM error: {err:?}"))),
        other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
    }
}
