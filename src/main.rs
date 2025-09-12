use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}};
use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use axum::http::StatusCode;
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use p256::elliptic_curve::rand_core::OsRng;
use sha2::Sha256;
use uuid::Uuid;

const INFO_STRING: &str = "nitro-key-exchange-v1";

#[derive(Deserialize)]
struct ClientHandshake {
    public_key: String,
    salt: String,
    info: String,
}

#[derive(Serialize)]
struct ServerHandshake {
    session_id: String,
    public_key: String,
}

#[derive(Clone)]
struct AppState {
    // Store session_id -> AES key mapping
    sessions: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/handshake", post(handshake))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await.unwrap();
}

async fn handshake(
    State(state): State<AppState>,
    Json(payload): Json<ClientHandshake>,
) -> Result<Json<ServerHandshake>, (StatusCode, String)> {
    // Make sure we're using the known/agreed upon info
    if payload.info != INFO_STRING {
        return Err((StatusCode::BAD_REQUEST, "invalid info string".into()));
    }

    // Read the clients public key
    let client_pub_bytes = general_purpose::STANDARD
        .decode(&payload.public_key)
        .expect("invalid base64 publicKey");
    let client_point = EncodedPoint::from_bytes(&client_pub_bytes).expect("bad public key");
    let client_pub = PublicKey::from_sec1_bytes(client_point.as_bytes()).expect("Invalid public key");

    // Generate our own ephemeral keypair for this session
    let server_secret = EphemeralSecret::random(&mut OsRng);
    let server_public = EncodedPoint::from(server_secret.public_key());
    let server_pub_b64 = general_purpose::STANDARD.encode(server_public.as_bytes());

    // Derive the shared secret from our secret key and the clients public key
    let shared = server_secret.diffie_hellman(&client_pub);
    let shared_secret_bytes = shared.raw_secret_bytes();

    // HKDF using the client providced salt + info
    let salt = general_purpose::STANDARD.decode(&payload.salt).expect("invalid base64 salt");
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

    Ok(Json(ServerHandshake {
        session_id,
        public_key: server_pub_b64,
    }))
}