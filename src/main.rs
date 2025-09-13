use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use axum::{extract::State, http, routing::post, Json, Router};
use axum::http::StatusCode;
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use p256::elliptic_curve::rand_core::OsRng;
use sha2::Sha256;
use tower_http::cors::{Any, CorsLayer};
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

#[derive(Deserialize)]
struct DecryptRequest {
    session_id: String,
    ciphertext: String,
    initialization_vector: String,
}

#[derive(Serialize)]
struct DecryptResponse {
    plaintext: String,
}

#[tokio::main]
async fn main() {
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

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
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

    // HKDF using the client provided salt + info
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

    //println!("Session ID: {} | Private Key: {}", session_id, general_purpose::STANDARD.encode(okm));

    Ok(Json(ServerHandshake {
        session_id,
        public_key: server_pub_b64,
    }))
}

async fn decrypt(
    State(state): State<AppState>,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, (StatusCode, String)> {
    // Look up the session key to get the shared aes key
    let key_bytes = {
        let sessions = state.sessions.lock().unwrap();
        sessions.get(&payload.session_id)
            .cloned()
            .ok_or((StatusCode::BAD_REQUEST, "invalid session id".into()))?
    };

    // Set up AES
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Get the ciphertext, initialization vector from the request
    let ct_bytes = general_purpose::STANDARD.decode(&payload.ciphertext)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid ciphertext".into()))?;
    let iv_bytes = general_purpose::STANDARD.decode(&payload.initialization_vector)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid initialization vector".into()))?;

    if iv_bytes.len() != 12 {
        return Err((StatusCode::BAD_REQUEST, "IV must be 12 bytes".into()));
    }
    let nonce = Nonce::from_slice(&iv_bytes);

    // Do the decrypt
    let plaintext_bytes = cipher.decrypt(nonce, ct_bytes.as_ref())
        .map_err(|_| (StatusCode::BAD_REQUEST, "decryption failed".into()))?;
    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "decryption failed".into()))?;

    //println!("Ciphertext: {} | Plaintext: {plaintext}", payload.ciphertext);

    Ok(Json(DecryptResponse { plaintext }))
}