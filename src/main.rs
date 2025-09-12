use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, Mutex}};
use axum::{
    extract::State,
    routing::post,
    Json, Router,
};

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
) -> Json<ServerHandshake> {
    Json(ServerHandshake {
        session_id: "".to_string(),
        public_key: "".to_string(),
    })
}