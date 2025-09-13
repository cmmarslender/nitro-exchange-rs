use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

mod client;
mod server;

const INFO_STRING: &str = "nitro-key-exchange-v1";

#[derive(Serialize, Deserialize)]
struct HandshakeRequest {
    public_key: String,
    salt: String,
    info: String,
}

#[derive(Serialize, Deserialize)]
struct HandshakeResponse {
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

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run as the enclave server
    Server {
        #[arg(long, default_value = "3001")]
        port: u16,

        #[arg(long)]
        vsock: bool,
    },
    /// Run as a client that talks to the server
    Client {
        #[arg(long, default_value = "http://127.0.0.1")]
        host: String,

        #[arg(long, default_value = "3001")]
        port: u16,

        #[arg(long)]
        vsock: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Server { port, vsock } => {
            server::run_server(port, vsock).await;
        }
        Mode::Client { host, port, vsock } => {
            client::run_client(host, port, vsock).await;
        }
    }
}
