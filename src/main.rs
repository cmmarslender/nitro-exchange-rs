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
pub struct AppState {
    // Store session_id -> AES key mapping
    pub sessions: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    // Proxy configuration
    pub proxy_config: Option<ProxyConfig>,
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub cid: u32,
    pub vsock_port: u32,
}

#[derive(Serialize, Deserialize)]
struct DecryptRequest {
    session_id: String,
    ciphertext: String,
    initialization_vector: String,
}

#[derive(Serialize, Deserialize)]
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

        #[arg(long)]
        proxy: bool,

        #[arg(long, default_value = "16")]
        cid: u32,

        #[arg(long, default_value = "5000")]
        vsock_port: u32,
    },
    /// Run as a client that talks to the server
    Client {
        #[arg(long, default_value = "http://127.0.0.1")]
        host: String,

        #[arg(long, default_value = "3001")]
        port: u16,

        #[arg(long)]
        vsock: bool,

        #[arg(long, default_value = "16")]
        cid: u32,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Server {
            port,
            vsock,
            proxy,
            cid,
            vsock_port,
        } => {
            server::run_server(port, vsock, proxy, cid, vsock_port).await;
        }
        Mode::Client {
            host,
            port,
            vsock,
            cid,
        } => {
            client::run_client(host, port, vsock, cid).await;
        }
    }
}
