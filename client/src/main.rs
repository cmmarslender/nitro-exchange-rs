use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use clap::Parser;
use hkdf::Hkdf;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::client::conn;
use hyper::Request;
use hyper_util::rt::tokio::TokioIo;
use log::{debug, info};
use nitro_exchange_common::{HandshakeRequest, HandshakeResponse, INFO_STRING};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use sha2::Sha256;
use tokio_vsock::{VsockAddr, VsockStream};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1")]
    host: String,

    #[arg(long, default_value = "3001")]
    port: u16,

    #[arg(long)]
    vsock: bool,

    #[arg(long, default_value = "5")]
    cid: u32,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let Cli {
        host,
        port,
        vsock,
        cid,
    } = Cli::parse();

    // Generate our own ephemeral keypair for this session
    let client_secret = EphemeralSecret::random(&mut OsRng);
    let client_public = EncodedPoint::from(client_secret.public_key());
    let client_pub_b64 = general_purpose::STANDARD.encode(client_public.as_bytes());

    // Generate the random salt
    let salt_bytes: [u8; 16] = rand::random();
    let salt_b64 = general_purpose::STANDARD.encode(salt_bytes);

    let handshake_req = HandshakeRequest {
        public_key: client_pub_b64,
        salt: salt_b64,
        info: INFO_STRING.to_string(),
    };

    let resp: HandshakeResponse = if vsock {
        do_handshake_vsock(cid, port, &handshake_req).await
    } else {
        do_handshake_http(&format! {"{host}:{port}"}, &handshake_req).await
    };

    info!("Got session_id: {}", resp.session_id);
    if let Ok(json) = serde_json::to_string(&resp) {
        debug!("Attestation response JSON: {json}");
    }

    let server_pub_bytes = general_purpose::STANDARD
        .decode(&resp.public_key)
        .expect("Invalid base64 public key");
    let server_point = EncodedPoint::from_bytes(&server_pub_bytes).expect("bad public key");
    let server_pub =
        PublicKey::from_sec1_bytes(server_point.as_bytes()).expect("Invalid public key");

    // Derive the shared secret from our secret key and the clients public key
    let shared = client_secret.diffie_hellman(&server_pub);
    let shared_secret_bytes = shared.raw_secret_bytes();

    // HKDF using the generated salt + info
    let info = INFO_STRING.as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt_bytes), shared_secret_bytes);
    let mut okm = [0u8; 32]; // 32 bytes = AES-256
    hk.expand(info, &mut okm).unwrap();

    info!(
        "Derived shared private key {}",
        general_purpose::STANDARD.encode(okm)
    );
}

async fn do_handshake_http(url: &str, handshake_req: &HandshakeRequest) -> HandshakeResponse {
    let client = reqwest::Client::new();

    client
        .post(format!("{url}/handshake"))
        .json(&handshake_req)
        .send()
        .await
        .unwrap()
        .json::<HandshakeResponse>()
        .await
        .unwrap()
}

async fn do_handshake_vsock(
    cid: u32,
    port: u16,
    handshake_req: &HandshakeRequest,
) -> HandshakeResponse {
    let addr = VsockAddr::new(cid, u32::from(port));
    let stream = VsockStream::connect(addr)
        .await
        .expect("vsock connect failed");
    let io = TokioIo::new(stream);

    let (mut sender, conn) = conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("connection error: {err:?}");
        }
    });

    let body_bytes = serde_json::to_vec(handshake_req).unwrap();
    let req = Request::post("/handshake")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    let bytes: Bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}
