use crate::{HandshakeRequest, HandshakeResponse};
use aes_gcm::aead::OsRng;
use base64::{Engine as _, engine::general_purpose};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use sha2::Sha256;

pub(crate) async fn run_client(url: String) {
    let client = reqwest::Client::new();

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
        info: crate::INFO_STRING.to_string(),
    };

    let resp = client
        .post(format!("{url}/handshake"))
        .json(&handshake_req)
        .send()
        .await
        .unwrap()
        .json::<HandshakeResponse>()
        .await
        .unwrap();

    println!("Got session_id: {}", resp.session_id);

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
    let info = crate::INFO_STRING.as_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt_bytes), shared_secret_bytes);
    let mut okm = [0u8; 32]; // 32 bytes = AES-256
    hk.expand(info, &mut okm).unwrap();

    println!(
        "Derived shared private key {}",
        general_purpose::STANDARD.encode(okm)
    );
}
