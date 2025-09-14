# Nitro Exchange

A secure key exchange and encryption service built for AWS Nitro Enclaves, providing cryptographically verifiable secure communication channels.

## Overview

Nitro Exchange is a Rust-based solution that enables secure key exchange and encrypted communication using AWS Nitro Enclaves for hardware-level security guarantees. It implements Elliptic Curve Diffie-Hellman (ECDH) key exchange with HKDF key derivation and AES-256-GCM encryption, all within the trusted execution environment of a Nitro Enclave.

**Key Benefit**: Nitro Exchange allows infrastructure layers to terminate TLS connections and handle network traffic while cryptographically guaranteeing that sensitive data remains accessible only to the verified enclave code. This enables cryptographically provable privacy guarantees—users can verify that their sensitive data (like private keys) cannot be accessed by anyone, even if they don't trust the infrastructure operators.

### Why Attested ECDH Instead of TLS-at-Enclave

Some Nitro Enclave projects terminate TLS directly inside the enclave and expose a WebSocket/TLS endpoint. In that model, the enclave embeds its TLS public key in the attestation document, and clients are expected to trust that the TLS session is therefore anchored in the enclave. This works well for server-to-server use cases where the client can fetch and validate the attestation out-of-band.

However, this model breaks down in web browsers: the browser’s JavaScript environment has no access to the TLS handshake details or server certificate. That means the client cannot directly confirm that the TLS key it negotiated actually matches the attested enclave key. To bridge that gap, projects using this pattern typically introduce a trusted server to validate attestation on the client’s behalf, shifting the trust boundary back outside the enclave.

This design avoids this limitation by using an attested ECDH key exchange. The enclave generates an ephemeral ECDH public key, embeds it in the attestation document, and returns it to the browser. The browser validates the attestation directly against AWS Nitro’s root of trust and checks PCR values. Once validated, the browser completes the ECDH exchange and derives a symmetric key that is provably known only to the enclave. TLS termination on the parent instance still protects transport, but confidentiality is guaranteed end-to-end: all payloads after the key exchange are encrypted with the enclave-bound key.

### Flow Overview

```
Browser                          Parent EC2                        Enclave
   |                                |                                 |
   |---- TLS Handshake ------------>|                                 |
   |  (terminated on parent)        |                                 |
   |                                |                                 |
   |---- Request Key Exchange ----->|---- Forward ------------------->|
   |                                |   Enclave generates ephemeral   |
   |                                |   ECDH public key + attestation |
   |                                |<------------------------------- |
   |<--- ECDH pubkey + attestation--|                                 |
   |                                |                                 |
   |-- Validate attestation (AWS root, PCRs, embedded pubkey)         |
   |-- Perform ECDH, derive shared key ------------------------------>|
   |                                |                                 |
   |===> All further app data encrypted with shared key (inside TLS)  |

```

With this model, the browser does not rely on TLS certificate binding (which it can’t observe). Instead, it uses attestation + ECDH to guarantee enclave-only access to secrets, while TLS still provides transport security.

### Threat Model

**Protects against:**

- A malicious or compromised parent EC2 instance:
  - Even if the parent sees decrypted TLS traffic, it only observes ciphertext once the enclave-derived symmetric key is in use. 
- MITM or replay attacks after TLS termination:
  - The symmetric session key is derived through an attested ECDH exchange and is bound to the enclave. 
  - This prevents a parent or MITM from forging new messages, since only the enclave holds the valid key. 
  - However, ciphertext replay within the established session (after key exchange) is still theoretically possible unless higher-level replay protection (e.g. nonces, sequence numbers) is added. 
- Incorrect enclave launch:
  - Validating PCRs ensures the enclave image, kernel, and configuration match expected values. 
- Fake attestations:
  - AWS Nitro Root CA verification ensures only genuine enclaves can produce valid attestation documents.

**Does not protect against:**

- A malicious enclave image:
  - If the code inside the enclave is backdoored, attestation will still succeed as long as PCRs match the backdoored image. 
- Message suppression or delay by the parent:
  - A malicious or compromised parent can drop or delay messages. 
  - This impacts availability but does not compromise confidentiality or integrity.
- Browser trust assumptions:
  - The browser still must trust its local environment (e.g., no malicious extensions) to validate attestation correctly.

## Architecture

The project consists of four main components:

### Enclave (`enclave/`)
The core secure service running inside an AWS Nitro Enclave. Features:
- **Secure Key Exchange**: ECDH-based handshake protocol with P-256 curves
- **Attestation Support**: Generates cryptographic attestation documents proving enclave integrity
- **AES-256-GCM Encryption**: Secure symmetric encryption for data protection
- **Session Management**: Maintains isolated encryption sessions with unique session IDs
- **VSock & HTTP Support**: HTTP support for testing outside enclave environments

### Proxy (`proxy/`)
HTTP-to-VSock bridge that enables external communication with the enclave:
- **Zero Knowledge Infrastructure**: Infrastructure layers can handle encrypted traffic without accessing sensitive data
- Accepts HTTP requests from external clients
- Forwards requests to the enclave via VSock (inter-VM communication)
- Transparent request/response proxying

### Client (`client/`)
Reference Rust client demonstrating secure communication:
- Performs ECDH key exchange with the enclave
- Derives shared encryption keys using HKDF
- Supports both direct HTTP and VSock communication modes
- Validates attestation documents (Not yet implemented in this version)

**Note**: Client implementations are available in multiple languages (React/Next.js, etc.) demonstrating how to integrate with the proxy/enclave from different platforms and frameworks.

### Common (`common/`)
Shared data structures and constants:
- Protocol message definitions (handshake, decrypt requests/responses)
- Serialization/deserialization logic
- Protocol version constants

## Security Features

- **Hardware-Verified Security**: Runs in AWS Nitro Enclaves for hardware-level isolation
- **Cryptographic Attestation**: Provides verifiable proof of enclave integrity and code authenticity
- **Perfect Forward Secrecy**: Each session uses ephemeral ECDH key pairs
- **Strong Encryption**: AES-256-GCM with HKDF key derivation
- **Session Isolation**: Each client session has independent encryption keys
- **Memory Safety**: Written in Rust for memory-safe cryptographic operations

## Protocol Flow

1. **Handshake Phase**:
   - Client generates ephemeral ECDH key pair and random salt
   - Client sends public key, salt, and protocol info to enclave
   - Enclave generates its own ephemeral key pair
   - Both parties derive shared secret using ECDH
   - Shared AES-256 key derived using HKDF with salt and info string
   - **Attestation Integration**: Enclave embeds its public key and the client-provided salt in the attestation document, cryptographically proving both the authenticity of the key exchange and freshness of the session (preventing replay attacks)
   - Enclave returns its public key, session ID, and attestation document
   - Client can verify the attestation to ensure communication is with the authentic enclave, not an intermediary

2. **Encryption Phase**:
   - Client encrypts data using derived AES-256-GCM key
   - Client sends ciphertext, IV, and session ID to enclave
   - **Infrastructure Transparency**: The parent EC2 instance, proxy, and other infrastructure layers can see the ciphertext but cannot decrypt it, since the decryption key was provably generated only within the enclave
   - Enclave decrypts using session-specific key
   - **Note**: The enclave returns plaintext in this demo to verify successful key derivation and encryption/decryption. In production, you would process the decrypted data within the enclave and return only non-sensitive results.

## Build and Deployment

### Prerequisites
- Rust toolchain
- AWS Nitro Enclaves SDK (for enclave deployment)
- Docker (required by Nitro Enclaves build process)

### Building for AWS Production

Build the enclave for deployment on AWS Nitro Enclaves:

```bash
# Build enclave Docker image
docker build -t nitro-exchange:latest .

# Convert Docker image to Enclave Image File (EIF)
nitro-cli build-enclave \
  --docker-uri nitro-exchange:latest \
  --output-file ~/nitro.eif

# Build proxy binary for the host
cargo build --release --bin nitro-exchange-proxy
```

### Running on AWS

```bash
# Run enclave
nitro-cli run-enclave \
  --eif-path ~/nitro.eif \
  --cpu-count 2 \
  --memory 512 \
  --enclave-cid 5 \
  --enclave-name nitro-exchange

# Run proxy (on host, outside enclave)
./target/release/nitro-exchange-proxy --port 3001 --cid 5 --vsock-port 5000

# Note: For browser-based clients (React/Next.js), WebCrypto requires TLS.
# You'll need a TLS terminator (nginx, ALB, etc.) in front of the proxy service.

```

### Local Development Testing

For testing without AWS Nitro Enclaves:

```bash
# Start enclave server (HTTP mode for local testing)
RUST_LOG=info cargo run --bin nitro-exchange-enclave -- --port 3001

# Run client directly (no proxy needed in local mode)
RUST_LOG=info cargo run --bin nitro-exchange-client -- --host http://127.0.0.1 --port 3001
```

## Configuration

### Enclave Options
- `--port`: Port to bind to (default: 3001)
- `--vsock`: Listen on VSock instead of TCP (Must run in this mode in enclaves)

### Proxy Options
- `--port`: HTTP port to bind to (default: 3001)
- `--cid`: Enclave VSock CID (default: 5)
- `--vsock-port`: Enclave VSock port (default: 5000)

### Client Options
- `--host`: Server host (default: http://127.0.0.1)
- `--port`: Server port (default: 3001)
- `--vsock`: Use VSock instead of HTTP
- `--cid`: VSock CID (default: 5)
