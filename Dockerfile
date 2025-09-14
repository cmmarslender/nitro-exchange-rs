# ---- Build Stage ----
FROM rust:1-slim AS builder

# Install musl tools
RUN apt-get update && apt-get install -y musl-tools pkg-config \
    && rustup target add x86_64-unknown-linux-musl

WORKDIR /app

# Copy in the Cargo.toml files so that dependency resolution works
COPY .cargo .cargo
COPY Cargo.toml Cargo.lock ./
COPY client/Cargo.toml client/
COPY common common
COPY enclave/Cargo.toml enclave/
COPY proxy/Cargo.toml proxy/
# Create dummy source to cache dependencies
RUN mkdir -p client/src enclave/src proxy/src \
    && echo "fn main() {}" > client/src/main.rs \
    && echo "fn main() {}" > enclave/src/main.rs \
    && echo "fn main() {}" > proxy/src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl --package nitro-exchange-enclave || true

# Copy source and build
# Now only copy sources
COPY client/src/ client/src/
COPY enclave/src/ enclave/src/
COPY proxy/src/ proxy/src/
RUN cargo build --release --target x86_64-unknown-linux-musl --package nitro-exchange-enclave --features insecure-logs

# ---- Runtime Stage (scratch, fully static) ----
FROM scratch

ENV RUST_LOG=info

# Copy static binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/nitro-exchange-enclave /nitro-exchange-enclave

# Enclave entrypoint
CMD ["/nitro-exchange-enclave", "--vsock", "--port", "5000"]