# ---- Build Stage ----
FROM rust:1-slim AS builder

# Install musl tools
RUN apt-get update && apt-get install -y musl-tools pkg-config \
    && rustup target add x86_64-unknown-linux-musl

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl || true

# Copy source and build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

# ---- Runtime Stage (scratch, fully static) ----
FROM scratch

ENV RUST_LOG=info

# Copy static binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/nitro-exchange-rs /nitro-exchange-rs

# Enclave entrypoint
CMD ["/nitro-exchange-rs", "server", "--vsock", "--port", "5000"]