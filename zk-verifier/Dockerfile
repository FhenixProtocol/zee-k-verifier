# Builder stage
FROM rust:1.92-slim-bookworm AS builder
RUN rustup toolchain install nightly-2025-10-15

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Define build argument for features
ARG FEATURES="default"

# Copy the source code and dependencies
COPY zk-verifier/ zk-verifier/
COPY rust-common/ rust-common/

# Change to zk-verifier directory and build
WORKDIR /usr/src/app/zk-verifier
RUN cargo build --release --locked --no-default-features --features "$FEATURES"

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /usr/src/app/zk-verifier/target/release/zk-verifier /app/zk-verifier

# Set environment variables
ENV RUST_LOG=info

# Run the binary
CMD ["./zk-verifier"] 