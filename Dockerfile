# =============================================================================
# Citadel API Server - Docker Image
#
# Build:  docker build -t citadel .
# Run:    docker run -p 3000:3000 -e CITADEL_API_KEY=your-secret citadel
# =============================================================================

# Stage 1: Build
FROM rust:1.81-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY citadel-envelope/Cargo.toml citadel-envelope/Cargo.toml
COPY citadel-keystore/Cargo.toml citadel-keystore/Cargo.toml
COPY citadel-api/Cargo.toml citadel-api/Cargo.toml

# Create stub files so cargo can resolve the workspace
RUN mkdir -p citadel-envelope/src && echo "" > citadel-envelope/src/lib.rs && \
    mkdir -p citadel-keystore/src && echo "" > citadel-keystore/src/lib.rs && \
    mkdir -p citadel-api/src && echo "fn main() {}" > citadel-api/src/main.rs

# Cache dependency build
RUN cargo build --release -p citadel-api 2>/dev/null || true

# Copy actual source
COPY citadel-envelope/ citadel-envelope/
COPY citadel-keystore/ citadel-keystore/
COPY citadel-api/ citadel-api/

# Touch sources to invalidate the stub cache
RUN touch citadel-envelope/src/lib.rs citadel-keystore/src/lib.rs citadel-api/src/main.rs

# Build release binary
RUN cargo build --release -p citadel-api

# Stage 2: Runtime (minimal image)
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r citadel && useradd -r -g citadel -m citadel

# Copy binary
COPY --from=builder /build/target/release/citadel-api /usr/local/bin/citadel-api

# Data directory (mount a volume here for persistence)
RUN mkdir -p /data && chown citadel:citadel /data
VOLUME /data

USER citadel

ENV CITADEL_PORT=3000
ENV CITADEL_DATA_DIR=/data
ENV CITADEL_SEED_DEMO=true

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["citadel-api"]
