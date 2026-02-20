# ── Stage 1: Build ──────────────────────────────────────────────
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Cache dependencies by copying manifests first
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs so `cargo build` resolves + caches deps
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release && rm -rf src

# Copy the real source and rebuild (only the application is recompiled)
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ── Stage 2: Runtime ───────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/relay /usr/local/bin/relay
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# WebTransport uses QUIC (UDP); TCP exposed for HTTP/3 fallback and health checks
EXPOSE 4433/udp
EXPOSE 4433/tcp

# Certificate volume mount point.
# For PRODUCTION, mount Let's Encrypt (or any CA) certs:
#   -v /etc/letsencrypt/live/relay.example.com:/certs:ro
#   -e RELAY_CERT_PEM=/certs/fullchain.pem
#   -e RELAY_KEY_PEM=/certs/privkey.pem
#   -e CERT_POLL_INTERVAL=60    (optional, default 60s)
#
# The entrypoint watches cert files and restarts the relay on renewal.
# Without cert vars, the relay generates an ephemeral self-signed cert (dev only).

ENTRYPOINT ["docker-entrypoint.sh"]
