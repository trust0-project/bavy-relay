# WebTransport Relay for RISC-V VM

This is a high-performance relay server built with [WebTransport](https://w3c.github.io/webtransport/) and Rust. It enables browser-based RISC-V VMs to communicate with each other and access the external internet via a User-Space NAT gateway.

## Features

- **WebTransport/QUIC:** Uses modern HTTP/3-based transport for low-latency, secure connections over UDP port 4433.
- **Virtual Switch:** Broadcasts Ethernet frames between all connected clients (VMs), effectively placing them on the same virtual LAN.
- **User-Space NAT Gateway:**
    - **Gateway IP:** `10.0.2.2` (responds to ARP and Ping)
    - **External Access:** Allows VMs to ping external hosts (e.g., `8.8.8.8`) and perform UDP queries (e.g., DNS) by proxying traffic through the container's network stack.
    - **No Privileges Needed:** Uses standard UDP sockets and the `ping` command installed in the container.
- **Flexible TLS:** Supports both CA-signed certificates (production) and self-signed certificates (development).

## Production Deployment

For production, use **Let's Encrypt** (or any CA) certificates. Browsers trust these natively — no hash pinning or `serverCertificateHashes` needed.

### Docker Compose

```bash
docker compose up -d
```

Edit `docker-compose.yml` to uncomment and configure the certificate volume mount:

```yaml
services:
  relay:
    build: .
    ports:
      - "4433:4433/udp"
      - "4433:4433/tcp"
    environment:
      RELAY_CERT_PEM: /certs/fullchain.pem
      RELAY_KEY_PEM: /certs/privkey.pem
      CERT_POLL_INTERVAL: "60"
    volumes:
      - /etc/letsencrypt/live/relay.yourdomain.com:/certs:ro
```

The entrypoint watches the certificate files and automatically restarts the relay when they change (e.g., certbot renewal).

### Nginx Reverse Proxy

If your relay sits behind Nginx with HTTP/3 enabled, ensure your Nginx config exposes QUIC on the relay's domain:

```nginx
server {
    listen 443 quic reuseport;
    listen 443 ssl;
    http2 on;
    http3 on;

    server_name relay.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/relay.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.yourdomain.com/privkey.pem;

    # Forward QUIC/WebTransport to the relay
    location / {
        proxy_pass https://relay-container:4433;
    }
}
```

> **Note:** For direct WebTransport proxying, Nginx needs HTTP/3 upstream support, which is still maturing. An alternative is to expose the relay's UDP port directly and point the domain at it, using the same Let's Encrypt certs mounted into the relay container.

### Connecting from the Browser (Production)

With a CA-signed certificate, no hash pinning is needed:

```javascript
async function connectToRelay() {
  const transport = new WebTransport("https://relay.yourdomain.com:4433");

  await transport.ready;
  console.log("Connected to relay!");

  const reader = transport.datagrams.readable.getReader();
  const writer = transport.datagrams.writable.getWriter();

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    console.log("Received packet:", value);
  }
}
```

## Development Setup

### Running Locally

1. **Install Rust:** Ensure you have the latest stable Rust toolchain installed.
2. **Run the Server:**

```bash
cargo run --release
```

The server starts on port `4433` (UDP) with an **ephemeral self-signed certificate**. It will print a certificate hash you can use for browser connections:

```text
Certificate SHA-256 Hash: e7...3f
Use this hash with serverCertificateHashes when connecting (dev mode)
Listening on https://0.0.0.0:4433
```

### Using Pre-Generated Dev Certs

Generate short-lived certificates (valid 10 days, Chrome requires ≤14):

```bash
./scripts/generate-certs.sh
cargo run --release -- --cert-pem certs/relay-cert.pem --key-pem certs/relay-key.pem
```

### Docker (dev mode)

```bash
docker build -t riscv-relay .
docker run -d -p 4433:4433/udp --name relay riscv-relay
docker logs relay   # grab the certificate hash
```

### Connecting from the Browser (Dev)

Self-signed certificates require `serverCertificateHashes`:

```javascript
const RELAY_CERT_HASH = "YOUR_CERTIFICATE_HASH_HERE";

const certHashBytes = new Uint8Array(
  RELAY_CERT_HASH.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
);

async function connectToRelay() {
  const transport = new WebTransport("https://127.0.0.1:4433", {
    serverCertificateHashes: [
      { algorithm: "sha-256", value: certHashBytes },
    ],
  });

  await transport.ready;
  console.log("Connected to relay!");

  const reader = transport.datagrams.readable.getReader();
  const writer = transport.datagrams.writable.getWriter();

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    console.log("Received packet:", value);
  }
}
```

> **⚠ Browser Limitation:** Chrome/Chromium requires self-signed certificates used with `serverCertificateHashes` to have a maximum validity of **14 days**. The cert hash changes on every regeneration, so your app must fetch it dynamically.

## How it Works

1. **Connection:** The browser initiates a WebTransport session over QUIC.
2. **Verification:** The browser verifies the server's certificate (via CA trust chain in production, or hash pinning in dev).
3. **Data Exchange:**
   - The VM encapsulates Ethernet frames into WebTransport datagrams.
   - The Relay receives these datagrams.
4. **Routing:**
   - **Broadcast:** If the packet is internal (e.g., ARP, or destined for another VM), the relay broadcasts it to all other connected clients.
   - **NAT:** If the packet is destined for the internet (e.g., Google DNS `8.8.8.8`), the relay performs NAT, sends it out via the host's UDP socket, and forwards the response back to the specific client.

## Configuration

```bash
cargo run --release -- --bind 0.0.0.0 --port 4433
```

| Flag / Env Var | Default | Description |
|---|---|---|
| `--port` | `4433` | UDP/QUIC listen port |
| `--bind` | `0.0.0.0` | Bind address |
| `--cert-pem` / `RELAY_CERT_PEM` | — | Path to TLS certificate PEM |
| `--key-pem` / `RELAY_KEY_PEM` | — | Path to TLS private key PEM |
| `--heartbeat-interval` | `30` | Heartbeat interval (seconds) |
| `--peer-timeout` | `150` | Peer timeout (seconds) |
| `CERT_POLL_INTERVAL` | `60` | Cert file poll interval (seconds, entrypoint only) |
