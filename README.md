# Lattice

Ephemeral 1:1 post-quantum encrypted chat with file transfer. No database, no browser persistence, no accounts. Both participants must be online at the same time.

## What it does

Alice creates a session and gets an invite link. Bob opens the link. They perform a hybrid post-quantum key exchange through the server, then exchange end-to-end encrypted messages and files. The server relays ciphertext only. When either side leaves or the session expires, everything is gone.

## How the cryptography works

**Hybrid key exchange** combining classical and post-quantum primitives:

- **ML-KEM-768** (FIPS 203) for post-quantum key encapsulation
- **X25519** for classical elliptic-curve Diffie-Hellman
- **HKDF-SHA256** derives traffic keys from both shared secrets, binding the session ID, invite secret, both nonces, and the handshake transcript hash into the derivation
- **XChaCha20-Poly1305** encrypts all messages with random 24-byte nonces and authenticated associated data (AAD)
- **HMAC-SHA256** for handshake confirmation MACs and session resume proofs

**Invite link authentication** prevents relay MITM:

```
/join?sid=<session_id>#secret=<invite_secret>
```

The `session_id` is `SHA-256(invite_secret || protocol_version)` — the server sees the session ID for routing but never learns the invite secret (URL fragments are not sent in HTTP requests). The invite secret is bound into key derivation so the relay cannot silently substitute keys.

**Session fingerprint** — both clients derive a short fingerprint from the shared master secret. Users can compare fingerprints out-of-band to verify the handshake wasn't tampered with.

## What the server knows

The server is a dumb relay. It sees:

- session IDs (public routing identifiers)
- who connects when (IP addresses, timing)
- encrypted message sizes and timing
- handshake public keys in transit (ephemeral, useless without the invite secret)

The server **does not** see:

- the invite secret
- plaintext message or file contents
- encryption keys
- session fingerprints

## Architecture

```
lattice/
  crypto/     Rust crate — ML-KEM, X25519, HKDF, XChaCha20-Poly1305, WASM bindings
  server/     Rust Axum relay — WebSocket, in-memory sessions, no database
  client/     React + TypeScript — handshake, encrypted chat, file transfer
  nginx/      Reverse proxy config — TLS termination, Cloudflare, rate limiting
  scripts/    Build helpers — WASM compilation, dev server
```

### Crypto crate (`crypto/`)

Shared between the native Rust server tests and the browser via `wasm-bindgen`. Contains:

- `kem.rs` — ML-KEM-768 key generation, encapsulation, decapsulation
- `x25519.rs` — X25519 key generation and ECDH
- `session.rs` — HKDF key derivation, handshake MACs, resume proofs, nonce generation
- `aead.rs` — XChaCha20-Poly1305 encrypt/decrypt
- `envelope.rs` — canonical AAD builders for chat messages and file chunks
- `hash.rs` — incremental SHA-256 hasher (used for whole-file integrity verification)
- `wasm.rs` — `wasm-bindgen` exports for all of the above

### Server (`server/`)

Axum async server with:

- In-memory session registry with 30-minute TTL and background sweeper
- Two-participant enforcement (exactly one Alice, one Bob per session)
- WebSocket relay for text frames (JSON control messages) and binary frames (encrypted file chunks)
- Per-session replay/dedup cache (bounded at 256 frame fingerprints)
- Per-IP rate limiting on session creation (20/min) and WebSocket frames (240 text/min, 10K binary/min)
- Per-field size validation on all protocol messages
- Health check endpoint (`/healthz`)
- Configurable bind address via `LATTICE_HOST` / `LATTICE_PORT` env vars
- Proxy header trust via `LATTICE_TRUST_PROXY_HEADERS` for real client IP behind nginx
- Session resume: stores resume verifiers, issues challenge nonces, verifies HMAC proofs, reattaches sockets within a 30-second grace period

### Client (`client/`)

React 19 + TypeScript + Vite:

- WASM crypto loaded via dynamic import (Vite content-hashes the filenames)
- Full handshake state machine: offer, answer, finish, confirm
- Encrypted chat with sequence numbers, delivery ACKs, and visual pending/delivered states
- Encrypted file transfer: chunked at 16 KiB, SHA-256 integrity, accept/reject prompt, download link
- Same-tab auto-reconnect with exponential backoff and challenge-response resume
- Chat retransmission of unacknowledged messages after resume
- File transfer recovery: receiver sends a bitmap of received chunks, sender retransmits only missing ones
- Ctrl+Enter to send, auto-scroll, session fingerprint display
- `beforeunload` handler sends explicit `leave_session` for immediate peer notification

## Protocol

### Handshake (4 messages)

1. **Offer** (Alice to Bob) — X25519 public key + nonce
2. **Answer** (Bob to Alice) — ML-KEM public key + X25519 public key + nonce
3. **Finish** (Alice to Bob) — ML-KEM ciphertext + HMAC proof
4. **Confirm** (Bob to Alice) — HMAC proof

Both sides derive identical `send_key`, `recv_key`, `handshake_key`, `fingerprint`, and `resume_key` from the combined ML-KEM + X25519 shared secrets.

### Chat messages

Each message carries a sequence number, random nonce, and ciphertext. AAD binds the protocol version, session ID, sender role, and sequence number. The receiver ACKs each message; the sender shows pending/delivered status.

### File transfer

Files are split into 16 KiB chunks. Control messages (`file_offer`, `file_accept`, `file_complete`) travel as JSON text frames. Encrypted chunks travel as binary WebSocket frames:

```
[ transfer_id: 16 bytes ][ chunk_index: 4 bytes BE ][ nonce: 24 bytes ][ ciphertext ]
```

Chunk AAD binds the protocol version, session ID, sender role, transfer ID, chunk index, declared file size, total chunk count, and the file's SHA-256 digest. The receiver verifies exact size and SHA-256 match at completion.

### Session resume

On transport disconnect (network drop, not explicit leave), the server holds the session open for 30 seconds. The client auto-reconnects and proves identity via challenge-response:

1. Client sends `resume_session { session_id, role }`
2. Server sends `resume_challenge { nonce }`
3. Client sends `resume_proof { resume_key, mac }` where `mac = HMAC-SHA256(resume_key, nonce || session_id || role)`
4. Server verifies `SHA-256(resume_key) == stored_verifier` and checks the MAC

After resume, unacknowledged chat messages are retransmitted and partial file transfers continue from where they left off.

## Deployment

### Production (Docker + nginx + Cloudflare)

```bash
# First-time server setup (Ubuntu)
sudo ./setup-server.sh

# Deploy
git clone <repo> /opt/lattice
cd /opt/lattice
docker compose up -d --build
```

The Docker Compose stack runs three services:

- **app** — Rust server binary + built client assets, non-root user, read-only filesystem
- **nginx** — TLS termination with self-signed origin cert (Cloudflare handles public TLS), Cloudflare IP ranges for real IP detection, rate limiting, gzip, security headers
- **certgen** — one-shot Alpine container that generates a self-signed certificate on first boot

Cloudflare settings: DNS proxied (orange cloud), SSL mode **Full**.

### Local development

```bash
# Terminal 1: Rust server
cargo run -p lattice-server

# Terminal 2: Client dev server with hot reload
cd client && npm install && npm run dev
```

### Local Docker test

```bash
docker compose up --build
# Open http://localhost:3000/join
```

## Security properties

| Property | Status |
|---|---|
| Server cannot read messages | Yes, if client code is trusted |
| Post-quantum key exchange | Yes, ML-KEM-768 + X25519 hybrid |
| Forward secrecy | Yes, all keys are ephemeral per session |
| Replay protection | Yes, sequence numbers + bounded dedup cache |
| MITM detection | Yes, invite secret bound into key derivation + session fingerprint |
| File integrity | Yes, per-chunk AEAD + whole-file SHA-256 |
| No persistence | Yes, no database, no localStorage, no IndexedDB |

### Limitations

- No long-term identity — each session is independent
- No offline messaging — both participants must be online
- No message history after page refresh
- If the operator controls both the relay and client delivery, a malicious client bundle can exfiltrate plaintext

## Tech stack

| Component | Technology |
|---|---|
| Server | Rust, Axum, Tokio, WebSocket |
| Crypto | ML-KEM-768, X25519, HKDF-SHA256, XChaCha20-Poly1305, HMAC-SHA256 |
| WASM | wasm-bindgen, compiled from the same Rust crypto crate |
| Client | React 19, TypeScript, Vite 7 |
| Deployment | Docker, nginx, Cloudflare |
| Testing | cargo test (Rust), vitest (TypeScript) |

## Tests

```bash
# Rust (crypto + server)
cargo test --workspace

# Client (recovery helpers)
cd client && npm test

# Type check
cd client && npx tsc -b

# WASM rebuild
bash scripts/build-wasm.sh
```

## License

MIT
