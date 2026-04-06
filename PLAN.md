# Lattice: Ephemeral 1:1 Secure Chat Plan

## Goal

Build a live end-to-end encrypted 1:1 chat system with these properties:

- Alice creates a session through the server
- the server returns a shareable join link
- Bob opens the link and joins the same live session
- Alice and Bob perform an end-to-end key exchange through the relay
- all chat traffic is encrypted client-to-client
- the server routes ciphertext and coordination messages only
- no database is used
- no long-term key storage is used in the browser

This is an ephemeral secure chat system, not an offline messenger. Both participants must be online at the same time to establish and use the session.

## Scope

Included:

- 1:1 live chat
- one active session with exactly two participants
- ephemeral in-memory session state
- end-to-end encrypted text messages
- session link sharing
- server relay over WebSocket

Excluded:

- offline messaging
- prekeys
- browser key persistence
- message history after disconnect or refresh
- multi-device support
- group chat
- attachments in the first text-only implementation (see Phase 7 below for the file transfer extension)

## Security Model

### Core guarantees

- the server cannot decrypt message contents if the client code is trusted
- message keys exist only in memory on each client
- session state is destroyed when either side leaves or the session expires
- ciphertext integrity is enforced with authenticated encryption
- replayed ciphertexts inside a live session can be detected and rejected

### Important limitations

- there is no long-term identity system in this design
- there is no recovery of chat history after page reload, browser restart, or disconnect
- if the same operator controls both the relay and the web client delivery, a malicious client bundle can still exfiltrate plaintext and keys
- without an authentication secret bound into the handshake, the relay could mount a man-in-the-middle attack during key exchange

### Authentication model for this design

Because there is no persistent identity key, session authentication must come from the invite link itself.

The link must be split into two values with different visibility:

- `session_id`: public routing identifier visible to the server
- `invite_secret`: high-entropy secret visible to the clients only

Recommended URL shape:

```text
/join?sid=<session_id>#secret=<invite_secret>
```

Important behavior:

- the query string is sent to the server, so the relay sees `session_id`
- the fragment after `#` is not sent in the HTTP request, so the relay does not learn `invite_secret` from normal request handling
- client-side code can read `invite_secret` from `window.location.hash`

Alice should generate `invite_secret` locally and derive:

- `session_id = SHA-256(invite_secret || protocol_version)`

That gives the server a stable room identifier without giving it the secret that authenticates the handshake.

The handshake must bind `invite_secret` into key derivation and handshake verification. That does not create long-term identity, but it does prevent the relay from silently rewriting the initial key exchange unless it can also steal the fragment secret.

Optional but recommended:

- display a short session fingerprint or safety code on both clients after handshake so Alice and Bob can verbally confirm they derived the same session

## Architecture

### Stack

- Rust server with Axum and WebSocket support
- React and TypeScript client
- shared Rust crypto crate compiled to WASM for browser use

### Monorepo layout

```text
lattice/
|- Cargo.toml
|- crypto/
|  |- Cargo.toml
|  `- src/
|     |- lib.rs
|     |- kem.rs
|     |- aead.rs
|     |- envelope.rs
|     |- session.rs
|     |- x25519.rs
|     |- types.rs
|     |- errors.rs
|     `- wasm.rs
|- server/
|  |- Cargo.toml
|  `- src/
|     |- main.rs
|     |- config.rs
|     |- session/
|     |- ws/
|     |- api/
|     `- middleware/
|- client/
|  |- package.json
|  |- vite.config.ts
|  `- src/
|     |- main.tsx
|     |- App.tsx
|     |- api/
|     |- crypto/
|     |- stores/
|     |- components/
|     `- hooks/
`- scripts/
   |- build-wasm.sh
   `- dev.sh
```

## Session Lifecycle

### 1. Session creation

Alice generates `invite_secret` locally, derives `session_id`, and then requests a new session from the server using that `session_id`.

The server creates in-memory session state:

- `session_id`
- `created_at`
- `expires_at`
- `alice_connection_id`
- `bob_connection_id` set to empty until Bob joins
- handshake state
- relay message counters and replay cache

The server returns a join link to Alice, for example:

```text
/join?sid=<session_id>#secret=<invite_secret>
```

Alice sends that link to Bob over any out-of-band channel.

### 2. Bob joins

Bob opens the link and connects to the server with:

- `session_id`

The server validates:

- session exists
- session is not expired
- Bob is the second participant
- provided `session_id` matches the waiting session

If valid, the server attaches Bob to the session and allows the handshake to start.

Client-side validation:

- Bob's client reads `invite_secret` from the URL fragment
- Bob's client recomputes `SHA-256(invite_secret || protocol_version)`
- Bob's client confirms that it matches the `session_id` in the query string before continuing

### 3. End-to-end handshake

Both clients generate ephemeral key material in memory only.

Minimum key material per client:

- ephemeral ML-KEM keypair
- ephemeral X25519 keypair
- random client nonce

Handshake flow:

1. Alice generates ephemeral keys when the session is created.
2. Bob generates ephemeral keys when he opens the join link.
3. Alice sends her ephemeral X25519 public key and nonce through the relay.
4. Bob sends his ephemeral public keys and nonce through the relay.
5. Alice, as session initiator, encapsulates to Bob's ML-KEM public key. Bob does not perform a reverse ML-KEM encapsulation in this first design.
6. Both sides compute:
   - the same ML-KEM shared secret from Alice's encapsulation and Bob's decapsulation
   - the same X25519 shared secret from their ephemeral X25519 public keys
7. Both sides derive a session master secret using HKDF over:
   - ML-KEM shared secret
   - X25519 shared secret
   - `session_id`
   - `invite_secret`
   - Alice nonce
   - Bob nonce
   - handshake transcript hash
8. Both sides derive:
   - `send_key`
   - `recv_key`
   - session fingerprint
9. Both sides exchange a handshake-finished MAC derived from the master secret.
10. If MAC validation succeeds, chat becomes active.

The relay forwards handshake messages but cannot complete the handshake unless it also learns the fragment secret.

### 4. Live messaging

After handshake:

- Alice encrypts outgoing messages with her `send_key`
- Bob decrypts them with his `recv_key`
- Bob encrypts outgoing messages with his `send_key`
- Alice decrypts them with her `recv_key`

### 5. Session termination

The session ends when:

- either client explicitly ends the chat via `leave_session`
- session TTL expires
- a disconnected client does not resume within the grace period (see Phase 8)

On termination:

- both clients erase session keys from memory
- server erases all in-memory session and ciphertext buffers

A transport-level disconnect (network drop, browser tab crash) does not immediately end the session. The server holds the role slot open for a short grace period to allow same-tab reconnection. If the client does not resume within the window, the session terminates as above. See Phase 8 for the full reconnection design.

## Protocol Design

### Cryptographic building blocks

- ML-KEM-768 for post-quantum KEM
- X25519 for hybrid contribution
- HKDF-SHA256 for key derivation
- XChaCha20-Poly1305 preferred for message encryption

XChaCha20-Poly1305 is preferred here because the system is ephemeral and browser-based, and it avoids the brittle nonce-management requirements of AES-GCM counters.

### Key derivation

Derive keys in layers:

1. `master_secret = HKDF-Extract(salt = SHA-256(session_id || invite_secret), ikm = mlkem_ss || x25519_ss)`
2. `traffic_secret = HKDF-Expand(master_secret, "lattice-traffic-v1", 64)`
3. split into:
   - Alice send / Bob receive key
   - Bob send / Alice receive key
4. derive:
   - handshake confirmation key
   - session fingerprint material
   - resume key (for same-tab reconnection; see Phase 8)

The transcript hash must include all handshake messages so field swapping or key substitution is detected.

Because `session_id` is already derived from `invite_secret`, including both values in the salt is slightly redundant. That is acceptable here because the intent is domain separation and explicit binding of both the server-visible room identifier and the client-only invite secret into the final transcript.

### Message envelope

Each encrypted message contains:

- protocol version
- session id
- sender role: `alice` or `bob`
- message sequence number
- random nonce
- ciphertext

Authenticated associated data must include:

- protocol version
- session id
- sender role
- message sequence number

### Replay protection

Each side keeps in memory:

- highest inbound sequence number seen
- small replay window or exact set for recent message numbers

The client must reject:

- duplicate sequence numbers
- messages from the wrong sender role
- messages with invalid AEAD tags
- messages for a different session id

Because there is no persistence, replay protection only lasts for the life of the live session.

## Server Design

### Responsibilities

- create ephemeral sessions
- validate join links
- pair Alice and Bob into exactly one live session
- relay handshake frames
- relay encrypted chat frames
- enforce session TTL and participant count
- never persist session contents

### In-memory session model

Each session holds:

- session metadata
- two active WebSocket channels at most
- handshake progress state
- small replay and deduplication cache for transport-level frame ids

No database is used. If the process restarts, all sessions are lost.

Disconnect handling:

- transport-level disconnects (network drop, tab crash) enter a grace period; the session stays alive and the role slot is held open for reconnection (see Phase 8)
- explicit `leave_session` ends the session immediately with no grace period
- page refresh or browser restart destroys local key material, so reconnection is not possible even if the server-side grace period is still open
- if the grace period expires without a resume, the session terminates and the peer receives `peer_left`

### API surface

```text
POST   /api/v1/sessions
GET    /join
GET    /api/v1/ws
POST   /api/v1/sessions/:id/close
```

Suggested behavior:

- `POST /api/v1/sessions` creates a session and returns the join link
- `/join` serves the client app and bootstrap session parameters
- `/api/v1/ws` upgrades to WebSocket and attaches to a session
- `POST /api/v1/sessions/:id/close` lets Alice explicitly end the session

### WebSocket event types

Client to server (text frames):

- `join_session`
- `handshake_offer`
- `handshake_answer`
- `handshake_finish`
- `handshake_confirm`
- `chat_message`
- `chat_ack`
- `leave_session`
- `ping`
- `file_offer` (Phase 7)
- `file_accept` (Phase 7)
- `file_reject` (Phase 7)
- `file_complete` (Phase 7)
- `file_abort` (Phase 7)
- `register_resume` (Phase 8)
- `resume_session` (Phase 8)
- `resume_proof` (Phase 8)
- `file_resume_state` (Phase 9)

Client to server (binary frames):

- encrypted file chunk (Phase 7)

Server to client (text frames):

- `peer_joined`
- `joined_session`
- `relay_handshake_offer`
- `relay_handshake_answer`
- `relay_handshake_finish`
- `relay_handshake_confirm`
- `relay_chat_message`
- `relay_chat_ack`
- `peer_left`
- `session_expired`
- `error`
- `pong`
- `relay_file_offer` (Phase 7)
- `relay_file_accept` (Phase 7)
- `relay_file_reject` (Phase 7)
- `relay_file_complete` (Phase 7)
- `relay_file_abort` (Phase 7)
- `resume_challenge` (Phase 8)
- `resume_accepted` (Phase 8)
- `peer_reconnected` (Phase 8)
- `relay_file_resume_state` (Phase 9)

Server to client (binary frames):

- relayed encrypted file chunk (Phase 7)

The server validates routing and session membership for all frames. It must not parse or inspect encrypted message payloads beyond frame shape and size limits. Binary frames are relayed without inspection. In Phase 8, the server additionally validates resume proofs: it stores a `resume_verifier` per role, issues challenge nonces, and verifies `resume_proof` MACs before reattaching a socket. This is the only server-side cryptographic verification; all other crypto is client-to-client.

### Operational controls

- short session TTL, for example 15 to 60 minutes
- strict two-participant maximum
- rate limiting on session creation and handshake frames
- maximum message size
- no plaintext logging
- no logging of URL fragments in client telemetry or frontend error reporting
- best effort memory cleanup on session close

## Client Design

### Storage model

The client stores no long-term secrets.

Allowed in browser memory only:

- ephemeral private keys
- derived session keys
- sequence counters
- replay window state

Not allowed in IndexedDB or localStorage:

- session master secret
- traffic keys
- private keys
- plaintext message history

Refreshing the page destroys the session and requires creating a new one.

### UI requirements

- Alice can create a session and copy a join link
- Bob can open the join link and join the waiting session
- chat remains disabled until handshake success
- both users see handshake status
- both users see a session fingerprint after handshake
- both users see clear indication when the peer disconnects or the session expires

### Browser hardening

- strict CSP
- no third-party runtime scripts
- no analytics that can capture message contents
- no logging of secrets, plaintext, or invite links
- immutable versioned client assets where practical

### WASM integration

- build the Rust crypto crate with `wasm-bindgen` and `wasm-pack`
- load the generated package into the Vite client through a small `client/src/crypto/` wrapper
- keep binary serialization logic inside the Rust crate so TypeScript only handles typed byte arrays and envelope framing

## Implementation Phases

### Phase 1: Repository and crypto crate

- create workspace structure
- implement ML-KEM, X25519, HKDF, and XChaCha20-Poly1305 wrappers
- implement session key derivation and transcript hashing
- implement `wasm-bindgen` exports and `wasm-pack` build flow for Vite consumption
- add native and WASM interop tests

### Phase 2: Server session relay

- implement in-memory session registry
- implement session creation from client-derived `session_id`
- implement WebSocket connection management
- implement two-party session enforcement
- implement session expiration and cleanup

### Phase 3: Handshake protocol

- implement client ephemeral key generation
- implement relay-based handshake frames
- implement KEM plus X25519 shared secret derivation
- implement transcript-bound HKDF
- implement handshake-finished MAC verification
- implement session fingerprint display

### Phase 4: Encrypted chat transport

- implement encrypted message envelopes
- implement sequence numbering and replay rejection
- implement acknowledgements and basic delivery state
- implement disconnect and termination handling

### Phase 5: Client application

- create session flow for Alice
- join session flow for Bob
- waiting room state before Bob joins
- active chat UI after handshake
- end session and expired session UI

### Phase 6: Hardening and verification

- audit logs and network traces for leakage
- enforce CSP and token handling rules
- add rate limiting and message size limits
- test relay restart behavior and session cleanup
- document exact security guarantees and non-guarantees

### Phase 7: Encrypted file transfer

- add binary WebSocket frame handling to the server relay
- add file control messages to the protocol (`file_offer`, `file_accept`, `file_reject`, `file_complete`, `file_abort`)
- add `build_file_chunk_aad` to the crypto crate envelope module and WASM exports
- implement client-side chunking, encryption, and binary frame sending
- implement client-side chunk reception, decryption, reassembly, and Blob download
- add file picker UI and incoming file accept/reject prompt
- see the detailed design in Phase 7 section below

### Phase 8: Same-tab session resume

- extend HKDF output in the crypto crate to include `resume_key`
- add `register_resume`, `resume_session`, `resume_proof`, `resume_challenge`, `resume_accepted`, `peer_reconnected` protocol messages
- implement grace period in server session registry (hold role slot open on disconnect)
- implement challenge-response verification on the server using stored `resume_verifier`
- implement client-side auto-reconnect with resume proof
- see the detailed design in Phase 8 section below

### Phase 9: Delivery recovery after resume

- extend chat ACK handling from UI-only status to actual pending outbound delivery tracking
- retain unacknowledged outbound chat messages in memory and retransmit them after `resume_accepted`
- preserve partial file-transfer state across same-tab reconnects instead of aborting immediately
- add `file_resume_state` protocol message so the receiver can tell the sender which chunks were already received
- retransmit only missing file chunks after resume; reuse existing `file_complete` once the transfer finishes
- document sender-side file-state tradeoffs: keep encrypted/plaintext data in memory for simplicity, or keep a `File` handle and re-slice/re-encrypt on demand to reduce peak retained memory
- see the detailed design in Phase 9 section below

## Verification

### Crypto tests

- ML-KEM roundtrip
- X25519 agreement
- transcript hash stability
- HKDF derivation consistency
- XChaCha20-Poly1305 encrypt/decrypt vectors
- native and WASM handshake interop

### Server tests

- create session
- join with valid `session_id`
- reject unknown or expired `session_id`
- reject third participant
- expire idle session
- cleanup after disconnect

### End-to-end tests

- Alice creates session and Bob joins
- handshake succeeds and chat becomes enabled
- Alice sends encrypted message to Bob
- Bob sends encrypted message to Alice
- duplicate frame replay is rejected
- session closes when peer leaves or TTL expires

### Manual checks

- inspect server logs for absence of plaintext, invite-link leakage, and any accidental fragment capture in frontend telemetry
- verify no IndexedDB or localStorage secrets are written
- inspect relay traffic and confirm message bodies are ciphertext only
- verify page refresh destroys local session state

## Phase 7: Encrypted File Transfer

### Motivation

The text chat transport (Phases 1-6) is sized for small JSON messages: 32 KiB WebSocket frame cap, 12 KiB base64 field limit, UTF-8 string encoding throughout. Reusing `chat_message` for file data would require base64-encoding binary content inside JSON text frames, wasting ~33% bandwidth and creating memory pressure in the browser for large files. The relay has no chunk-level delivery control and no file-level resume mechanism.

A clean file transfer extension must address these constraints without changing the existing chat protocol. In Phase 7 alone, a transport-level disconnect aborts any in-progress file transfer even if the chat session itself resumes via Phase 8. Phase 9 extends this with file-transfer recovery after reconnect.

### Design principles

- the server remains a dumb relay: it routes frames by session and role, enforces size and rate limits, but never inspects file content
- text WebSocket frames carry JSON control messages (offers, accepts, completions, aborts)
- binary WebSocket frames carry encrypted file chunks, avoiding base64 overhead entirely
- file encryption reuses the existing `send_key`/`recv_key` and XChaCha20-Poly1305 AEAD
- each chunk has its own AAD binding to prevent reordering and substitution

### Constraints

- maximum file size: 100 MB — the receiver buffers all chunks in memory before assembling the Blob, so this cap prevents memory exhaustion in the browser; the server streams chunks without buffering and does not enforce this limit itself
- chunk size: 16 KiB plaintext (produces ~16 KiB + 16 bytes tag + 24 bytes nonce per chunk, well within a 32 KiB binary frame)
- maximum concurrent transfers: 1 per direction (no interleaved multi-file transfers in v1)

### Wire format

#### Control messages (JSON text frames)

Client to server:

- `file_offer { transfer_id, name, mime_type, size, total_chunks, sha256 }`
- `file_accept { transfer_id }`
- `file_reject { transfer_id }`
- `file_complete { transfer_id }`
- `file_abort { transfer_id, reason }`

Server to client:

- `relay_file_offer { transfer_id, name, mime_type, size, total_chunks, sha256 }`
- `relay_file_accept { transfer_id }`
- `relay_file_reject { transfer_id }`
- `relay_file_complete { transfer_id }`
- `relay_file_abort { transfer_id, reason }`

`transfer_id` is a random hex string generated by the sender, unique within the session.
`sha256` is the lowercase hex SHA-256 digest of the original unencrypted file bytes. It is part of the file manifest and must remain constant for the whole transfer.

#### File chunks (binary WebSocket frames)

Each binary frame is a raw byte sequence:

```text
[ transfer_id: 16 bytes ][ chunk_index: 4 bytes big-endian ][ nonce: 24 bytes ][ ciphertext: variable ]
```

The AEAD authenticated associated data for each chunk must include:

- protocol version
- session id
- sender role
- transfer id
- chunk index
- declared file size
- declared total chunk count
- file SHA-256 digest

This binds every chunk to a specific transfer, position, session, sender, and file manifest, preventing reordering, substitution, cross-session replay, or relay tampering with the advertised file digest.

### Transfer lifecycle

1. Alice selects a file.
2. Alice computes `sha256 = SHA-256(file_bytes)` over the original unencrypted file bytes, then sends `file_offer` with metadata: `transfer_id`, filename, MIME type, byte size, `total_chunks = ceil(size / 16384)`, and `sha256`.
3. Bob receives `relay_file_offer` and the UI shows an accept/reject prompt.
4. Bob sends `file_accept` (or `file_reject` to cancel).
5. Alice receives `relay_file_accept` and begins sending binary chunk frames in order.
6. Bob receives each binary frame, decrypts, verifies the chunk index, and incrementally hashes the decrypted bytes with SHA-256. Bob aborts the transfer if the chunk index exceeds `total_chunks` or accumulated plaintext exceeds the declared `size`.
7. After the last chunk, Alice sends `file_complete`.
8. Bob receives `relay_file_complete`, verifies that all expected chunks were received, that the assembled plaintext size equals the declared `size` exactly, and that the computed SHA-256 digest equals the advertised `sha256`, then renders a download link in the chat.

Either side can send `file_abort` at any point to cancel the transfer. On abort, the receiving side discards buffered chunks.

### Server relay changes

- accept binary WebSocket frames in addition to text frames
- binary frames are relayed to the peer without inspection, subject to:
  - per-frame size limit (32 KiB)
  - per-IP rate limiting (reuse existing `ws-frame` rate limiter)
  - session membership check (sender must be joined)
- no chunk-level state on the server: no reassembly, no ACK tracking, no retransmission
- dedup cache is not applied to binary frames (chunk ordering is the client's responsibility)

### Client changes

- add file input button in the composer area
- send binary frames via `WebSocket.send(ArrayBuffer)` instead of JSON for chunk data
- receive binary frames via `message` event with `event.data instanceof ArrayBuffer`
- compute `sha256` over the original file bytes before sending `file_offer`
- reassemble chunks in memory, compute SHA-256 incrementally over decrypted bytes, construct a Blob, and create an object URL for download; abort if received chunk count exceeds `total_chunks`, accumulated plaintext exceeds the declared `size` from the offer, or the final SHA-256 digest does not match the offered `sha256`
- display incoming file offers as an accept/reject prompt in the message thread
- display completed files as download links with filename and size
- abort on disconnect: if the WebSocket closes mid-transfer, discard partial buffers and mark the transfer as failed; even if the chat session resumes (Phase 8), the file transfer does not resume — the sender must re-offer

### Crypto crate changes

- add `build_file_chunk_aad(session_id, sender_role, transfer_id, chunk_index, declared_size, total_chunks, file_sha256)` to `envelope.rs`
- export via `wasm-bindgen` in `wasm.rs`
- no new primitives needed: file chunks use the same `encrypt_message`/`decrypt_message`

### Verification

- file offer/accept/reject roundtrip
- single-chunk file (< 16 KiB) transfer and decryption
- multi-chunk file transfer with correct reassembly
- chunk with wrong transfer_id or chunk_index rejected by AEAD
- chunk with wrong file manifest metadata (`size`, `total_chunks`, or `sha256`) rejected by AEAD
- file_abort mid-transfer discards partial state
- large file (multiple MB, many chunks) transfers and completes correctly
- file exceeding 100 MB rejected client-side before offer
- binary frame exceeding 32 KiB rejected server-side
- final SHA-256 mismatch at `file_complete` is rejected
- transfer survives interleaved chat messages (chat and file use separate frame types)

## Phase 8: Same-Tab Session Resume

### Scope

Recovery is supported only when the browser tab is still alive and session keys remain in memory. This covers transient network drops and WebSocket connection resets. It does not cover page refresh, browser restart, or cross-device resumption — those destroy local key material and require a new session.

### Crypto changes

Extend the HKDF output in `crypto/src/session.rs` by `RESUME_KEY_LEN` (32 bytes). The expanded output becomes:

```text
[ alice_send_key: 32 ][ bob_send_key: 32 ][ handshake_key: 32 ][ fingerprint: 16 ][ resume_key: 32 ]
```

The `resume_key` is derived from the same master secret as all other keys, bound to the same transcript hash, invite secret, and nonces. No additional HKDF call is needed — just a longer output from the existing `HKDF-Expand`.

After handshake, the client computes `resume_verifier = SHA-256(resume_key)` and registers it with the server. During resume, the client reveals `resume_key` to prove possession. The server verifies it against the stored verifier. This means the server learns `resume_key` during a resume, but `resume_key` is not used for message encryption (it is separate from `send_key`/`recv_key`), so this does not weaken message confidentiality.

### Protocol messages

Client to server:

- `register_resume { verifier }` — sent once after handshake completes; `verifier` is hex-encoded `SHA-256(resume_key)`
- `resume_session { session_id, role }` — sent as the first frame on a reconnecting socket (instead of `join_session`)
- `resume_proof { resume_key, mac }` — sent in response to `resume_challenge`; `mac = HMAC-SHA256(resume_key, nonce || session_id || role)`

Server to client:

- `resume_challenge { nonce }` — sent after receiving a valid `resume_session` for a role slot in grace period
- `resume_accepted` — sent after successful verification; the client continues with existing keys
- `peer_reconnected` — sent to the other peer when their partner successfully resumes

### Server changes

#### Session state

Add to the role state:

```text
resume_verifier: Option<[u8; 32]>     — set by register_resume
disconnected_at: Option<Instant>       — set on transport disconnect
```

#### Grace period

When a WebSocket drops (not an explicit `leave_session`):

1. Set `disconnected_at = Instant::now()` on the role slot
2. Clear the sender channel (socket is dead)
3. Do **not** send `peer_left` to the other side yet
4. Spawn a delayed task (grace period, 30 seconds):
   - if the role slot still has `disconnected_at` set when the timer fires, treat it as a full disconnect: send `peer_left` to the peer, clean up normally
   - if the client resumed before the timer fires, the task is a no-op

#### Resume flow

1. New socket connects, sends `resume_session { session_id, role }` as first frame (no MAC yet)
2. Server validates:
   - session exists and is not expired
   - the role slot has `disconnected_at` set (is in grace period)
   - the role slot has a `resume_verifier`
3. Server generates a random `challenge_nonce` and sends `resume_challenge { nonce }`
4. Client responds with `resume_proof { resume_key, mac }` where `mac = HMAC-SHA256(resume_key, nonce || session_id || role)`
5. Server verifies:
   - `SHA-256(resume_key) == stored resume_verifier` (proves the client derived the same key)
   - `HMAC-SHA256(resume_key, nonce || session_id || role) == mac` (proves freshness, prevents replay)
6. If both checks pass: clear `disconnected_at`, attach the new sender channel, cancel the grace period timer
7. Send `resume_accepted` to the resumed client
8. Send `peer_reconnected` to the other peer (if connected)
9. Both sides continue with the same keys; outbound sequence counters continue from where they left off

### Client changes

- After handshake completes, compute `resume_verifier = SHA-256(resume_key)` and send `register_resume { verifier }` to the server
- On WebSocket `close` event, do **not** clear `handshakeRef` — keep all keys and state in memory
- Start a reconnect loop: attempt to reopen the WebSocket after a short delay (1 second, then 2, then 4, up to 15 seconds)
- On new socket open, send `resume_session { session_id, role }` instead of `join_session`
- On receiving `resume_challenge { nonce }`, compute the MAC and send `resume_proof { resume_key, mac }`
- On receiving `resume_accepted`, update the status display and continue normally
- If the reconnect loop exceeds the grace period (30 seconds) or receives an error, give up and show "Session ended"

### Known limitations

- Phase 8 only restores the transport. Delivery recovery for unacknowledged chat messages and in-progress file transfers is handled in Phase 9, not here.
- If both peers disconnect simultaneously and both resume, both grace period timers run independently. Both can resume successfully as long as they return within the window.
- The `resume_key` is revealed to the server during the resume proof. This is acceptable because the server is already a trusted relay and the `resume_key` is not used for message encryption.
- Without Phase 9, an in-progress file transfer is aborted on disconnect even if the chat session resumes. File transfer recovery is specified separately to keep the transport-resume phase narrow.

### Verification

- client registers resume verifier after handshake
- transport disconnect enters grace period (peer does not receive `peer_left` immediately)
- client resumes within grace period: verification passes, session continues, peer receives `peer_reconnected`
- client resumes with wrong `resume_key`: rejected, connection closed
- challenge nonce is unique per resume attempt (replay of old `resume_proof` fails)
- grace period expires without resume: peer receives `peer_left`, session cleaned up
- explicit `leave_session` bypasses grace period: immediate `peer_left`
- both peers disconnect and both resume within grace period
- page refresh after disconnect cannot resume (keys lost, `resume_session` not sent)
- outbound sequence counters continue correctly after resume; inbound gaps from lost messages are tolerated

## Phase 9: Delivery Recovery After Resume

### Motivation

Phase 8 restores the socket and role slot, but it does not guarantee delivery of frames that were in flight when the transport broke. For chat, this means a message may have been encrypted and sent locally yet never acknowledged by the peer. For files, this means some chunks may have arrived while others were lost, forcing the whole transfer to restart.

This phase adds client-to-client recovery without changing the server into a queueing broker. The server remains a dumb relay. Delivery state stays in browser memory and is recovered only for same-tab reconnects that preserve local state.

### Design principles

- do not add server-side message or chunk buffering
- treat `chat_ack` as the source of truth for chat delivery completion
- keep recovery state in client memory only; refresh or browser restart still loses it
- retransmit only what is missing after resume, not the entire conversation or full file by default
- preserve end-to-end encryption and the existing session keys; retransmitted frames are encrypted under the same traffic keys

### Chat recovery

#### Client state

Maintain an in-memory `pending_outbound_messages` map keyed by chat sequence number. Each entry stores:

- `seq`
- serialized `chat_message` frame payload (`nonce`, `ciphertext`)
- plaintext preview for UI state if needed
- delivery state: `pending` or `acked`

When the user sends a chat message:

1. Allocate the next outbound sequence number.
2. Encrypt the plaintext and send `chat_message`.
3. Store the frame in `pending_outbound_messages`.
4. Mark it delivered only when `relay_chat_ack { seq }` arrives.

When `relay_chat_ack { seq }` arrives:

- remove the matching pending entry
- update UI delivery state

When a duplicate `relay_chat_message { seq, ... }` arrives after resume:

- if the receiver has already processed `seq`, do not append a second chat entry
- still send `chat_ack { seq }` again so the sender can stop retransmitting

#### Resume behavior

After `resume_accepted`:

1. Iterate pending outbound chat messages in ascending `seq` order.
2. Re-send every message that has not been acknowledged.
3. Keep the existing sequence numbers; do not allocate new ones for retransmits.

This gives at-least-once transport across reconnect, with receiver-side deduplication by sequence number yielding exactly-once user-visible chat entries.

### File transfer recovery

#### Protocol message

Add one new JSON control frame:

- `file_resume_state { transfer_id, received_bitmap }`

Server relay:

- `relay_file_resume_state { transfer_id, received_bitmap }`

`received_bitmap` is a base64-encoded bitset where bit `i` indicates whether chunk `i` has already been received and authenticated by the receiver. For the current 100 MB / 16 KiB limit, the bitmap is bounded and small enough for a text control frame.

Bitmap validation rules:

- the decoded bitmap length must equal `ceil(total_chunks / 8)` for the transfer manifest
- bits beyond `total_chunks` in the final byte must be zero
- the sender must reject or abort on malformed base64, wrong bitmap length, or any bitmap that claims impossible chunk indexes
- the bitmap is advisory resend state only; it must never override the sender's own manifest (`transfer_id`, `size`, `total_chunks`, `sha256`)

#### Receiver behavior

On transport disconnect during an incoming file transfer:

- do not discard partial chunk buffers immediately
- keep the manifest, chunk array, and received bitmap in memory while the Phase 8 grace/resume flow is active

After the session resumes and the peer is reachable:

1. Send `file_resume_state { transfer_id, received_bitmap }` for each partial incoming transfer.
2. Continue accepting chunks for missing indexes only.
3. If a duplicate chunk arrives for an already received index, ignore it and do not abort.
4. When `file_complete` arrives, verify:
   - all chunks are present
   - final assembled size equals declared `size`
   - SHA-256 of decrypted file bytes equals the manifest digest

If resume fails or the grace period expires:

- discard partial incoming transfer state

#### Sender behavior

On transport disconnect during an outgoing file transfer:

- keep resumable transfer state in memory while the Phase 8 grace/resume flow is active
- do not mark the transfer failed immediately

After resume, when `relay_file_resume_state { transfer_id, received_bitmap }` arrives:

1. Compare the receiver bitmap with local chunk count.
2. If the bitmap is malformed or inconsistent with the manifest, abort the transfer with `file_abort { reason }`.
3. Re-send only chunks whose bits are unset.
4. After all missing chunks are re-sent, send `file_complete` again.

The sender must retain enough local state to regenerate the missing chunks. Two implementation options are acceptable:

- simpler: keep the full plaintext file bytes in memory for the lifetime of the resumable transfer
- lower retained memory: keep a `File` handle and re-read slices from the File API, re-encrypting chunks on demand during retransmit

The first option is simpler to implement. The second is better for large files because it avoids retaining a second 100 MB buffer for the whole reconnect window.

### Server changes

No server queueing is added. The server only needs to:

- relay `file_resume_state` like any other control message
- continue enforcing existing frame size and rate limits
- preserve the Phase 8 role-slot grace period so the clients can exchange recovery state after reconnect
- validate only frame shape and size, not bitmap semantics; bitmap/manifest consistency is enforced end-to-end by the clients

### Client changes

- chat:
  - add pending outbound chat message storage keyed by `seq`
  - remove entries only on `relay_chat_ack`
  - on `resume_accepted`, resend all pending messages in order
  - ACK duplicate inbound messages without re-rendering them
- files:
  - stop aborting partial transfers immediately on socket close if resume is still possible
  - retain outgoing and incoming transfer state through the reconnect window
  - add bitmap generation/parsing helpers
  - send `file_resume_state` after reconnect for each partial incoming transfer
  - ignore duplicate file chunks instead of aborting
  - re-send only missing chunks on the sender side
- UI:
  - distinguish `pending`, `acked`, `reconnecting`, and `resuming transfer` states so the user can tell whether recovery is still in progress

### Known limitations

- recovery remains same-tab only; refresh, browser restart, or local state loss still destroy pending delivery state
- if both peers lose local state, no recovery is possible even if the server grace period has not expired
- retransmission is bounded by the 30-minute session TTL and the Phase 8 reconnect grace period
- the server still has no durable storage and cannot recover anything after process restart

### Verification

- unacknowledged outbound chat messages are retransmitted after `resume_accepted`
- duplicate retransmitted chat messages are not rendered twice, but are acknowledged again
- a message already acknowledged before disconnect is not retransmitted
- partial incoming file transfer survives reconnect and sends `file_resume_state`
- sender retransmits only missing file chunks, not already received chunks
- duplicate file chunks after resume are ignored, not treated as fatal
- malformed or inconsistent `file_resume_state` bitmaps are rejected and abort the transfer
- resumed file transfer verifies exact size and SHA-256 digest before completion
- if resume fails or grace expires, partial transfer state is discarded and the UI shows failure

## Final Notes

This design is much simpler than an offline messenger and matches the constraints you described. It is a secure live rendezvous chat if implemented carefully, but it does not provide long-term identity continuity or offline delivery. If those requirements return later, the architecture will need a real identity and prekey system rather than incremental patches.
