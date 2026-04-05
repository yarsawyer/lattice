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
- attachments in the first implementation

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

- either client disconnects and does not reconnect within a short grace period
- either client explicitly ends the chat
- session TTL expires

On termination:

- both clients erase session keys from memory
- server erases all in-memory session and ciphertext buffers

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
- optional short-lived ciphertext queue for transient reconnects within the same live session

No database is used. If the process restarts, all sessions are lost.

Reconnect scope is intentionally narrow:

- reconnect is allowed only for brief network interruptions while the tab remains open and the client's in-memory session keys still exist
- page refresh, browser restart, or renderer crash destroys local key material and therefore cannot resume the encrypted session
- the short-lived ciphertext queue exists only to bridge transport interruptions measured in seconds, not to provide offline delivery

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

Client to server:

- `join_session`
- `handshake_offer`
- `handshake_answer`
- `handshake_finish`
- `handshake_confirm`
- `chat_message`
- `chat_ack`
- `leave_session`
- `ping`

Server to client:

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

The server validates routing and session membership only. It must not parse or inspect encrypted message payloads beyond frame shape and size limits.

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

Refreshing the page destroys the session unless an explicit in-memory reconnect flow is still active in the same tab.

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

## Final Notes

This design is much simpler than an offline messenger and matches the constraints you described. It is a secure live rendezvous chat if implemented carefully, but it does not provide long-term identity continuity or offline delivery. If those requirements return later, the architecture will need a real identity and prekey system rather than incremental patches.
