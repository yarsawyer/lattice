use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    Alice,
    Bob,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientEvent {
    JoinSession {
        session_id: String,
        role: SessionRole,
    },
    HandshakeOffer {
        offer_x25519_public: String,
        alice_nonce: String,
    },
    HandshakeAnswer {
        bob_mlkem_public: String,
        bob_x25519_public: String,
        bob_nonce: String,
    },
    HandshakeFinish {
        kem_ciphertext: String,
        mac: String,
    },
    HandshakeConfirm {
        mac: String,
    },
    ChatMessage {
        seq: u64,
        nonce: String,
        ciphertext: String,
    },
    ChatAck {
        seq: u64,
    },
    FileOffer {
        transfer_id: String,
        name: String,
        mime_type: String,
        size: u64,
        total_chunks: u32,
        sha256: String,
    },
    FileAccept {
        transfer_id: String,
    },
    FileReject {
        transfer_id: String,
    },
    FileComplete {
        transfer_id: String,
    },
    FileAbort {
        transfer_id: String,
        reason: String,
    },
    FileResumeState {
        transfer_id: String,
        received_bitmap: String,
    },
    RegisterResume {
        verifier: String,
    },
    ResumeSession {
        session_id: String,
        role: SessionRole,
    },
    ResumeProof {
        resume_key: String,
        mac: String,
    },
    LeaveSession,
    Ping,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    JoinedSession {
        role: SessionRole,
        expires_in_seconds: u64,
    },
    PeerJoined,
    RelayHandshakeOffer {
        offer_x25519_public: String,
        alice_nonce: String,
    },
    RelayHandshakeAnswer {
        bob_mlkem_public: String,
        bob_x25519_public: String,
        bob_nonce: String,
    },
    RelayHandshakeFinish {
        kem_ciphertext: String,
        mac: String,
    },
    RelayHandshakeConfirm {
        mac: String,
    },
    RelayChatMessage {
        seq: u64,
        nonce: String,
        ciphertext: String,
    },
    RelayChatAck {
        seq: u64,
    },
    RelayFileOffer {
        transfer_id: String,
        name: String,
        mime_type: String,
        size: u64,
        total_chunks: u32,
        sha256: String,
    },
    RelayFileAccept {
        transfer_id: String,
    },
    RelayFileReject {
        transfer_id: String,
    },
    RelayFileComplete {
        transfer_id: String,
    },
    RelayFileAbort {
        transfer_id: String,
        reason: String,
    },
    RelayFileResumeState {
        transfer_id: String,
        received_bitmap: String,
    },
    ResumeChallenge {
        nonce: String,
    },
    ResumeAccepted,
    PeerReconnected,
    PeerLeft,
    SessionExpired,
    Error {
        message: String,
    },
    Pong,
}

#[derive(Debug, Clone)]
pub enum RelayPayload {
    Event(ServerEvent),
    Binary(Vec<u8>),
}
