export type SessionRole = "alice" | "bob";

export type ClientEvent =
  | { type: "join_session"; session_id: string; role: SessionRole }
  | { type: "handshake_offer"; offer_x25519_public: string; alice_nonce: string }
  | {
      type: "handshake_answer";
      bob_mlkem_public: string;
      bob_x25519_public: string;
      bob_nonce: string;
    }
  | { type: "handshake_finish"; kem_ciphertext: string; mac: string }
  | { type: "handshake_confirm"; mac: string }
  | { type: "chat_message"; seq: number; nonce: string; ciphertext: string }
  | { type: "chat_ack"; seq: number }
  | {
      type: "file_offer";
      transfer_id: string;
      name: string;
      mime_type: string;
      size: number;
      total_chunks: number;
      sha256: string;
    }
  | { type: "file_accept"; transfer_id: string }
  | { type: "file_reject"; transfer_id: string }
  | { type: "file_complete"; transfer_id: string }
  | { type: "file_abort"; transfer_id: string; reason: string }
  | { type: "file_resume_state"; transfer_id: string; received_bitmap: string }
  | { type: "register_resume"; verifier: string }
  | { type: "resume_session"; session_id: string; role: SessionRole }
  | { type: "resume_proof"; resume_key: string; mac: string }
  | { type: "leave_session" }
  | { type: "ping" };

export type ServerEvent =
  | { type: "joined_session"; role: SessionRole; expires_in_seconds: number }
  | { type: "peer_joined" }
  | { type: "relay_handshake_offer"; offer_x25519_public: string; alice_nonce: string }
  | {
      type: "relay_handshake_answer";
      bob_mlkem_public: string;
      bob_x25519_public: string;
      bob_nonce: string;
    }
  | { type: "relay_handshake_finish"; kem_ciphertext: string; mac: string }
  | { type: "relay_handshake_confirm"; mac: string }
  | { type: "relay_chat_message"; seq: number; nonce: string; ciphertext: string }
  | { type: "relay_chat_ack"; seq: number }
  | {
      type: "relay_file_offer";
      transfer_id: string;
      name: string;
      mime_type: string;
      size: number;
      total_chunks: number;
      sha256: string;
    }
  | { type: "relay_file_accept"; transfer_id: string }
  | { type: "relay_file_reject"; transfer_id: string }
  | { type: "relay_file_complete"; transfer_id: string }
  | { type: "relay_file_abort"; transfer_id: string; reason: string }
  | { type: "relay_file_resume_state"; transfer_id: string; received_bitmap: string }
  | { type: "resume_challenge"; nonce: string }
  | { type: "resume_accepted" }
  | { type: "peer_reconnected" }
  | { type: "peer_left" }
  | { type: "session_expired" }
  | { type: "pong" }
  | { type: "error"; message: string };
