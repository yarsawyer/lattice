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
  | { type: "peer_left" }
  | { type: "session_expired" }
  | { type: "pong" }
  | { type: "error"; message: string };
