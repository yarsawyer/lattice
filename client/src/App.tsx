import { useEffect, useRef, useState } from "react";
import { createSession, wsBaseUrl } from "./api/client";
import type { ClientEvent, ServerEvent, SessionRole } from "./api/protocol";
import { loadCryptoModule } from "./crypto";

type ChatEntry = {
  id: string;
  from: "alice" | "bob" | "system";
  body: string;
};

type WasmCrypto = Awaited<ReturnType<typeof loadCryptoModule>>;

type HandshakeState = {
  inviteSecret: Uint8Array;
  sessionId: Uint8Array;
  sessionIdHex: string;
  role: SessionRole;
  aliceX25519?: { secret_key: Uint8Array; public_key: Uint8Array };
  bobX25519?: { secret_key: Uint8Array; public_key: Uint8Array };
  bobMlKem?: { secret_seed: Uint8Array; public_key: Uint8Array };
  aliceNonce?: Uint8Array;
  bobNonce?: Uint8Array;
  offerPart?: Uint8Array;
  answerPart?: Uint8Array;
  finishTranscriptHash?: Uint8Array;
  sendKey?: Uint8Array;
  recvKey?: Uint8Array;
  handshakeKey?: Uint8Array;
  fingerprint?: Uint8Array;
  seenInboundSeqs: Set<number>;
  nextOutboundSeq: number;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string) {
  if (hex.length % 2 !== 0) {
    throw new Error("invalid hex");
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function serializePart(label: string, fields: Record<string, string>) {
  const lines = [`type=${label}`];
  for (const [key, value] of Object.entries(fields)) {
    lines.push(`${key}=${value}`);
  }
  return encoder.encode(lines.join("\n"));
}

function deserializePart(encoded: Uint8Array) {
  const text = decoder.decode(encoded);
  const entries = text
    .split("\n")
    .slice(1)
    .map((line) => line.split("=", 2) as [string, string]);
  return Object.fromEntries(entries);
}

const heroSection = (
  <section className="hero">
    <p className="eyebrow">Ephemeral 1:1 secure chat</p>
    <h1>Lattice</h1>
    <p className="lede">
      Live post-quantum encrypted sessions with no database, no browser persistence, and an
      invite secret bound into the handshake.
    </p>
  </section>
);

function buildShareLink(sessionIdHex: string, inviteSecretHex: string) {
  const url = new URL("/join", window.location.origin);
  url.searchParams.set("sid", sessionIdHex);
  url.hash = `secret=${inviteSecretHex}`;
  return url.toString();
}

function App() {
  const [crypto, setCrypto] = useState<WasmCrypto | null>(null);
  const [status, setStatus] = useState("Loading crypto module\u2026");
  const [inviteLink, setInviteLink] = useState("");
  const [messages, setMessages] = useState<ChatEntry[]>([]);
  const [draft, setDraft] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [role, setRole] = useState<SessionRole | null>(null);
  const [sessionIdHex, setSessionIdHex] = useState("");
  const [error, setError] = useState("");

  const wsRef = useRef<WebSocket | null>(null);
  const handshakeRef = useRef<HandshakeState | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const sidFromUrl = new URLSearchParams(window.location.search).get("sid");
  const secretFromUrl = window.location.hash.startsWith("#secret=")
    ? window.location.hash.slice("#secret=".length)
    : "";

  useEffect(() => {
    let cancelled = false;

    void loadCryptoModule()
      .then((module) => {
        if (cancelled) {
          return;
        }

        setCrypto(module);
        setStatus("Ready");
      })
      .catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : "failed to load wasm crypto");
      });

    return () => {
      cancelled = true;
      wsRef.current?.close();
    };
  }, []);

  useEffect(() => {
    if (!crypto || !sidFromUrl) {
      return;
    }

    try {
      if (!secretFromUrl) {
        throw new Error("join link is missing the fragment secret");
      }

      const inviteSecret = hexToBytes(secretFromUrl);
      const derivedSessionId = crypto.derive_session_id(inviteSecret);
      const derivedSessionIdHex = bytesToHex(derivedSessionId);
      if (derivedSessionIdHex !== sidFromUrl) {
        throw new Error("join link is inconsistent: session id does not match invite secret");
      }

      setRole("bob");
      setSessionIdHex(derivedSessionIdHex);
      setStatus("Joining session...");
      handshakeRef.current = {
        inviteSecret,
        sessionId: derivedSessionId,
        sessionIdHex: derivedSessionIdHex,
        role: "bob",
        seenInboundSeqs: new Set<number>(),
        nextOutboundSeq: 1
      };
      connectWebSocket(derivedSessionIdHex, "bob");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "invalid join link");
    }
  }, [crypto, sidFromUrl, secretFromUrl]);

  function appendMessage(entry: ChatEntry) {
    setMessages((current) => [...current, entry]);
    requestAnimationFrame(() => {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    });
  }

  function connectWebSocket(targetSessionId: string, targetRole: SessionRole) {
    wsRef.current?.close();

    const socket = new WebSocket(wsBaseUrl());
    wsRef.current = socket;

    socket.addEventListener("open", () => {
      sendFrame({
        type: "join_session",
        session_id: targetSessionId,
        role: targetRole
      });
    });

    socket.addEventListener("message", (event) => {
      const payload = JSON.parse(String(event.data)) as ServerEvent;
      void handleServerEvent(payload).catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : "failed to process server event");
      });
    });

    socket.addEventListener("close", () => {
      setStatus("Disconnected");
    });
  }

  function sendFrame(frame: ClientEvent) {
    const socket = wsRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error("websocket is not connected");
    }

    socket.send(JSON.stringify(frame));
  }

  async function handleServerEvent(event: ServerEvent) {
    if (event.type === "error") {
      setError(event.message);
      return;
    }

    const handshake = handshakeRef.current;
    if (!crypto || !handshake) {
      return;
    }

    switch (event.type) {
      case "joined_session":
        setRole(event.role);
        setStatus(event.role === "alice" ? "Waiting for Bob to join\u2026" : "Waiting for Alice\u2026");
        break;
      case "peer_joined":
        setStatus("Peer connected. Starting handshake\u2026");
        if (handshake.role === "alice" && !handshake.offerPart) {
          const aliceX25519 = crypto.generate_x25519_keypair();
          const aliceNonce = crypto.generate_nonce();
          handshake.aliceX25519 = aliceX25519;
          handshake.aliceNonce = aliceNonce;

          const frame = {
            offer_x25519_public: bytesToBase64(aliceX25519.public_key),
            alice_nonce: bytesToBase64(aliceNonce)
          };
          handshake.offerPart = serializePart("handshake_offer", frame);
          sendFrame({ type: "handshake_offer", ...frame });
        }
        break;
      case "relay_handshake_offer": {
        if (handshake.role !== "bob") {
          break;
        }

        const bobMlKem = crypto.generate_mlkem_keypair();
        const bobX25519 = crypto.generate_x25519_keypair();
        const bobNonce = crypto.generate_nonce();
        handshake.bobMlKem = bobMlKem;
        handshake.bobX25519 = bobX25519;
        handshake.bobNonce = bobNonce;
        handshake.aliceNonce = base64ToBytes(event.alice_nonce);
        handshake.offerPart = serializePart("handshake_offer", {
          offer_x25519_public: event.offer_x25519_public,
          alice_nonce: event.alice_nonce
        });

        const frame = {
          bob_mlkem_public: bytesToBase64(bobMlKem.public_key),
          bob_x25519_public: bytesToBase64(bobX25519.public_key),
          bob_nonce: bytesToBase64(bobNonce)
        };
        handshake.answerPart = serializePart("handshake_answer", frame);
        sendFrame({ type: "handshake_answer", ...frame });
        setStatus("Sent handshake answer\u2026");
        break;
      }
      case "relay_handshake_answer": {
        if (handshake.role !== "alice" || !handshake.aliceX25519 || !handshake.aliceNonce || !handshake.offerPart) {
          break;
        }

        handshake.answerPart = serializePart("handshake_answer", {
          bob_mlkem_public: event.bob_mlkem_public,
          bob_x25519_public: event.bob_x25519_public,
          bob_nonce: event.bob_nonce
        });
        handshake.bobNonce = base64ToBytes(event.bob_nonce);

        const kem = crypto.encapsulate_mlkem(base64ToBytes(event.bob_mlkem_public));
        const x25519Secret = crypto.x25519_shared_secret(
          handshake.aliceX25519.secret_key,
          base64ToBytes(event.bob_x25519_public),
        );
        const transcriptHash = crypto.hash_transcript([handshake.offerPart, handshake.answerPart]);
        const secrets = crypto.derive_session_secrets(
          "alice",
          handshake.sessionId,
          handshake.inviteSecret,
          handshake.aliceNonce,
          handshake.bobNonce!,
          kem.shared_secret,
          x25519Secret,
          transcriptHash,
        );
        const finishTranscriptHash = crypto.hash_transcript([
          handshake.offerPart,
          handshake.answerPart,
          kem.ciphertext
        ]);
        const mac = crypto.handshake_mac(secrets.handshake_key, finishTranscriptHash, "alice");

        handshake.sendKey = secrets.send_key;
        handshake.recvKey = secrets.recv_key;
        handshake.handshakeKey = secrets.handshake_key;
        handshake.fingerprint = secrets.fingerprint;
        handshake.finishTranscriptHash = finishTranscriptHash;
        setFingerprint(bytesToHex(secrets.fingerprint));

        sendFrame({
          type: "handshake_finish",
          kem_ciphertext: bytesToBase64(kem.ciphertext),
          mac: bytesToBase64(mac)
        });
        setStatus("Waiting for Bob to confirm handshake\u2026");
        break;
      }
      case "relay_handshake_finish": {
        if (
          handshake.role !== "bob" ||
          !handshake.bobMlKem ||
          !handshake.bobX25519 ||
          !handshake.aliceNonce ||
          !handshake.bobNonce ||
          !handshake.offerPart ||
          !handshake.answerPart
        ) {
          break;
        }
        const offerFields = deserializePart(handshake.offerPart) as {
          offer_x25519_public: string;
        };
        const kemSharedSecret = crypto.decapsulate_mlkem(
          handshake.bobMlKem.secret_seed,
          base64ToBytes(event.kem_ciphertext),
        );
        const x25519Secret = crypto.x25519_shared_secret(
          handshake.bobX25519.secret_key,
          base64ToBytes(offerFields.offer_x25519_public),
        );
        const transcriptHash = crypto.hash_transcript([handshake.offerPart, handshake.answerPart]);
        const secrets = crypto.derive_session_secrets(
          "bob",
          handshake.sessionId,
          handshake.inviteSecret,
          handshake.aliceNonce,
          handshake.bobNonce,
          kemSharedSecret,
          x25519Secret,
          transcriptHash,
        );
        const finishTranscriptHash = crypto.hash_transcript([
          handshake.offerPart,
          handshake.answerPart,
          base64ToBytes(event.kem_ciphertext)
        ]);

        const expectedAliceMac = crypto.handshake_mac(
          secrets.handshake_key,
          finishTranscriptHash,
          "alice",
        );

        if (bytesToBase64(expectedAliceMac) !== event.mac) {
          throw new Error("handshake MAC verification failed");
        }

        const bobMac = crypto.handshake_mac(secrets.handshake_key, finishTranscriptHash, "bob");
        handshake.sendKey = secrets.send_key;
        handshake.recvKey = secrets.recv_key;
        handshake.handshakeKey = secrets.handshake_key;
        handshake.fingerprint = secrets.fingerprint;
        handshake.finishTranscriptHash = finishTranscriptHash;
        setFingerprint(bytesToHex(secrets.fingerprint));
        setStatus("Handshake complete.");

        sendFrame({
          type: "handshake_confirm",
          mac: bytesToBase64(bobMac)
        });
        break;
      }
      case "relay_handshake_confirm": {
        if (
          handshake.role !== "alice" ||
          !handshake.handshakeKey ||
          !handshake.finishTranscriptHash
        ) {
          break;
        }

        const expectedBobMac = crypto.handshake_mac(
          handshake.handshakeKey,
          handshake.finishTranscriptHash,
          "bob",
        );
        if (bytesToBase64(expectedBobMac) !== event.mac) {
          throw new Error("Bob handshake confirmation did not verify");
        }
        setStatus("Handshake complete.");
        break;
      }
      case "relay_chat_message": {
        if (!handshake.recvKey) {
          break;
        }

        if (handshake.seenInboundSeqs.has(event.seq)) {
          break;
        }

        const senderRole = handshake.role === "alice" ? "bob" : "alice";
        const plaintext = crypto.decrypt_message(
          handshake.recvKey,
          base64ToBytes(event.nonce),
          base64ToBytes(event.ciphertext),
          crypto.build_message_aad(handshake.sessionIdHex, senderRole, BigInt(event.seq)),
        );

        handshake.seenInboundSeqs.add(event.seq);
        appendMessage({
          id: `${senderRole}-${event.seq}`,
          from: senderRole,
          body: decoder.decode(plaintext)
        });
        sendFrame({ type: "chat_ack", seq: event.seq });
        break;
      }
      case "relay_chat_ack":
        setStatus(`Peer acknowledged message ${event.seq}`);
        break;
      case "peer_left":
        setStatus("Peer left the session.");
        break;
      case "session_expired":
        setStatus("Session expired.");
        break;
      case "pong":
        break;
    }
  }

  async function handleCreateSession() {
    try {
      if (!crypto) {
        throw new Error("crypto module is still loading");
      }

      const inviteSecret = crypto.generate_invite_secret();
      const sessionId = crypto.derive_session_id(inviteSecret);
      const sessionIdHex = bytesToHex(sessionId);
      await createSession(sessionIdHex);

      const inviteSecretHex = bytesToHex(inviteSecret);
      const link = buildShareLink(sessionIdHex, inviteSecretHex);
      handshakeRef.current = {
        inviteSecret,
        sessionId,
        sessionIdHex,
        role: "alice",
        seenInboundSeqs: new Set<number>(),
        nextOutboundSeq: 1
      };

      setRole("alice");
      setSessionIdHex(sessionIdHex);
      setInviteLink(link);
      setMessages([]);
      setFingerprint("");
      setError("");
      setStatus("Session created. Waiting for Bob to join\u2026");
      connectWebSocket(sessionIdHex, "alice");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "failed to create session");
    }
  }

  function handleCopyLink() {
    if (navigator.clipboard) {
      void navigator.clipboard.writeText(inviteLink);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = inviteLink;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
  }

  function handleSendMessage() {
    const handshake = handshakeRef.current;
    if (!crypto || !handshake?.sendKey || !draft.trim()) {
      return;
    }

    const seq = handshake.nextOutboundSeq;
    handshake.nextOutboundSeq += 1;

    const plaintext = encoder.encode(draft.trim());
    const senderRole = handshake.role;
    const encrypted = crypto.encrypt_message(
      handshake.sendKey,
      plaintext,
      crypto.build_message_aad(handshake.sessionIdHex, senderRole, BigInt(seq)),
    );

    sendFrame({
      type: "chat_message",
      seq,
      nonce: bytesToBase64(encrypted.nonce),
      ciphertext: bytesToBase64(encrypted.ciphertext)
    });

    appendMessage({
      id: `${senderRole}-${seq}`,
      from: senderRole,
      body: draft.trim()
    });
    setDraft("");
  }

  return (
    <div className="shell">
      <main className="panel">
        {heroSection}

        <section className="card status-card" aria-live="polite">
          <div>
            <strong>Status</strong>
            <p>{status}</p>
          </div>
          {sessionIdHex ? (
            <div>
              <strong>Session ID</strong>
              <p className="mono">{sessionIdHex}</p>
            </div>
          ) : null}
          {fingerprint ? (
            <div>
              <strong>Fingerprint</strong>
              <p className="mono">{fingerprint}</p>
            </div>
          ) : null}
        </section>

        {error ? (
          <section className="card error-card" role="alert">
            <strong>Error</strong>
            <p>{error}</p>
          </section>
        ) : null}

        {!sidFromUrl ? (
          <section className="card create-card">
            {inviteLink ? (
              <div className="invite-row">
                <label className="sr-only" htmlFor="invite-link">Invite link</label>
                <input
                  id="invite-link"
                  className="invite-input"
                  readOnly
                  value={inviteLink}
                  spellCheck={false}
                  onClick={(e) => (e.target as HTMLInputElement).select()}
                />
                <button type="button" className="primary" onClick={handleCopyLink}>
                  Copy Link
                </button>
              </div>
            ) : (
              <button type="button" className="primary" onClick={handleCreateSession} disabled={!crypto}>
                Create Session
              </button>
            )}
          </section>
        ) : null}

        <section className="card chat-card">
          <div className="messages">
            {messages.length === 0 ? (
              <p className="placeholder">
                {fingerprint
                  ? "No messages yet. Say something!"
                  : "Messages will appear here once the handshake completes."}
              </p>
            ) : (
              messages.map((message) => (
                <article key={message.id} className={`message ${message.from}`}>
                  <span>{message.from}</span>
                  <p>{message.body}</p>
                </article>
              ))
            )}
            <div ref={messagesEndRef} />
          </div>
          <div className="composer">
            <label className="sr-only" htmlFor="chat-draft">Message</label>
            <textarea
              id="chat-draft"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                  event.preventDefault();
                  handleSendMessage();
                }
              }}
              placeholder={"Type a message\u2026"}
              rows={2}
            />
            <div className="composer-footer">
              <span className="hint">Ctrl+Enter to send</span>
              <button
                type="button"
                className="primary send-btn"
                onClick={handleSendMessage}
                disabled={!fingerprint || !draft.trim()}
              >
                Send
              </button>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;
