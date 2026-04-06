import { type ChangeEvent, useEffect, useRef, useState } from "react";
import { createSession, wsBaseUrl } from "./api/client";
import type { ClientEvent, ServerEvent, SessionRole } from "./api/protocol";
import { loadCryptoModule } from "./crypto";
import {
  type PendingChatMessage,
  decodeReceivedBitmap,
  encodeReceivedBitmap,
  markChatDelivered,
  pendingMessagesInOrder,
  readBitmapBit,
} from "./recovery";

type ChatEntry = {
  id: string;
  kind: "chat";
  from: "alice" | "bob" | "system";
  body: string;
  delivered: boolean;
};

type FileTransferStatus =
  | "offered"
  | "sending"
  | "receiving"
  | "sent"
  | "received"
  | "rejected"
  | "aborted"
  | "failed"
  | "resuming";

type FileEntry = {
  id: string;
  kind: "file";
  from: "alice" | "bob";
  transferId: string;
  name: string;
  mimeType: string;
  size: number;
  sha256: string;
  status: FileTransferStatus;
  canRespond: boolean;
  url?: string;
  details?: string;
};

type ThreadEntry = ChatEntry | FileEntry;

type WasmCrypto = Awaited<ReturnType<typeof loadCryptoModule>>;
type Sha256HasherHandle = InstanceType<WasmCrypto["Sha256Hasher"]>;

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
  resumeKey?: Uint8Array;
  resumeRegistered?: boolean;
  seenInboundSeqs: Set<number>;
  nextOutboundSeq: number;
};

type FileManifest = {
  transferId: string;
  name: string;
  mimeType: string;
  size: number;
  totalChunks: number;
  sha256: string;
  senderRole: "alice" | "bob";
};

type OutgoingTransferState = {
  manifest: FileManifest;
  data: Uint8Array;
  needsRecovery: boolean;
};

type IncomingTransferState = {
  manifest: FileManifest;
  chunks: Array<Uint8Array | undefined>;
  receivedBytes: number;
  hasher: Sha256HasherHandle;
};

const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;
const FILE_CHUNK_SIZE_BYTES = 16 * 1024;
const RESUME_GRACE_PERIOD_MS = 30_000;

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

function buildShareLink(sessionIdHex: string, inviteSecretHex: string) {
  const url = new URL("/join", window.location.origin);
  url.searchParams.set("sid", sessionIdHex);
  url.hash = `secret=${inviteSecretHex}`;
  return url.toString();
}

function formatBytes(value: number) {
  if (value < 1024) {
    return `${value} B`;
  }

  const units = ["KB", "MB", "GB"];
  let size = value;
  let unitIndex = -1;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

function randomTransferId() {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

async function sha256Hex(bytes: Uint8Array) {
  const payload = new Uint8Array(bytes);
  const digest = await window.crypto.subtle.digest("SHA-256", payload);
  return bytesToHex(new Uint8Array(digest));
}

function encodeFileChunkFrame(
  transferId: string,
  chunkIndex: number,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
) {
  const transferIdBytes = hexToBytes(transferId);
  if (transferIdBytes.length !== 16) {
    throw new Error("invalid transfer id");
  }

  const frame = new Uint8Array(16 + 4 + nonce.length + ciphertext.length);
  frame.set(transferIdBytes, 0);
  new DataView(frame.buffer).setUint32(16, chunkIndex, false);
  frame.set(nonce, 20);
  frame.set(ciphertext, 20 + nonce.length);
  return frame;
}

function decodeFileChunkFrame(payload: Uint8Array) {
  if (payload.length < 44) {
    throw new Error("invalid file chunk frame");
  }

  const transferId = bytesToHex(payload.subarray(0, 16));
  const chunkIndex = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(16, false);
  const nonce = payload.subarray(20, 44);
  const ciphertext = payload.subarray(44);
  return { transferId, chunkIndex, nonce, ciphertext };
}

function fileStatusLabel(entry: FileEntry) {
  switch (entry.status) {
    case "offered":
      return entry.canRespond ? "Awaiting response" : "Awaiting acceptance";
    case "sending":
      return "Sending";
    case "receiving":
      return "Receiving";
    case "sent":
      return "Sent";
    case "received":
      return "Ready to download";
    case "rejected":
      return "Rejected";
    case "aborted":
      return "Aborted";
    case "failed":
      return "Failed";
    case "resuming":
      return "Resuming";
  }
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

function App() {
  const [cryptoModule, setCryptoModule] = useState<WasmCrypto | null>(null);
  const [status, setStatus] = useState("Loading crypto module\u2026");
  const [inviteLink, setInviteLink] = useState("");
  const [messages, setMessages] = useState<ThreadEntry[]>([]);
  const [draft, setDraft] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [role, setRole] = useState<SessionRole | null>(null);
  const [sessionIdHex, setSessionIdHex] = useState("");
  const [error, setError] = useState("");

  const wsRef = useRef<WebSocket | null>(null);
  const mountedRef = useRef(true);
  const handshakeRef = useRef<HandshakeState | null>(null);
  const messagesRef = useRef<ThreadEntry[]>([]);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const outgoingTransferRef = useRef<OutgoingTransferState | null>(null);
  const incomingTransferRef = useRef<IncomingTransferState | null>(null);
  const pendingChatMessagesRef = useRef<Map<number, PendingChatMessage>>(new Map());
  const recoverableOutgoingTransfersRef = useRef<Map<string, OutgoingTransferState>>(new Map());
  const recoverableOutgoingTransferTimersRef = useRef<Map<string, number>>(new Map());
  const transferManifestRef = useRef<Map<string, FileManifest>>(new Map());
  const objectUrlsRef = useRef<string[]>([]);
  const reconnectTimerRef = useRef<number | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectStartedAtRef = useRef<number | null>(null);
  const intentionalCloseRef = useRef(false);

  const sidFromUrl = new URLSearchParams(window.location.search).get("sid");
  const secretFromUrl = window.location.hash.startsWith("#secret=")
    ? window.location.hash.slice("#secret=".length)
    : "";

  useEffect(() => {
    messagesRef.current = messages;
    requestAnimationFrame(() => {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    });
  }, [messages]);

  useEffect(() => {
    let cancelled = false;
    mountedRef.current = true;

    void loadCryptoModule()
      .then((module) => {
        if (cancelled) {
          return;
        }

        setCryptoModule(module);
        setStatus("Ready");
      })
      .catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : "failed to load wasm crypto");
      });

    return () => {
      cancelled = true;
      mountedRef.current = false;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
      }
      recoverableOutgoingTransferTimersRef.current.forEach((timerId) => {
        window.clearTimeout(timerId);
      });
      intentionalCloseRef.current = true;
      wsRef.current?.close();
      objectUrlsRef.current.forEach((url) => URL.revokeObjectURL(url));
    };
  }, []);

  useEffect(() => {
    if (!cryptoModule || !sidFromUrl) {
      return;
    }

    try {
      if (!secretFromUrl) {
        throw new Error("join link is missing the fragment secret");
      }

      const inviteSecret = hexToBytes(secretFromUrl);
      const derivedSessionId = cryptoModule.derive_session_id(inviteSecret);
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
        nextOutboundSeq: 1,
      };
      pendingChatMessagesRef.current.clear();
      connectWebSocket(derivedSessionIdHex, "bob");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "invalid join link");
    }
  }, [cryptoModule, sidFromUrl, secretFromUrl]);

  function appendThreadEntry(entry: ThreadEntry) {
    setMessages((current) => [...current, entry]);
  }

  function appendChatEntry(from: ChatEntry["from"], body: string) {
    appendThreadEntry({
      id: `${from}-${Date.now()}-${Math.random()}`,
      kind: "chat",
      from,
      body,
      delivered: true,
    });
  }

  function upsertFileEntry(entry: FileEntry) {
    setMessages((current) => {
      const index = current.findIndex(
        (message) => message.kind === "file" && message.transferId === entry.transferId,
      );
      if (index === -1) {
        return [...current, entry];
      }

      const next = current.slice();
      next[index] = entry;
      return next;
    });
  }

  function patchFileEntry(transferId: string, patch: Partial<FileEntry>) {
    setMessages((current) =>
      current.map((message) =>
        message.kind === "file" && message.transferId === transferId
          ? { ...message, ...patch }
          : message,
      ),
    );
  }

  function failOpenTransfers(reason: string) {
    setMessages((current) =>
      current.map((message) => {
        if (message.kind !== "file") {
          return message;
        }

        if (!["offered", "sending", "receiving"].includes(message.status)) {
          return message;
        }

        return {
          ...message,
          status: "failed" as const,
          canRespond: false,
          details: reason,
        };
      }),
    );
    outgoingTransferRef.current = null;
    incomingTransferRef.current = null;
    recoverableOutgoingTransferTimersRef.current.forEach((timerId) => {
      window.clearTimeout(timerId);
    });
    recoverableOutgoingTransferTimersRef.current.clear();
    recoverableOutgoingTransfersRef.current.clear();
  }

  function markTransfersResuming(reason: string) {
    setMessages((current) =>
      current.map((message) => {
        if (message.kind !== "file") {
          return message;
        }
        if (!["offered", "sending", "receiving", "resuming"].includes(message.status)) {
          return message;
        }

        return {
          ...message,
          status: "resuming" as const,
          canRespond: false,
          details: reason,
        };
      }),
    );
    if (outgoingTransferRef.current) {
      outgoingTransferRef.current.needsRecovery = true;
    }
  }

  function resetReconnectState() {
    if (reconnectTimerRef.current !== null) {
      window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    reconnectAttemptRef.current = 0;
    reconnectStartedAtRef.current = null;
  }

  function canResumeSession() {
    return Boolean(handshakeRef.current?.resumeKey && handshakeRef.current?.resumeRegistered);
  }

  function scheduleReconnect() {
    const handshake = handshakeRef.current;
    if (!handshake || !mountedRef.current || reconnectTimerRef.current !== null) {
      return;
    }

    const startedAt = reconnectStartedAtRef.current ?? Date.now();
    reconnectStartedAtRef.current = startedAt;
    const elapsed = Date.now() - startedAt;
    if (elapsed >= RESUME_GRACE_PERIOD_MS) {
      resetReconnectState();
      failOpenTransfers("Reconnect window expired");
      setStatus("Session ended");
      return;
    }

    const delay = Math.min(1_000 * 2 ** reconnectAttemptRef.current, 15_000);
    reconnectAttemptRef.current += 1;
    reconnectTimerRef.current = window.setTimeout(() => {
      reconnectTimerRef.current = null;
      connectWebSocket(handshake.sessionIdHex, handshake.role, "resume");
    }, delay);
  }

  function registerResumeVerifier() {
    const handshake = handshakeRef.current;
    if (!cryptoModule || !handshake?.resumeKey || handshake.resumeRegistered) {
      return;
    }

    sendFrame({
      type: "register_resume",
      verifier: bytesToHex(cryptoModule.resume_verifier(handshake.resumeKey)),
    });
    handshake.resumeRegistered = true;
  }

  function retainRecoverableOutgoingTransfer(transfer: OutgoingTransferState) {
    const transferId = transfer.manifest.transferId;
    const existingTimer = recoverableOutgoingTransferTimersRef.current.get(transferId);
    if (existingTimer !== undefined) {
      window.clearTimeout(existingTimer);
    }

    recoverableOutgoingTransfersRef.current.set(transferId, transfer);
    const timerId = window.setTimeout(() => {
      recoverableOutgoingTransfersRef.current.delete(transferId);
      recoverableOutgoingTransferTimersRef.current.delete(transferId);
    }, RESUME_GRACE_PERIOD_MS);
    recoverableOutgoingTransferTimersRef.current.set(transferId, timerId);
  }

  function takeRecoverableOutgoingTransfer(transferId: string) {
    const transfer = recoverableOutgoingTransfersRef.current.get(transferId) ?? null;
    if (!transfer) {
      return null;
    }

    const timerId = recoverableOutgoingTransferTimersRef.current.get(transferId);
    if (timerId !== undefined) {
      window.clearTimeout(timerId);
      recoverableOutgoingTransferTimersRef.current.delete(transferId);
    }
    recoverableOutgoingTransfersRef.current.delete(transferId);
    return transfer;
  }

  function resendPendingChatMessages() {
    const pendingMessages = pendingMessagesInOrder(pendingChatMessagesRef.current);
    for (const message of pendingMessages) {
      sendFrame({
        type: "chat_message",
        seq: message.seq,
        nonce: message.nonce,
        ciphertext: message.ciphertext,
      });
    }
  }

  function sendIncomingTransferResumeState(transfer: IncomingTransferState) {
    sendFrame({
      type: "file_resume_state",
      transfer_id: transfer.manifest.transferId,
      received_bitmap: encodeReceivedBitmap(transfer.chunks),
    });
    patchFileEntry(transfer.manifest.transferId, {
      status: "receiving",
      canRespond: false,
      details: `${formatBytes(transfer.receivedBytes)} recovered, requesting missing chunks`,
    });
  }

  function resumeRecoveredState() {
    resendPendingChatMessages();
    if (incomingTransferRef.current) {
      sendIncomingTransferResumeState(incomingTransferRef.current);
    }
  }

  function handlePeerUnavailable() {
    const transfer = outgoingTransferRef.current;
    if (transfer) {
      transfer.needsRecovery = true;
      patchFileEntry(transfer.manifest.transferId, {
        status: "resuming",
        canRespond: false,
        details: "Peer disconnected; waiting to resume transfer",
      });
    }
    setStatus("Peer connection lost. Waiting for reconnection…");
  }

  function connectWebSocket(
    targetSessionId: string,
    targetRole: SessionRole,
    mode: "join" | "resume" = "join",
  ) {
    if (wsRef.current) {
      intentionalCloseRef.current = true;
      wsRef.current.close();
    }

    const socket = new WebSocket(wsBaseUrl());
    socket.binaryType = "arraybuffer";
    wsRef.current = socket;

    socket.addEventListener("open", () => {
      resetReconnectState();
      sendFrame(
        mode === "join"
          ? {
              type: "join_session",
              session_id: targetSessionId,
              role: targetRole,
            }
          : {
              type: "resume_session",
              session_id: targetSessionId,
              role: targetRole,
            },
      );

      const keepalive = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "ping" }));
        } else {
          clearInterval(keepalive);
        }
      }, 30_000);
      socket.addEventListener("close", () => clearInterval(keepalive));
    });

    socket.addEventListener("message", (event) => {
      if (typeof event.data === "string") {
        const payload = JSON.parse(event.data) as ServerEvent;
        void handleServerEvent(payload).catch((cause: unknown) => {
          setError(cause instanceof Error ? cause.message : "failed to process server event");
        });
        return;
      }

      const bytes = new Uint8Array(event.data as ArrayBuffer);
      void handleBinaryFrame(bytes).catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : "failed to process file chunk");
      });
    });

    socket.addEventListener("close", () => {
      if (wsRef.current === socket) {
        wsRef.current = null;
      }
      if (intentionalCloseRef.current) {
        intentionalCloseRef.current = false;
        return;
      }

      if (canResumeSession()) {
        markTransfersResuming("Connection lost; waiting to resume");
        setStatus("Reconnecting…");
        scheduleReconnect();
      } else {
        failOpenTransfers("Connection lost");
        setStatus("Disconnected");
      }
    });
  }

  function sendFrame(frame: ClientEvent) {
    const socket = wsRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error("websocket is not connected");
    }

    socket.send(JSON.stringify(frame));
  }

  function sendBinaryFrame(payload: Uint8Array) {
    const socket = wsRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error("websocket is not connected");
    }

    socket.send(payload);
  }

  async function handleBinaryFrame(payload: Uint8Array) {
    const handshake = handshakeRef.current;
    if (!cryptoModule || !handshake?.recvKey) {
      return;
    }

    const transfer = incomingTransferRef.current;
    if (!transfer) {
      throw new Error("received unexpected file chunk");
    }

    const { transferId, chunkIndex, nonce, ciphertext } = decodeFileChunkFrame(payload);
    if (transferId !== transfer.manifest.transferId) {
      throw new Error("received file chunk for unknown transfer");
    }
    if (chunkIndex >= transfer.manifest.totalChunks) {
      sendLocalFileAbort(transferId, "chunk index out of range");
      return;
    }
    if (transfer.chunks[chunkIndex]) {
      return;
    }

    const plaintext = cryptoModule.decrypt_message(
      handshake.recvKey,
      nonce,
      ciphertext,
      cryptoModule.build_file_chunk_aad(
        handshake.sessionIdHex,
        transfer.manifest.senderRole,
        transfer.manifest.transferId,
        chunkIndex,
        BigInt(transfer.manifest.size),
        transfer.manifest.totalChunks,
        transfer.manifest.sha256,
      ),
    );

    transfer.receivedBytes += plaintext.length;
    if (transfer.receivedBytes > transfer.manifest.size) {
      sendLocalFileAbort(transferId, "declared size exceeded");
      return;
    }

    transfer.hasher.update(plaintext);
    transfer.chunks[chunkIndex] = plaintext;
  }

  function sendLocalFileAbort(transferId: string, reason: string) {
    if (outgoingTransferRef.current?.manifest.transferId === transferId) {
      outgoingTransferRef.current = null;
    }
    if (incomingTransferRef.current?.manifest.transferId === transferId) {
      incomingTransferRef.current = null;
    }

    patchFileEntry(transferId, {
      status: "aborted",
      canRespond: false,
      details: reason,
    });

    try {
      sendFrame({ type: "file_abort", transfer_id: transferId, reason });
    } catch {
      // Connection may already be gone.
    }
  }

  async function finalizeIncomingTransfer(transferId: string) {
    const transfer = incomingTransferRef.current;
    if (!transfer || transfer.manifest.transferId !== transferId) {
      return;
    }

    if (transfer.chunks.some((chunk) => chunk === undefined)) {
      sendLocalFileAbort(transferId, "missing file chunks");
      return;
    }

    if (transfer.receivedBytes !== transfer.manifest.size) {
      sendLocalFileAbort(transferId, "file size mismatch");
      return;
    }

    const fileBytes = new Uint8Array(transfer.manifest.size);
    let offset = 0;
    for (const chunk of transfer.chunks) {
      fileBytes.set(chunk!, offset);
      offset += chunk!.length;
    }

    const digest = transfer.hasher.finalize_hex();
    if (digest !== transfer.manifest.sha256) {
      sendLocalFileAbort(transferId, "file digest mismatch");
      return;
    }

    const blob = new Blob([fileBytes], {
      type: transfer.manifest.mimeType || "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    objectUrlsRef.current.push(url);

    patchFileEntry(transferId, {
      status: "received",
      canRespond: false,
      url,
      details: `${formatBytes(transfer.manifest.size)} verified`,
    });
    incomingTransferRef.current = null;
  }

  async function sendFileTransfer(transferId: string, missingBitmap?: Uint8Array) {
    const handshake = handshakeRef.current;
    const transfer = outgoingTransferRef.current;
    if (!cryptoModule || !handshake?.sendKey || !transfer || transfer.manifest.transferId !== transferId) {
      return;
    }

    transfer.needsRecovery = false;

    for (let chunkIndex = 0; chunkIndex < transfer.manifest.totalChunks; chunkIndex += 1) {
      if (outgoingTransferRef.current?.manifest.transferId !== transferId) {
        return;
      }
      if (missingBitmap && readBitmapBit(missingBitmap, chunkIndex)) {
        continue;
      }

      const start = chunkIndex * FILE_CHUNK_SIZE_BYTES;
      const end = Math.min(start + FILE_CHUNK_SIZE_BYTES, transfer.data.length);
      const plaintext = transfer.data.subarray(start, end);
      const encrypted = cryptoModule.encrypt_message(
        handshake.sendKey,
        plaintext,
        cryptoModule.build_file_chunk_aad(
          handshake.sessionIdHex,
          handshake.role,
          transfer.manifest.transferId,
          chunkIndex,
          BigInt(transfer.manifest.size),
          transfer.manifest.totalChunks,
          transfer.manifest.sha256,
        ),
      );

      sendBinaryFrame(
        encodeFileChunkFrame(
          transfer.manifest.transferId,
          chunkIndex,
          encrypted.nonce,
          encrypted.ciphertext,
        ),
      );

      if ((chunkIndex + 1) % 32 === 0) {
        await new Promise((resolve) => window.setTimeout(resolve, 0));
      }
    }

    if (outgoingTransferRef.current?.manifest.transferId !== transferId) {
      return;
    }

    sendFrame({ type: "file_complete", transfer_id: transferId });
    if (transfer.needsRecovery) {
      patchFileEntry(transferId, {
        status: "resuming",
        canRespond: false,
        details: "Waiting for peer to report missing chunks",
      });
      return;
    }

    patchFileEntry(transferId, {
      status: "sent",
      canRespond: false,
      details: `${formatBytes(transfer.manifest.size)} sent`,
    });
    retainRecoverableOutgoingTransfer(transfer);
    outgoingTransferRef.current = null;
  }

  async function resumeOutgoingTransfer(transferId: string, receivedBitmap: string) {
    const transfer =
      outgoingTransferRef.current?.manifest.transferId === transferId
        ? outgoingTransferRef.current
        : takeRecoverableOutgoingTransfer(transferId);
    if (!transfer) {
      return;
    }
    outgoingTransferRef.current = transfer;

    let bitmap: Uint8Array;
    try {
      bitmap = decodeReceivedBitmap(receivedBitmap, transfer.manifest.totalChunks);
    } catch (cause) {
      sendLocalFileAbort(
        transferId,
        cause instanceof Error ? cause.message : "received invalid resume state",
      );
      return;
    }
    patchFileEntry(transferId, {
      status: "sending",
      canRespond: false,
      details: "Resending missing chunks",
    });
    await sendFileTransfer(transferId, bitmap);
  }

  async function handleServerEvent(event: ServerEvent) {
    if (event.type === "error") {
      if (event.message === "peer not connected") {
        handlePeerUnavailable();
        return;
      }
      setError(event.message);
      return;
    }

    const handshake = handshakeRef.current;
    if (!cryptoModule || !handshake) {
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
          const aliceX25519 = cryptoModule.generate_x25519_keypair();
          const aliceNonce = cryptoModule.generate_nonce();
          handshake.aliceX25519 = aliceX25519;
          handshake.aliceNonce = aliceNonce;

          const frame = {
            offer_x25519_public: bytesToBase64(aliceX25519.public_key),
            alice_nonce: bytesToBase64(aliceNonce),
          };
          handshake.offerPart = serializePart("handshake_offer", frame);
          sendFrame({ type: "handshake_offer", ...frame });
        }
        break;
      case "relay_handshake_offer": {
        if (handshake.role !== "bob") {
          break;
        }

        const bobMlKem = cryptoModule.generate_mlkem_keypair();
        const bobX25519 = cryptoModule.generate_x25519_keypair();
        const bobNonce = cryptoModule.generate_nonce();
        handshake.bobMlKem = bobMlKem;
        handshake.bobX25519 = bobX25519;
        handshake.bobNonce = bobNonce;
        handshake.aliceNonce = base64ToBytes(event.alice_nonce);
        handshake.offerPart = serializePart("handshake_offer", {
          offer_x25519_public: event.offer_x25519_public,
          alice_nonce: event.alice_nonce,
        });

        const frame = {
          bob_mlkem_public: bytesToBase64(bobMlKem.public_key),
          bob_x25519_public: bytesToBase64(bobX25519.public_key),
          bob_nonce: bytesToBase64(bobNonce),
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
          bob_nonce: event.bob_nonce,
        });
        handshake.bobNonce = base64ToBytes(event.bob_nonce);

        const kem = cryptoModule.encapsulate_mlkem(base64ToBytes(event.bob_mlkem_public));
        const x25519Secret = cryptoModule.x25519_shared_secret(
          handshake.aliceX25519.secret_key,
          base64ToBytes(event.bob_x25519_public),
        );
        const transcriptHash = cryptoModule.hash_transcript([handshake.offerPart, handshake.answerPart]);
        const secrets = cryptoModule.derive_session_secrets(
          "alice",
          handshake.sessionId,
          handshake.inviteSecret,
          handshake.aliceNonce,
          handshake.bobNonce!,
          kem.shared_secret,
          x25519Secret,
          transcriptHash,
        );
        const finishTranscriptHash = cryptoModule.hash_transcript([
          handshake.offerPart,
          handshake.answerPart,
          kem.ciphertext,
        ]);
        const mac = cryptoModule.handshake_mac(secrets.handshake_key, finishTranscriptHash, "alice");

        handshake.sendKey = secrets.send_key;
        handshake.recvKey = secrets.recv_key;
        handshake.handshakeKey = secrets.handshake_key;
        handshake.fingerprint = secrets.fingerprint;
        handshake.resumeKey = secrets.resume_key;
        handshake.resumeRegistered = false;
        handshake.finishTranscriptHash = finishTranscriptHash;
        setFingerprint(bytesToHex(secrets.fingerprint));

        sendFrame({
          type: "handshake_finish",
          kem_ciphertext: bytesToBase64(kem.ciphertext),
          mac: bytesToBase64(mac),
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
        const kemSharedSecret = cryptoModule.decapsulate_mlkem(
          handshake.bobMlKem.secret_seed,
          base64ToBytes(event.kem_ciphertext),
        );
        const x25519Secret = cryptoModule.x25519_shared_secret(
          handshake.bobX25519.secret_key,
          base64ToBytes(offerFields.offer_x25519_public),
        );
        const transcriptHash = cryptoModule.hash_transcript([handshake.offerPart, handshake.answerPart]);
        const secrets = cryptoModule.derive_session_secrets(
          "bob",
          handshake.sessionId,
          handshake.inviteSecret,
          handshake.aliceNonce,
          handshake.bobNonce,
          kemSharedSecret,
          x25519Secret,
          transcriptHash,
        );
        const finishTranscriptHash = cryptoModule.hash_transcript([
          handshake.offerPart,
          handshake.answerPart,
          base64ToBytes(event.kem_ciphertext),
        ]);

        const expectedAliceMac = cryptoModule.handshake_mac(
          secrets.handshake_key,
          finishTranscriptHash,
          "alice",
        );

        if (bytesToBase64(expectedAliceMac) !== event.mac) {
          throw new Error("handshake MAC verification failed");
        }

        const bobMac = cryptoModule.handshake_mac(secrets.handshake_key, finishTranscriptHash, "bob");
        handshake.sendKey = secrets.send_key;
        handshake.recvKey = secrets.recv_key;
        handshake.handshakeKey = secrets.handshake_key;
        handshake.fingerprint = secrets.fingerprint;
        handshake.resumeKey = secrets.resume_key;
        handshake.resumeRegistered = false;
        handshake.finishTranscriptHash = finishTranscriptHash;
        setFingerprint(bytesToHex(secrets.fingerprint));
        setStatus("Handshake complete.");
        registerResumeVerifier();

        sendFrame({
          type: "handshake_confirm",
          mac: bytesToBase64(bobMac),
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

        const expectedBobMac = cryptoModule.handshake_mac(
          handshake.handshakeKey,
          handshake.finishTranscriptHash,
          "bob",
        );
        if (bytesToBase64(expectedBobMac) !== event.mac) {
          throw new Error("Bob handshake confirmation did not verify");
        }
        setStatus("Handshake complete.");
        registerResumeVerifier();
        break;
      }
      case "relay_chat_message": {
        if (!handshake.recvKey) {
          break;
        }

        if (handshake.seenInboundSeqs.has(event.seq)) {
          sendFrame({ type: "chat_ack", seq: event.seq });
          break;
        }

        const senderRole = handshake.role === "alice" ? "bob" : "alice";
        const plaintext = cryptoModule.decrypt_message(
          handshake.recvKey,
          base64ToBytes(event.nonce),
          base64ToBytes(event.ciphertext),
          cryptoModule.build_message_aad(handshake.sessionIdHex, senderRole, BigInt(event.seq)),
        );

        handshake.seenInboundSeqs.add(event.seq);
        appendThreadEntry({
          id: `${senderRole}-${event.seq}`,
          kind: "chat",
          from: senderRole,
          body: decoder.decode(plaintext),
          delivered: true,
        });
        sendFrame({ type: "chat_ack", seq: event.seq });
        break;
      }
      case "relay_chat_ack": {
        pendingChatMessagesRef.current.delete(event.seq);
        setMessages((current) => markChatDelivered(current, handshake.role, event.seq));
        break;
      }
      case "relay_file_offer": {
        const senderRole = handshake.role === "alice" ? "bob" : "alice";
        const hasIncomingBusy = messagesRef.current.some(
          (entry) =>
            entry.kind === "file" &&
            entry.from === senderRole &&
            ["offered", "receiving"].includes(entry.status),
        );
        if (hasIncomingBusy || incomingTransferRef.current) {
          sendFrame({ type: "file_reject", transfer_id: event.transfer_id });
          break;
        }

        const manifest: FileManifest = {
          transferId: event.transfer_id,
          name: event.name,
          mimeType: event.mime_type,
          size: event.size,
          totalChunks: event.total_chunks,
          sha256: event.sha256,
          senderRole,
        };
        transferManifestRef.current.set(event.transfer_id, manifest);
        upsertFileEntry({
          id: `file-${event.transfer_id}`,
          kind: "file",
          from: senderRole,
          transferId: event.transfer_id,
          name: event.name,
          mimeType: event.mime_type,
          size: event.size,
          sha256: event.sha256,
          status: "offered",
          canRespond: true,
          details: `${formatBytes(event.size)} incoming file`,
        });
        break;
      }
      case "relay_file_accept": {
        const transfer = outgoingTransferRef.current;
        if (!transfer || transfer.manifest.transferId !== event.transfer_id) {
          break;
        }

        patchFileEntry(event.transfer_id, {
          status: "sending",
          canRespond: false,
          details: `${formatBytes(transfer.manifest.size)} sending`,
        });
        setStatus(`Sending ${transfer.manifest.name}\u2026`);
        await sendFileTransfer(event.transfer_id);
        break;
      }
      case "relay_file_reject":
        if (outgoingTransferRef.current?.manifest.transferId === event.transfer_id) {
          outgoingTransferRef.current = null;
        }
        takeRecoverableOutgoingTransfer(event.transfer_id);
        patchFileEntry(event.transfer_id, {
          status: "rejected",
          canRespond: false,
          details: "Peer rejected the file",
        });
        break;
      case "relay_file_complete":
        await finalizeIncomingTransfer(event.transfer_id);
        break;
      case "relay_file_abort":
        if (outgoingTransferRef.current?.manifest.transferId === event.transfer_id) {
          outgoingTransferRef.current = null;
        }
        if (incomingTransferRef.current?.manifest.transferId === event.transfer_id) {
          incomingTransferRef.current = null;
        }
        takeRecoverableOutgoingTransfer(event.transfer_id);
        patchFileEntry(event.transfer_id, {
          status: "aborted",
          canRespond: false,
          details: event.reason,
        });
        break;
      case "relay_file_resume_state":
        await resumeOutgoingTransfer(event.transfer_id, event.received_bitmap);
        break;
      case "resume_challenge": {
        if (!handshake.resumeKey) {
          throw new Error("resume key is unavailable");
        }

        const mac = cryptoModule.resume_mac(
          handshake.resumeKey,
          base64ToBytes(event.nonce),
          handshake.sessionIdHex,
          handshake.role,
        );
        sendFrame({
          type: "resume_proof",
          resume_key: bytesToBase64(handshake.resumeKey),
          mac: bytesToBase64(mac),
        });
        break;
      }
      case "resume_accepted":
        setStatus("Reconnected.");
        resumeRecoveredState();
        break;
      case "peer_reconnected":
        setStatus("Peer reconnected.");
        resumeRecoveredState();
        break;
      case "peer_left":
        pendingChatMessagesRef.current.clear();
        failOpenTransfers("Peer left the session");
        resetReconnectState();
        setStatus("Peer left the session.");
        break;
      case "session_expired":
        pendingChatMessagesRef.current.clear();
        failOpenTransfers("Session expired");
        resetReconnectState();
        setStatus("Session expired.");
        break;
      case "pong":
        break;
    }
  }

  async function handleCreateSession() {
    try {
      if (!cryptoModule) {
        throw new Error("crypto module is still loading");
      }

      const inviteSecret = cryptoModule.generate_invite_secret();
      const sessionId = cryptoModule.derive_session_id(inviteSecret);
      const nextSessionIdHex = bytesToHex(sessionId);
      await createSession(nextSessionIdHex);

      const inviteSecretHex = bytesToHex(inviteSecret);
      const link = buildShareLink(nextSessionIdHex, inviteSecretHex);
      handshakeRef.current = {
        inviteSecret,
        sessionId,
        sessionIdHex: nextSessionIdHex,
        role: "alice",
        seenInboundSeqs: new Set<number>(),
        nextOutboundSeq: 1,
      };

      resetReconnectState();
      outgoingTransferRef.current = null;
      incomingTransferRef.current = null;
      pendingChatMessagesRef.current.clear();
      recoverableOutgoingTransferTimersRef.current.forEach((timerId) => {
        window.clearTimeout(timerId);
      });
      recoverableOutgoingTransferTimersRef.current.clear();
      recoverableOutgoingTransfersRef.current.clear();
      transferManifestRef.current.clear();
      setRole("alice");
      setSessionIdHex(nextSessionIdHex);
      setInviteLink(link);
      setMessages([]);
      setFingerprint("");
      setError("");
      setStatus("Session created. Waiting for Bob to join\u2026");
      connectWebSocket(nextSessionIdHex, "alice");
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
    if (!cryptoModule || !handshake?.sendKey || !draft.trim()) {
      return;
    }

    const seq = handshake.nextOutboundSeq;
    handshake.nextOutboundSeq += 1;

    const plaintext = encoder.encode(draft.trim());
    const senderRole = handshake.role;
    const encrypted = cryptoModule.encrypt_message(
      handshake.sendKey,
      plaintext,
      cryptoModule.build_message_aad(handshake.sessionIdHex, senderRole, BigInt(seq)),
    );

    const frame: PendingChatMessage = {
      seq,
      nonce: bytesToBase64(encrypted.nonce),
      ciphertext: bytesToBase64(encrypted.ciphertext),
    };
    pendingChatMessagesRef.current.set(seq, frame);
    try {
      sendFrame({
        type: "chat_message",
        seq,
        nonce: frame.nonce,
        ciphertext: frame.ciphertext,
      });
    } catch (cause) {
      pendingChatMessagesRef.current.delete(seq);
      setError(cause instanceof Error ? cause.message : "failed to send message");
      return;
    }

    appendThreadEntry({
      id: `${senderRole}-${seq}`,
      kind: "chat",
      from: senderRole,
      body: draft.trim(),
      delivered: false,
    });
    setDraft("");
  }

  async function handleFileSelected(event: ChangeEvent<HTMLInputElement>) {
    const handshake = handshakeRef.current;
    const file = event.target.files?.[0];
    event.target.value = "";

    if (!file || !cryptoModule || !handshake?.sendKey) {
      return;
    }
    if (outgoingTransferRef.current) {
      setError("wait for the current outgoing transfer to finish");
      return;
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setError(`file exceeds the ${formatBytes(MAX_FILE_SIZE_BYTES)} limit`);
      return;
    }

    try {
      setError("");
      const buffer = await file.arrayBuffer();
      const data = new Uint8Array(buffer);
      const manifest: FileManifest = {
        transferId: randomTransferId(),
        name: file.name || "untitled",
        mimeType: file.type || "application/octet-stream",
        size: data.length,
        totalChunks: Math.ceil(data.length / FILE_CHUNK_SIZE_BYTES),
        sha256: await sha256Hex(data),
        senderRole: handshake.role,
      };

      transferManifestRef.current.set(manifest.transferId, manifest);
      outgoingTransferRef.current = { manifest, data, needsRecovery: false };
      upsertFileEntry({
        id: `file-${manifest.transferId}`,
        kind: "file",
        from: handshake.role,
        transferId: manifest.transferId,
        name: manifest.name,
        mimeType: manifest.mimeType,
        size: manifest.size,
        sha256: manifest.sha256,
        status: "offered",
        canRespond: false,
        details: `${formatBytes(manifest.size)} awaiting acceptance`,
      });

      sendFrame({
        type: "file_offer",
        transfer_id: manifest.transferId,
        name: manifest.name,
        mime_type: manifest.mimeType,
        size: manifest.size,
        total_chunks: manifest.totalChunks,
        sha256: manifest.sha256,
      });
      setStatus(`Waiting for peer to accept ${manifest.name}\u2026`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "failed to prepare file");
      outgoingTransferRef.current = null;
    }
  }

  function handleAcceptFile(transferId: string) {
    if (!cryptoModule) {
      setError("crypto module is still loading");
      return;
    }

    if (incomingTransferRef.current) {
      setError("wait for the current incoming transfer to finish");
      return;
    }

    const manifest = transferManifestRef.current.get(transferId);
    if (!manifest) {
      setError("missing file manifest");
      return;
    }

    incomingTransferRef.current = {
      manifest,
      chunks: Array.from({ length: manifest.totalChunks }),
      receivedBytes: 0,
      hasher: new cryptoModule.Sha256Hasher(),
    };
    patchFileEntry(transferId, {
      status: "receiving",
      canRespond: false,
      details: `${formatBytes(manifest.size)} receiving`,
    });
    sendFrame({ type: "file_accept", transfer_id: transferId });
  }

  function handleRejectFile(transferId: string) {
    patchFileEntry(transferId, {
      status: "rejected",
      canRespond: false,
      details: "You rejected this file",
    });
    sendFrame({ type: "file_reject", transfer_id: transferId });
  }

  const hasHandshake = Boolean(fingerprint);
  const hasOutgoingTransfer = messages.some(
    (message) =>
      message.kind === "file" &&
      message.from === role &&
      ["offered", "sending", "resuming"].includes(message.status),
  );

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
              <button type="button" className="primary" onClick={handleCreateSession} disabled={!cryptoModule}>
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
                  ? "No messages or files yet."
                  : "Messages and files will appear here once the handshake completes."}
              </p>
            ) : (
              messages.map((message) => {
                if (message.kind === "chat") {
                  return (
                    <article key={message.id} className={`message ${message.from} ${message.delivered ? "delivered" : "pending"}`}>
                      <span>{message.from}</span>
                      <p>{message.body}</p>
                    </article>
                  );
                }

                return (
                  <article key={message.id} className={`message file-message ${message.from}`}>
                    <span>{message.from}</span>
                    <p className="file-title">{message.name}</p>
                    <p className="file-meta">
                      {formatBytes(message.size)} · {fileStatusLabel(message)}
                    </p>
                    {message.details ? <p className="file-meta">{message.details}</p> : null}
                    {message.canRespond ? (
                      <div className="file-actions">
                        <button
                          type="button"
                          className="primary"
                          onClick={() => handleAcceptFile(message.transferId)}
                        >
                          Accept
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => handleRejectFile(message.transferId)}
                        >
                          Reject
                        </button>
                      </div>
                    ) : null}
                    {message.url ? (
                      <a
                        className="download-link"
                        href={message.url}
                        download={message.name}
                      >
                        Download file
                      </a>
                    ) : null}
                  </article>
                );
              })
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
              <div className="composer-actions">
                <input
                  ref={fileInputRef}
                  className="sr-only"
                  type="file"
                  onChange={handleFileSelected}
                />
                <button
                  type="button"
                  className="secondary"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={!hasHandshake || hasOutgoingTransfer}
                >
                  Send File
                </button>
                <button
                  type="button"
                  className="primary send-btn"
                  onClick={handleSendMessage}
                  disabled={!hasHandshake || !draft.trim()}
                >
                  Send
                </button>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;
