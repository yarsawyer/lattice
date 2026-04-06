type WasmModule = {
  default: (input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module) => Promise<unknown>;
  create_sha256_hasher: () => {
    update: (bytes: Uint8Array) => void;
    finalize_hex: () => string;
  };
  generate_invite_secret: () => Uint8Array;
  generate_nonce: () => Uint8Array;
  derive_session_id: (inviteSecret: Uint8Array) => Uint8Array;
  build_message_aad: (
    sessionIdHex: string,
    role: "alice" | "bob",
    sequenceNumber: bigint,
  ) => Uint8Array;
  build_file_chunk_aad: (
    sessionIdHex: string,
    role: "alice" | "bob",
    transferIdHex: string,
    chunkIndex: number,
    declaredSize: bigint,
    totalChunks: number,
    fileSha256Hex: string,
  ) => Uint8Array;
  generate_mlkem_keypair: () => {
    secret_seed: Uint8Array;
    public_key: Uint8Array;
  };
  generate_x25519_keypair: () => {
    secret_key: Uint8Array;
    public_key: Uint8Array;
  };
  encapsulate_mlkem: (publicKey: Uint8Array) => {
    ciphertext: Uint8Array;
    shared_secret: Uint8Array;
  };
  decapsulate_mlkem: (seed: Uint8Array, ciphertext: Uint8Array) => Uint8Array;
  x25519_shared_secret: (secretKey: Uint8Array, publicKey: Uint8Array) => Uint8Array;
  hash_transcript: (parts: Uint8Array[]) => Uint8Array;
  derive_session_secrets: (
    role: "alice" | "bob",
    sessionId: Uint8Array,
    inviteSecret: Uint8Array,
    aliceNonce: Uint8Array,
    bobNonce: Uint8Array,
    mlkemSharedSecret: Uint8Array,
    x25519SharedSecret: Uint8Array,
    transcriptHash: Uint8Array,
  ) => {
    send_key: Uint8Array;
    recv_key: Uint8Array;
    handshake_key: Uint8Array;
    fingerprint: Uint8Array;
    resume_key: Uint8Array;
  };
  handshake_mac: (
    handshakeKey: Uint8Array,
    transcriptHash: Uint8Array,
    role: "alice" | "bob",
  ) => Uint8Array;
  resume_verifier: (resumeKey: Uint8Array) => Uint8Array;
  resume_mac: (
    resumeKey: Uint8Array,
    challengeNonce: Uint8Array,
    sessionIdHex: string,
    role: "alice" | "bob",
  ) => Uint8Array;
  encrypt_message: (key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array) => {
    nonce: Uint8Array;
    ciphertext: Uint8Array;
  };
  decrypt_message: (
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array,
  ) => Uint8Array;
};

let cachedModule: WasmModule | null = null;

export async function loadCryptoModule() {
  if (cachedModule) {
    return cachedModule;
  }

  const modulePath = "../generated/lattice_crypto.js";
  const imported = (await import(/* @vite-ignore */ modulePath)) as unknown as WasmModule;
  await imported.default();
  cachedModule = imported;
  return imported;
}
