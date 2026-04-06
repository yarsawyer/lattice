export type PendingChatMessage = {
  seq: number;
  nonce: string;
  ciphertext: string;
};

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

function setBitmapBit(bitmap: Uint8Array, index: number) {
  bitmap[Math.floor(index / 8)] |= 1 << (7 - (index % 8));
}

export function readBitmapBit(bitmap: Uint8Array, index: number) {
  return (bitmap[Math.floor(index / 8)] & (1 << (7 - (index % 8)))) !== 0;
}

export function encodeReceivedBitmap(chunks: Array<Uint8Array | undefined>) {
  const bitmap = new Uint8Array(Math.ceil(chunks.length / 8));
  for (let index = 0; index < chunks.length; index += 1) {
    if (chunks[index]) {
      setBitmapBit(bitmap, index);
    }
  }
  return bytesToBase64(bitmap);
}

export function decodeReceivedBitmap(encoded: string, totalChunks: number) {
  const bitmap = base64ToBytes(encoded);
  const expectedLength = Math.ceil(totalChunks / 8);
  if (bitmap.length !== expectedLength) {
    throw new Error("received invalid resume bitmap length");
  }

  const trailingBits = expectedLength * 8 - totalChunks;
  if (trailingBits > 0 && bitmap.length > 0) {
    const allowedMask = 0xff << trailingBits;
    if ((bitmap[bitmap.length - 1] & ~allowedMask) !== 0) {
      throw new Error("received invalid resume bitmap");
    }
  }

  return bitmap;
}

export function pendingMessagesInOrder(pendingMessages: Map<number, PendingChatMessage>) {
  return Array.from(pendingMessages.values()).sort((left, right) => left.seq - right.seq);
}

export function markChatDelivered<T extends { id: string; kind: string }>(
  messages: T[],
  role: "alice" | "bob",
  seq: number,
) {
  const targetId = `${role}-${seq}`;
  return messages.map((message) =>
    message.kind === "chat" && message.id === targetId
      ? ({ ...message, delivered: true } as T)
      : message,
  );
}
