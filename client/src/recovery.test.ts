import { describe, expect, it } from "vitest";
import {
  decodeReceivedBitmap,
  encodeReceivedBitmap,
  markChatDelivered,
  pendingMessagesInOrder,
  readBitmapBit,
} from "./recovery";

describe("pendingMessagesInOrder", () => {
  it("returns pending chat messages sorted by sequence number", () => {
    const pending = new Map([
      [7, { seq: 7, nonce: "n7", ciphertext: "c7" }],
      [2, { seq: 2, nonce: "n2", ciphertext: "c2" }],
      [5, { seq: 5, nonce: "n5", ciphertext: "c5" }],
    ]);

    expect(pendingMessagesInOrder(pending).map((message) => message.seq)).toEqual([2, 5, 7]);
  });
});

describe("markChatDelivered", () => {
  it("marks only the acknowledged outbound chat entry as delivered", () => {
    const updated = markChatDelivered(
      [
        { id: "alice-1", kind: "chat" as const, delivered: false },
        { id: "alice-2", kind: "chat" as const, delivered: false },
        { id: "file-1", kind: "file" as const, delivered: false },
      ],
      "alice",
      2,
    );

    expect(updated).toEqual([
      { id: "alice-1", kind: "chat", delivered: false },
      { id: "alice-2", kind: "chat", delivered: true },
      { id: "file-1", kind: "file", delivered: false },
    ]);
  });
});

describe("received bitmaps", () => {
  it("round-trips received chunk state", () => {
    const encoded = encodeReceivedBitmap([
      new Uint8Array([1]),
      undefined,
      new Uint8Array([2]),
      undefined,
      undefined,
      new Uint8Array([3]),
    ]);
    const bitmap = decodeReceivedBitmap(encoded, 6);

    expect(readBitmapBit(bitmap, 0)).toBe(true);
    expect(readBitmapBit(bitmap, 1)).toBe(false);
    expect(readBitmapBit(bitmap, 2)).toBe(true);
    expect(readBitmapBit(bitmap, 5)).toBe(true);
  });

  it("rejects a bitmap with the wrong decoded length", () => {
    expect(() => decodeReceivedBitmap("gA==", 16)).toThrow(
      "received invalid resume bitmap length",
    );
  });

  it("rejects trailing bits beyond total chunks", () => {
    expect(() => decodeReceivedBitmap("/w==", 1)).toThrow("received invalid resume bitmap");
  });
});
