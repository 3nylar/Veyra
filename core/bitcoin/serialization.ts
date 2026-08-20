/**
 * BITCOIN SERIALIZATION
 *
 * ─── Why byte-exactness is a security property, not a formatting detail ────
 * A transaction's identity IS its serialisation: txid = HASH256(rawBytes).
 * A signature commits to a hash of a specific byte layout. So a serialiser
 * that is off by one byte does not produce a "slightly wrong" transaction —
 * it produces a different transaction with a different txid whose signature
 * verifies against nothing.
 *
 * There is no validation layer that catches this. The network simply rejects
 * the transaction, or worse, accepts one that spends differently than the
 * user approved.
 *
 * ─── Little-endian, mostly ─────────────────────────────────────────────────
 * Bitcoin serialises integers little-endian, which trips up everyone who
 * learned network byte order. But NOT uniformly:
 *
 *   - Integers in transactions: little-endian.
 *   - Hashes as byte strings: internal (little-endian) order on the wire.
 *   - Hashes DISPLAYED to humans: reversed (big-endian hex).
 *
 * That last distinction is the single most common source of confusion in
 * Bitcoin development. The txid you see in a block explorer is the REVERSE
 * of the bytes that appear on the wire. Veyra keeps them separate and
 * explicitly named — `txid()` returns display order, `txidBytes()` returns
 * wire order — because silently mixing them produces transactions that
 * reference inputs that do not exist.
 *
 * ─── CompactSize (varint) ──────────────────────────────────────────────────
 * A variable-length integer encoding used for counts and lengths:
 *
 *   < 0xfd            1 byte,  the value itself
 *   <= 0xffff         0xfd + uint16 LE
 *   <= 0xffffffff     0xfe + uint32 LE
 *   otherwise         0xff + uint64 LE
 *
 * NON-CANONICAL ENCODINGS MUST BE REJECTED. The value 1 can be written as
 * `01`, or as `fd0100`, or as `fe01000000`. All decode to 1, but they are
 * different bytes and therefore different txids for the same logical
 * transaction. Accepting them is a malleability vulnerability: an attacker
 * could re-encode your transaction, change its txid, and break anything that
 * referenced the original. The parser below rejects every non-minimal form.
 */

import { hash256 } from "../crypto/hashes.js";
import { VeyraError } from "../errors/index.js";

export class SerializationError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Serialization: ${reason}`);
    this.name = "SerializationError";
  }
}

/** Incrementally builds a byte buffer. */
export class ByteWriter {
  private chunks: Uint8Array[] = [];
  private length = 0;

  writeBytes(bytes: Uint8Array): this {
    this.chunks.push(Uint8Array.from(bytes));
    this.length += bytes.length;
    return this;
  }

  writeUint8(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new SerializationError("uint8 out of range");
    }
    return this.writeBytes(new Uint8Array([value]));
  }

  writeUint32LE(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new SerializationError("uint32 out of range");
    }
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, true);
    return this.writeBytes(out);
  }

  /**
   * Amounts are uint64 satoshis. BigInt is mandatory here: 21 million BTC is
   * 2.1e15 satoshis, which fits in a double, but intermediate arithmetic in
   * fee calculation does not reliably stay exact. Using `number` for money is
   * how rounding errors become lost funds.
   */
  writeUint64LE(value: bigint): this {
    if (value < 0n || value > 0xffffffffffffffffn) {
      throw new SerializationError("uint64 out of range");
    }
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, value, true);
    return this.writeBytes(out);
  }

  /** CompactSize, always in minimal form. */
  writeVarInt(value: number | bigint): this {
    const n = BigInt(value);
    if (n < 0n) throw new SerializationError("varint must be non-negative");
    if (n < 0xfdn) return this.writeUint8(Number(n));
    if (n <= 0xffffn) {
      const out = new Uint8Array(3);
      const view = new DataView(out.buffer);
      view.setUint8(0, 0xfd);
      view.setUint16(1, Number(n), true);
      return this.writeBytes(out);
    }
    if (n <= 0xffffffffn) {
      const out = new Uint8Array(5);
      const view = new DataView(out.buffer);
      view.setUint8(0, 0xfe);
      view.setUint32(1, Number(n), true);
      return this.writeBytes(out);
    }
    const out = new Uint8Array(9);
    const view = new DataView(out.buffer);
    view.setUint8(0, 0xff);
    view.setBigUint64(1, n, true);
    return this.writeBytes(out);
  }

  /** Length-prefixed byte string. */
  writeVarBytes(bytes: Uint8Array): this {
    return this.writeVarInt(bytes.length).writeBytes(bytes);
  }

  toBytes(): Uint8Array {
    const out = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }

  get size(): number {
    return this.length;
  }
}

/** Reads a byte buffer, rejecting malformed and non-canonical encodings. */
export class ByteReader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {}

  get remaining(): number {
    return this.data.length - this.offset;
  }

  get position(): number {
    return this.offset;
  }

  readBytes(count: number): Uint8Array {
    if (count < 0) throw new SerializationError("negative read length");
    if (this.remaining < count) {
      throw new SerializationError(
        `unexpected end of data: needed ${count} bytes, ${this.remaining} remain`,
      );
    }
    const out = this.data.slice(this.offset, this.offset + count);
    this.offset += count;
    return out;
  }

  readUint8(): number {
    return this.readBytes(1)[0]!;
  }

  readUint32LE(): number {
    const bytes = this.readBytes(4);
    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  }

  readUint64LE(): bigint {
    const bytes = this.readBytes(8);
    return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
  }

  /**
   * CompactSize, rejecting non-minimal encodings.
   *
   * The minimality check is the security-relevant part. Without it, the same
   * logical transaction has many valid byte encodings and therefore many
   * txids — third-party malleability.
   */
  readVarInt(): bigint {
    const first = this.readUint8();
    if (first < 0xfd) return BigInt(first);

    if (first === 0xfd) {
      const bytes = this.readBytes(2);
      const value = new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, true);
      if (value < 0xfd) throw new SerializationError("non-minimal varint encoding");
      return BigInt(value);
    }
    if (first === 0xfe) {
      const bytes = this.readBytes(4);
      const value = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
      if (value <= 0xffff) throw new SerializationError("non-minimal varint encoding");
      return BigInt(value);
    }
    const bytes = this.readBytes(8);
    const value = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
    if (value <= 0xffffffffn) throw new SerializationError("non-minimal varint encoding");
    return value;
  }

  readVarBytes(): Uint8Array {
    const length = this.readVarInt();
    // Bound the allocation: an attacker-supplied length of 2^64 must not
    // become a memory-exhaustion DoS before the length check fails.
    if (length > BigInt(this.remaining)) {
      throw new SerializationError("declared length exceeds remaining data");
    }
    return this.readBytes(Number(length));
  }

  /** Throws unless every byte has been consumed. */
  assertConsumed(): void {
    if (this.remaining !== 0) {
      throw new SerializationError(`${this.remaining} trailing bytes after parsing`);
    }
  }
}

/**
 * Reverse a byte array. Used exclusively for the wire↔display hash conversion.
 *
 * Isolated into a named function rather than inlined so that every place the
 * conversion happens is greppable — mixing the two orderings is the classic
 * Bitcoin bug.
 */
export function reverseBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes).reverse();
}

/** HASH256 of arbitrary bytes — the txid/block-hash construction. */
export function doubleSha256(data: Uint8Array): Uint8Array {
  return hash256(data);
}
