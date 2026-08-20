/**
 * PUBLIC KEYS
 *
 * ─── What it is ────────────────────────────────────────────────────────────
 * A point K = kG on secp256k1, where k is the private scalar and G is the
 * fixed generator. Not a number — a *pair* of field elements (x, y).
 *
 * ─── Why the relationship is one-way ───────────────────────────────────────
 * Forward:  k → kG costs ~256 point doublings. Microseconds.
 * Backward: kG → k is the elliptic-curve discrete logarithm problem. The best
 *           known generic attack, Pollard's rho, needs ~sqrt(n) ≈ 2^128 group
 *           operations. For scale: if every atom in Earth's crust performed
 *           one operation per nanosecond, this would still not finish before
 *           the sun burns out.
 *
 * Two honest caveats. First, hardness is *conjectured*, not proven — there is
 * no theorem forbidding a better algorithm. Second, Shor's algorithm on a
 * large fault-tolerant quantum computer solves ECDLP in polynomial time. Both
 * are recorded as explicit assumptions in docs/THREAT-MODEL.md.
 *
 * ─── Compressed encoding (SEC1) ────────────────────────────────────────────
 * 33 bytes: a parity prefix (0x02 even y / 0x03 odd y) followed by the 32-byte
 * big-endian x coordinate. y is recovered by solving y² = x³ + 7 and picking
 * the root with the stated parity — p is odd, so exactly one of y and p−y is even.
 *
 * The legacy uncompressed form (65 bytes, prefix 0x04, both coordinates) is
 * accepted for *parsing* — it appears in old on-chain data — but Veyra never
 * produces it. This is not stylistic:
 *   - BIP-143 makes compressed keys mandatory for SegWit v0 spends. An
 *     uncompressed key in a P2WPKH witness is simply invalid.
 *   - The same private key yields a *different* address under each encoding.
 *     Users have repeatedly "lost" funds by generating an address one way and
 *     restoring the other, then concluding the wallet was empty.
 *
 * ─── Library boundary ──────────────────────────────────────────────────────
 * @noble/curves is responsible for: constant-time scalar multiplication,
 * point validation, and rejecting the point at infinity and off-curve points.
 * Veyra is responsible for: never handing it an unvalidated scalar, and never
 * treating a parsed point as trusted before `isValid()` has passed.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "../crypto/bytes.js";
import { hash160 } from "../crypto/hashes.js";
import { InvalidPublicKeyError } from "../errors/index.js";
import type { PrivateKey } from "./privateKey.js";

export const COMPRESSED_PUBLIC_KEY_BYTES = 33;
export const UNCOMPRESSED_PUBLIC_KEY_BYTES = 65;

export class PublicKey {
  /** Always stored compressed. Uncompressed input is normalised on parse. */
  private readonly bytes: Uint8Array;

  private constructor(compressed: Uint8Array) {
    this.bytes = compressed;
  }

  /**
   * Derive the public key from a private key: K = kG.
   *
   * This is the single most important line in the wallet, and it is one
   * function call — which is the point. The security here comes from
   * @noble/curves' constant-time implementation, not from anything Veyra does
   * cleverly. Our job is to have validated k before this line, and to not
   * leak K's derivation timing. The reference implementation in
   * core/crypto/reference/secp256k1.ts shows what this call is doing, and
   * tests/cryptography/reference-secp256k1.test.ts proves the two agree.
   */
  static fromPrivateKey(privateKey: PrivateKey): PublicKey {
    const secret = privateKey.toBytes();
    try {
      const compressed = secp256k1.getPublicKey(secret, true);
      return new PublicKey(compressed);
    } finally {
      // Wipe our copy of the secret regardless of success or throw.
      secret.fill(0);
    }
  }

  /**
   * Parse a SEC1-encoded public key, compressed or uncompressed.
   *
   * Validation is not optional. An unvalidated point is an invalid-curve
   * attack primitive: feed a carefully chosen off-curve point into an
   * implementation that skips the check and the resulting arithmetic can leak
   * the other party's secret. We do not currently perform ECDH, but the habit
   * of validating at every boundary is what prevents that from becoming a
   * vulnerability the day someone adds it.
   */
  static fromBytes(bytes: Uint8Array): PublicKey {
    if (
      bytes.length !== COMPRESSED_PUBLIC_KEY_BYTES &&
      bytes.length !== UNCOMPRESSED_PUBLIC_KEY_BYTES
    ) {
      throw new InvalidPublicKeyError(
        `expected ${COMPRESSED_PUBLIC_KEY_BYTES} or ${UNCOMPRESSED_PUBLIC_KEY_BYTES} bytes, received ${bytes.length}`,
      );
    }
    const prefix = bytes[0]!;
    if (bytes.length === COMPRESSED_PUBLIC_KEY_BYTES && prefix !== 0x02 && prefix !== 0x03) {
      throw new InvalidPublicKeyError("compressed key must start with 0x02 or 0x03");
    }
    if (bytes.length === UNCOMPRESSED_PUBLIC_KEY_BYTES && prefix !== 0x04) {
      throw new InvalidPublicKeyError("uncompressed key must start with 0x04");
    }

    let point;
    try {
      // Throws if x has no square root (point is not on the curve), if the
      // coordinates are out of field range, or if the point is at infinity.
      point = secp256k1.Point.fromBytes(bytes);
      point.assertValidity();
    } catch {
      // Deliberately swallow the library's message: it can echo caller-
      // supplied bytes back into logs. Ours is a constant string.
      throw new InvalidPublicKeyError("point is not a valid secp256k1 curve point");
    }
    return new PublicKey(point.toBytes(true));
  }

  static fromHex(hex: string): PublicKey {
    return PublicKey.fromBytes(hexToBytes(hex));
  }

  /** 33-byte compressed SEC1 encoding. Returns a copy. */
  toBytes(): Uint8Array {
    return Uint8Array.from(this.bytes);
  }

  toHex(): string {
    return bytesToHex(this.bytes);
  }

  /** 65-byte uncompressed SEC1. Provided for interop and tests only. */
  toUncompressedBytes(): Uint8Array {
    return secp256k1.Point.fromBytes(this.bytes).toBytes(false);
  }

  /** The x coordinate as a BigInt. */
  get x(): bigint {
    return secp256k1.Point.fromBytes(this.bytes).x;
  }

  /** The y coordinate as a BigInt. */
  get y(): bigint {
    return secp256k1.Point.fromBytes(this.bytes).y;
  }

  /**
   * HASH160 of the compressed key — 20 bytes.
   *
   * This is the value that becomes the witness program of a P2WPKH output and
   * the payload of a P2PKH address. Note that it commits to the *compressed*
   * encoding specifically: hashing the uncompressed form gives a different
   * 20 bytes and therefore a different, unrelated address.
   */
  hash160(): Uint8Array {
    return hash160(this.bytes);
  }

  equals(other: PublicKey): boolean {
    // Public keys are not secret, so a plain comparison is fine here.
    const a = this.bytes;
    const b = other.bytes;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  toString(): string {
    return `PublicKey<${this.toHex()}>`;
  }
}
