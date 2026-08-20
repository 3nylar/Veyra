/**
 * PRIVATE KEYS
 *
 * ─── What is a Bitcoin private key, actually? ──────────────────────────────
 * An integer. That is all.
 *
 * Specifically, an integer k in the range [1, n−1], where
 *
 *   n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
 *
 * is the order of the secp256k1 group. It is not a file, not a password, not
 * an encrypted blob. Every 32-byte string below n is a valid Bitcoin private
 * key with a corresponding address that already exists on the blockchain. The
 * key is not "created" so much as *selected* from a space of ~2^256
 * possibilities. Ownership of an address means nothing more than knowing the
 * integer, and anyone who learns that integer owns the coins equally and
 * irrevocably. There is no account, no registration, no revocation.
 *
 * ─── Why is the range [1, n−1] and not [0, 2^256−1]? ───────────────────────
 *   k = 0     → 0·G = O, the point at infinity. Not a valid public key.
 *   k ≥ n     → arithmetic wraps: (k mod n)·G = k·G. So k and k−n would map
 *               to the *same* public key. Accepting k ≥ n would break the
 *               one-to-one correspondence between keys and points, and some
 *               implementations would reduce while others rejected — an
 *               interoperability and fund-loss hazard.
 *
 * The excluded range is about 2^128 values out of 2^256, i.e. a fraction of
 * roughly 2^-128. A uniformly random 32-byte draw lands out of range with
 * probability ~1 in 2^128 — it will never happen in practice, and we still
 * check, because "never happens in practice" is how CVEs are written.
 *
 * ─── Why must it remain secret, and what does "secret" mean here? ──────────
 * A signature made with k authorises spending. Bitcoin has no other
 * authorisation mechanism. There is no second factor, no fraud department, no
 * chargeback, and no way to prove after the fact that a valid signature was
 * made by a thief rather than by you — the two are mathematically identical.
 *
 * ─── Why does knowing the address not reveal the key? ──────────────────────
 * Two independent one-way functions stand between them:
 *
 *   k --[ EC scalar multiplication ]--> K --[ HASH160 ]--> address
 *       inverting requires solving        inverting requires
 *       the discrete log (~2^128)         a hash preimage (~2^160)
 *
 * An attacker holding an address has, in the pre-spend case, not even seen
 * the public key. After you spend from a P2WPKH output the public key becomes
 * visible in the witness, at which point only the discrete-log barrier
 * remains. This is the technical basis for the "don't reuse addresses"
 * guidance, and it is one reason Veyra uses fresh change addresses (§17).
 *
 * ─── Implementation notes ──────────────────────────────────────────────────
 * `PrivateKey` wraps bytes rather than exposing a bare Uint8Array so that:
 *   - validation happens exactly once, at construction (parse, don't validate);
 *   - `toString`, `toJSON`, and `util.inspect` are all overridden to redact.
 *     An accidental `console.log(key)` or `JSON.stringify({ key })` in the API
 *     layer or a log line is otherwise a direct path from a debug statement to
 *     total fund loss. This is a real and common failure mode, so we make the
 *     safe behaviour the default rather than a discipline anyone must remember.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { randomBytes, wipe } from "../crypto/entropy.js";
import type { RandomSource } from "../crypto/entropy.js";
import {
  bytesToBigIntBE,
  bigIntToBytesBE,
  bytesToHex,
  hexToBytes,
} from "../crypto/bytes.js";
import { InvalidPrivateKeyError } from "../errors/index.js";

/** Order of the secp256k1 group. A valid private key is in [1, N-1]. */
export const CURVE_ORDER: bigint = secp256k1.CURVE.n;

/** Private keys are always exactly 32 bytes, zero-padded on the left. */
export const PRIVATE_KEY_BYTES = 32;

/** Maximum rejection-sampling attempts before we conclude the RNG is broken. */
const MAX_SAMPLING_ATTEMPTS = 128;

export class PrivateKey {
  /**
   * The scalar, big-endian, 32 bytes. Private so that callers must go through
   * `toBytes()`, which is a deliberate, greppable act — `grep -rn 'toBytes'`
   * enumerates every place raw key material escapes.
   */
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * Validate and wrap 32 bytes as a private key.
   * Rejects wrong lengths and out-of-range scalars.
   */
  static fromBytes(bytes: Uint8Array): PrivateKey {
    if (bytes.length !== PRIVATE_KEY_BYTES) {
      throw new InvalidPrivateKeyError(
        `expected ${PRIVATE_KEY_BYTES} bytes, received ${bytes.length}`,
      );
    }
    const scalar = bytesToBigIntBE(bytes);
    if (scalar === 0n) {
      throw new InvalidPrivateKeyError("scalar is zero");
    }
    if (scalar >= CURVE_ORDER) {
      throw new InvalidPrivateKeyError("scalar is greater than or equal to the curve order");
    }
    // Copy so a caller mutating their buffer cannot mutate our key.
    return new PrivateKey(Uint8Array.from(bytes));
  }

  /** Parse from strict 64-character hex. */
  static fromHex(hex: string): PrivateKey {
    return PrivateKey.fromBytes(hexToBytes(hex));
  }

  static fromBigInt(scalar: bigint): PrivateKey {
    if (scalar <= 0n || scalar >= CURVE_ORDER) {
      throw new InvalidPrivateKeyError("scalar out of range [1, n-1]");
    }
    return new PrivateKey(bigIntToBytesBE(scalar, PRIVATE_KEY_BYTES));
  }

  /**
   * Generate a fresh private key by REJECTION SAMPLING.
   *
   * ─── Why rejection sampling and not `scalar mod n`? ──────────────────────
   * Reducing a uniform 256-bit draw modulo n is the obvious shortcut and it is
   * subtly wrong. Because 2^256 is not a multiple of n, the values in
   * [0, 2^256 mod n) can each be hit by one extra preimage, so they come out
   * *twice as likely* as the rest. The bias here is around 2^-128 and is
   * unexploitable for key generation — but the identical mistake in ECDSA
   * *nonce* generation is catastrophic and has been exploited repeatedly
   * (biased nonces let lattice attacks recover the private key from a handful
   * of signatures). We use the unbiased method everywhere so that the correct
   * pattern is the one present in the codebase to copy.
   *
   * Draw, check range, discard and redraw if out of range. Each attempt fails
   * with probability ~2^-128, so the loop effectively always exits on the
   * first iteration. The attempt cap exists to convert a hypothetical
   * infinite loop (a stuck RNG returning all-0xFF) into a loud failure.
   *
   * @param source Test-only. Production callers pass nothing.
   */
  static generate(source?: RandomSource): PrivateKey {
    for (let attempt = 0; attempt < MAX_SAMPLING_ATTEMPTS; attempt++) {
      const candidate = randomBytes(PRIVATE_KEY_BYTES, source);
      const scalar = bytesToBigIntBE(candidate);
      if (scalar > 0n && scalar < CURVE_ORDER) {
        return new PrivateKey(candidate);
      }
      // Out of range: wipe the rejected draw before discarding it. It is not
      // a usable key, but it is RNG output and should not linger in the heap.
      wipe(candidate);
    }
    throw new InvalidPrivateKeyError(
      "rejection sampling failed repeatedly; the random source may be defective",
    );
  }

  /** The scalar as a BigInt. */
  toBigInt(): bigint {
    return bytesToBigIntBE(this.#bytes);
  }

  /**
   * Raw key bytes. Returns a COPY — callers cannot mutate our state, and are
   * responsible for wiping what they receive.
   */
  toBytes(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }

  /**
   * Hex, for tests and explicit export flows only. Named verbosely so that it
   * reads as alarming at a call site and is trivial to grep for in review.
   */
  toHexUnsafe(): string {
    return bytesToHex(this.#bytes);
  }

  /** Destroy this key's material in place. The instance is unusable after. */
  destroy(): void {
    wipe(this.#bytes);
  }

  // ─── Redaction ──────────────────────────────────────────────────────────
  // Every accidental-stringification path is closed. See tests/cryptography/
  // key-leakage.test.ts, which asserts each of these independently.

  toString(): string {
    return "PrivateKey<redacted>";
  }

  toJSON(): string {
    return "PrivateKey<redacted>";
  }

  /** Node's console.log / util.inspect hook. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "PrivateKey<redacted>";
  }

  get [Symbol.toStringTag](): string {
    return "PrivateKey";
  }
}
