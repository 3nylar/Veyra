/**
 * BIP-32 — HIERARCHICAL DETERMINISTIC WALLETS
 *
 * ─── The problem HD wallets solve ──────────────────────────────────────────
 * Before BIP-32, a wallet was a bag of unrelated random keys. Every new
 * address meant new key material that had to be backed up. Miss one backup,
 * lose those coins. The infamous "wallet.dat" era.
 *
 * An HD wallet derives an unbounded tree of keys from a single seed, so one
 * backup covers every key you will ever generate — including keys that do not
 * exist yet.
 *
 * ─── Structure ─────────────────────────────────────────────────────────────
 *
 *     seed (512 bits)
 *        ↓  HMAC-SHA512(key = "Bitcoin seed", data = seed)
 *     master key (left 32 bytes) + master chain code (right 32 bytes)
 *        ↓  CKDpriv, repeatedly
 *     m/84'/1'/0'/0/0  ← a specific address key
 *
 * ─── What is a chain code? ─────────────────────────────────────────────────
 * 32 bytes of additional entropy carried alongside every key. It is NOT
 * secret in the same way a private key is, but it IS sensitive: chain code +
 * public key is enough to derive every non-hardened descendant public key,
 * and chain code + ONE child private key is enough to recover the parent
 * private key (see the hardening discussion below).
 *
 * Its purpose is to make derivation depend on more than the key itself, so
 * that two wallets which happened to share a key would not share a subtree.
 *
 * ─── Child derivation, and the additive structure ──────────────────────────
 * For a non-hardened child at index i:
 *
 *     I = HMAC-SHA512(key = chainCode, data = serP(parentPub) ‖ ser32(i))
 *     childKey       = (IL + parentKey) mod n
 *     childChainCode = IR
 *
 * The child key is the parent key PLUS a tweak. That additive relationship is
 * what makes the following work:
 *
 *     (IL + k)·G  =  IL·G + k·G  =  IL·G + K
 *
 * i.e. the child PUBLIC key can be computed from the parent PUBLIC key alone,
 * with no private key involved. This is the watch-only wallet superpower: a
 * server can generate fresh receive addresses forever while holding no
 * spending authority whatsoever.
 *
 * ─── Hardened derivation, and why it is not optional ───────────────────────
 * For a hardened child (index ≥ 2^31):
 *
 *     I = HMAC-SHA512(key = chainCode, data = 0x00 ‖ ser256(parentKey) ‖ ser32(i))
 *
 * The parent PRIVATE key goes into the HMAC instead of the public key, which
 * breaks the public-derivation property. That is the entire point.
 *
 * THE ATTACK hardening prevents:
 *   Given a parent extended PUBLIC key (xpub + chain code) and ANY ONE
 *   non-hardened child PRIVATE key, an attacker computes:
 *
 *       IL     = HMAC-SHA512(chainCode, serP(parentPub) ‖ ser32(i))  ← public data
 *       parent = (childKey − IL) mod n                                ← RECOVERED
 *
 *   The parent private key falls out by subtraction. From there the attacker
 *   derives the entire subtree — every sibling, every descendant.
 *
 *   This is not theoretical. It is why leaking an xpub alongside a single
 *   child key is catastrophic, and why account-level nodes (m/84'/1'/0') are
 *   ALWAYS hardened: hardening at the account level contains the blast radius
 *   to one account rather than the whole wallet.
 *
 * ─── Where used in Veyra ───────────────────────────────────────────────────
 * Every key the wallet uses. Receive addresses at m/84'/coin'/0'/0/i, change
 * addresses at m/84'/coin'/0'/1/i.
 *
 * ─── Library boundary ──────────────────────────────────────────────────────
 * @noble/curves provides scalar arithmetic mod n and point addition.
 * @noble/hashes provides HMAC-SHA512.
 * Veyra is responsible for: the serialisation formats (byte-exact, or the
 * derived keys differ from every other wallet), the hardened/non-hardened
 * branch, and the invalid-child retry rule below.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { PrivateKey, CURVE_ORDER } from "../keys/privateKey.js";
import { PublicKey } from "../keys/publicKey.js";
import { hash160 } from "../crypto/hashes.js";
import { bytesToBigIntBE, bigIntToBytesBE, concatBytes, bytesToHex } from "../crypto/bytes.js";
import { wipe } from "../crypto/entropy.js";
import { VeyraError } from "../errors/index.js";

/** Indices >= this are hardened. 2^31. */
export const HARDENED_OFFSET = 0x80000000;

/**
 * The HMAC key used to derive the master node.
 *
 * This ASCII string is a domain separator, exactly as in BIP-340 tagged
 * hashes: it ensures a BIP-32 master key cannot collide with any other
 * HMAC-SHA512 construction that might use the same seed bytes. Other chains
 * use different strings for the same reason (e.g. "Nist256p1 seed").
 */
const MASTER_KEY_SALT = new TextEncoder().encode("Bitcoin seed");

export class DerivationError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Derivation failed: ${reason}`);
    this.name = "DerivationError";
  }
}

/** Serialise a uint32 big-endian. */
function ser32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/**
 * An extended key: a key plus the chain code and tree position needed to
 * derive children.
 *
 * Holds EITHER a private key (a full node, can derive anything) or only a
 * public key (a watch-only node, can derive non-hardened children only).
 */
export class ExtendedKey {
  readonly #privateKey: PrivateKey | null;
  readonly publicKey: PublicKey;
  readonly chainCode: Uint8Array;
  readonly depth: number;
  readonly index: number;
  readonly parentFingerprint: Uint8Array;

  private constructor(
    privateKey: PrivateKey | null,
    publicKey: PublicKey,
    chainCode: Uint8Array,
    depth: number,
    index: number,
    parentFingerprint: Uint8Array,
  ) {
    this.#privateKey = privateKey;
    this.publicKey = publicKey;
    this.chainCode = chainCode;
    this.depth = depth;
    this.index = index;
    this.parentFingerprint = parentFingerprint;
  }

  /**
   * Derive the master node from a BIP-39 seed.
   *
   *     I = HMAC-SHA512("Bitcoin seed", seed)
   *     master key = IL, master chain code = IR
   *
   * BIP-32 requires a seed of 16–64 bytes. We additionally reject anything
   * under 16 bytes outright rather than deriving from it — a short seed is
   * almost always a caller bug, and deriving anyway produces a working wallet
   * with far less security than the user believes they have.
   */
  static fromSeed(seed: Uint8Array): ExtendedKey {
    if (seed.length < 16 || seed.length > 64) {
      throw new DerivationError(
        `seed must be between 16 and 64 bytes, received ${seed.length}`,
      );
    }

    const I = hmac(sha512, MASTER_KEY_SALT, seed);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    try {
      // Probability ~2^-127. BIP-32 says the seed is invalid; there is no
      // retry defined at the master level, so we fail loudly.
      const scalar = bytesToBigIntBE(IL);
      if (scalar === 0n || scalar >= CURVE_ORDER) {
        throw new DerivationError("seed produced an invalid master key; use a different seed");
      }
      const privateKey = PrivateKey.fromBytes(IL);
      return new ExtendedKey(
        privateKey,
        PublicKey.fromPrivateKey(privateKey),
        IR,
        0,
        0,
        new Uint8Array(4),
      );
    } finally {
      wipe(I);
      wipe(IL);
    }
  }

  /** True if this node holds a private key and can therefore sign. */
  get hasPrivateKey(): boolean {
    return this.#privateKey !== null;
  }

  /**
   * The private key. Throws on a watch-only node rather than returning null,
   * so a missing key can never be silently treated as a valid one.
   */
  get privateKey(): PrivateKey {
    if (this.#privateKey === null) {
      throw new DerivationError("this is a watch-only node and holds no private key");
    }
    return this.#privateKey;
  }

  /**
   * First 4 bytes of HASH160(publicKey). Used in serialisation to reference
   * the parent.
   *
   * It is only a 32-bit hint for detecting mismatched keys, NOT a secure
   * identifier — collisions are expected roughly every 2^16 keys by the
   * birthday bound. Nothing security-relevant may depend on it.
   */
  get fingerprint(): Uint8Array {
    return hash160(this.publicKey.toBytes()).slice(0, 4);
  }

  /**
   * Derive one child.
   *
   * The retry rule at the bottom is easy to miss and required by BIP-32: if
   * the derived scalar is invalid (IL >= n, or the resulting child key is
   * zero), the correct behaviour is to SKIP to index+1, not to reduce mod n
   * and not to fail. Probability ~2^-127, so this branch will never execute
   * in practice — but an implementation that reduces instead of skipping
   * would derive a different key than every other wallet in that case.
   */
  derive(index: number): ExtendedKey {
    if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
      throw new DerivationError(`index must be a uint32, received ${index}`);
    }
    const hardened = index >= HARDENED_OFFSET;

    if (hardened && !this.hasPrivateKey) {
      // The defining limitation of a watch-only node, and the reason xpubs
      // are safe to hand to a server: hardened derivation is impossible
      // without the private key.
      throw new DerivationError(
        "cannot derive a hardened child from a watch-only (public-only) node",
      );
    }

    let data: Uint8Array;
    let secret: Uint8Array | null = null;
    if (hardened) {
      // 0x00 ‖ ser256(parentKey) ‖ ser32(i)
      // The leading zero byte makes this 33 bytes, matching the length of a
      // compressed public key. Without it, a hardened derivation could be
      // confused with a non-hardened one at the byte level.
      secret = this.privateKey.toBytes();
      data = concatBytes(new Uint8Array([0x00]), secret, ser32(index));
    } else {
      // serP(parentPub) ‖ ser32(i)
      data = concatBytes(this.publicKey.toBytes(), ser32(index));
    }

    const I = hmac(sha512, this.chainCode, data);
    const IL = I.slice(0, 32);
    const childChainCode = I.slice(32);

    try {
      const tweak = bytesToBigIntBE(IL);

      // BIP-32 §"Child key derivation": if IL >= n, skip this index.
      if (tweak >= CURVE_ORDER) {
        return this.derive(index + 1);
      }

      if (this.hasPrivateKey) {
        // childKey = (IL + parentKey) mod n
        const parentScalar = this.privateKey.toBigInt();
        const childScalar = (tweak + parentScalar) % CURVE_ORDER;

        // If the sum is zero the child key is invalid; skip.
        if (childScalar === 0n) {
          return this.derive(index + 1);
        }

        const childPrivate = PrivateKey.fromBigInt(childScalar);
        return new ExtendedKey(
          childPrivate,
          PublicKey.fromPrivateKey(childPrivate),
          childChainCode,
          this.depth + 1,
          index,
          this.fingerprint,
        );
      }

      // Watch-only: childPub = IL·G + parentPub
      // This is the point-addition form of the same relationship, and is
      // exactly why non-hardened public derivation is possible at all.
      const parentPoint = secp256k1.Point.fromBytes(this.publicKey.toBytes());
      const childPoint = secp256k1.Point.BASE.multiply(tweak).add(parentPoint);

      // Vanishingly unlikely, but the point at infinity has no encoding.
      try {
        childPoint.assertValidity();
      } catch {
        return this.derive(index + 1);
      }

      return new ExtendedKey(
        null,
        PublicKey.fromBytes(childPoint.toBytes(true)),
        childChainCode,
        this.depth + 1,
        index,
        this.fingerprint,
      );
    } finally {
      wipe(I);
      wipe(IL);
      if (secret) wipe(secret);
    }
  }

  /**
   * Derive along a path such as "m/84'/1'/0'/0/0".
   *
   * Both `'` and `h` are accepted as hardened markers, since both appear in
   * the wild. Parsing is strict otherwise: a malformed path throws rather
   * than being partially interpreted, because silently deriving from a
   * misparsed path sends funds to an address the user cannot recover.
   */
  derivePath(path: string): ExtendedKey {
    const trimmed = path.trim();
    if (trimmed === "m" || trimmed === "") return this;

    const segments = trimmed.split("/");
    if (segments[0] !== "m") {
      throw new DerivationError("path must begin with 'm'");
    }

    let node: ExtendedKey = this;
    for (const segment of segments.slice(1)) {
      const hardened = segment.endsWith("'") || segment.endsWith("h");
      const raw = hardened ? segment.slice(0, -1) : segment;

      if (!/^\d+$/.test(raw)) {
        throw new DerivationError(`path segment '${segment}' is not a valid index`);
      }
      const index = Number.parseInt(raw, 10);
      if (index >= HARDENED_OFFSET) {
        throw new DerivationError(`path index ${index} exceeds the maximum of 2^31 - 1`);
      }
      node = node.derive(hardened ? index + HARDENED_OFFSET : index);
    }
    return node;
  }

  /**
   * Strip the private key, yielding a watch-only node.
   *
   * Recall the hardening discussion: this node is safe to export ONLY if no
   * non-hardened descendant private key is ever exposed alongside it.
   */
  neutered(): ExtendedKey {
    return new ExtendedKey(
      null,
      this.publicKey,
      this.chainCode,
      this.depth,
      this.index,
      this.parentFingerprint,
    );
  }

  toString(): string {
    // Never includes key material — the chain code is sensitive too.
    return `ExtendedKey<depth=${this.depth} index=${this.index} ${
      this.hasPrivateKey ? "private" : "watch-only"
    }>`;
  }

  toJSON(): string {
    return this.toString();
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }

  /** Public identifier — safe to log. */
  get identifier(): string {
    return bytesToHex(this.fingerprint);
  }
}

/** Convenience: master node straight from a seed. */
export function masterKeyFromSeed(seed: Uint8Array): ExtendedKey {
  return ExtendedKey.fromSeed(seed);
}

export { bigIntToBytesBE };
