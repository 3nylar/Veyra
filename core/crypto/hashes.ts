/**
 * HASHING — Bitcoin's structural glue.
 *
 * ─── What is a cryptographic hash function? ────────────────────────────────
 * A deterministic function H mapping an arbitrary-length input to a
 * fixed-length output, with three properties that matter here:
 *
 *   1. Preimage resistance
 *      Given h, it is infeasible to find any m with H(m) = h.
 *      Cost for SHA-256: ~2^256.
 *      This is what stops an attacker who sees a P2WPKH address (which is a
 *      HASH160 of a public key) from recovering the public key it commits to.
 *
 *   2. Second-preimage resistance
 *      Given m1, it is infeasible to find m2 ≠ m1 with H(m2) = H(m1).
 *      Cost: ~2^256.
 *      This is what stops an attacker from finding a *different* transaction
 *      that produces the same sighash as one you already signed — which would
 *      let your signature authorise a payment you never approved.
 *
 *   3. Collision resistance
 *      It is infeasible to find *any* m1 ≠ m2 with H(m1) = H(m2).
 *      Cost: ~2^128 by the birthday bound — which is why SHA-256 is rated at
 *      128-bit security, not 256, and why that happens to match secp256k1's
 *      128-bit level. Bitcoin's security level is uniform, not accidental.
 *
 * ─── Hashing is NOT encryption ─────────────────────────────────────────────
 * This is worth stating flatly because it is the most common misconception
 * about Bitcoin. Encryption is *invertible with a key*: E(k, m) → c, and
 * D(k, c) → m. Hashing has no key and no inverse. H destroys information: a
 * 1 GB file and a 3-byte string both map to 32 bytes, so infinitely many
 * inputs share every output. There is no "decrypting a hash" — there is only
 * guessing an input and checking. When a wallet's address "hides" a public
 * key, it is not encrypting it; it is committing to it irreversibly.
 *
 * Bitcoin, likewise, does not encrypt transactions. Every transaction on the
 * chain is fully public and readable by anyone. What Bitcoin uses cryptography
 * for is *authentication* — proving that whoever authorised a spend held the
 * right private key — and *commitment* — binding data so it cannot be altered
 * after the fact. Confidentiality is not among Bitcoin's goals.
 *
 * ─── Why Bitcoin hashes so aggressively ────────────────────────────────────
 *   - Commitment: a signature signs a hash of the transaction, not the
 *     transaction. Fixed-size input to the signing algorithm, and the hash
 *     binds every committed field.
 *   - Identity: a txid IS a hash of the transaction. Identity is derived from
 *     content, so referencing a txid is referencing exact bytes.
 *   - Size: a 20-byte HASH160 is a much cheaper on-chain payment destination
 *     than a 33-byte public key, and shorter for humans to handle.
 *   - Deferred disclosure: with P2WPKH the chain holds only the *hash* of your
 *     public key until you spend. Until that moment, even a hypothetical
 *     quantum adversary running Shor's algorithm has no public key to attack.
 *
 * ─── Where these are used in Veyra ─────────────────────────────────────────
 *   sha256    — sighash construction, BIP-32 (inside HMAC-SHA512), checksums
 *   hash256   — txids, block hashes, Base58Check checksums
 *   hash160   — P2PKH / P2WPKH payment destinations
 *   taggedHash— BIP-340 Schnorr / BIP-341 Taproot domain separation
 *
 * ─── Library boundary ──────────────────────────────────────────────────────
 * @noble/hashes is responsible for: correct, constant-time-where-relevant,
 * audited implementations of SHA-256 and RIPEMD-160.
 * Veyra is responsible for: composing them in the exact orders Bitcoin's
 * consensus rules specify, and never confusing one composition for another.
 * A hash160 where a hash256 was required is a consensus bug, not a library bug.
 *
 * A readable, dependency-free reference implementation of SHA-256 lives in
 * ./reference/sha256.ts. It is for study only and is never imported here.
 */

import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { ripemd160 as nobleRipemd160 } from "@noble/hashes/legacy.js";

/** SHA-256. 32-byte output. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/**
 * RIPEMD-160. 20-byte output.
 *
 * Why does Bitcoin use a second, unrelated hash family at all? Two reasons.
 * Size: 20 bytes rather than 32, which mattered when address formats were
 * designed. And hedging: RIPEMD-160 and SHA-2 have entirely different
 * internal structures, so a break of one is unlikely to imply a break of the
 * composition. Note that RIPEMD-160 alone offers only ~80-bit collision
 * resistance, which is why Bitcoin never uses it alone — see hash160.
 */
export function ripemd160(data: Uint8Array): Uint8Array {
  return nobleRipemd160(data);
}

/**
 * HASH256 = SHA-256(SHA-256(x)). Used for txids, block hashes, and the
 * 4-byte Base58Check checksum.
 *
 * Why double? Satoshi did not explain, but the standard rationale is defence
 * against length-extension. Merkle–Damgård constructions like SHA-256 leak
 * enough internal state in their output that an attacker who knows H(m) and
 * |m| can compute H(m ‖ padding ‖ suffix) without knowing m. Hashing the
 * 32-byte digest a second time breaks that property, because the outer hash's
 * input length is fixed and known. Length extension is not obviously
 * exploitable in Bitcoin's specific constructions — this is belt-and-braces.
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * HASH160 = RIPEMD-160(SHA-256(x)).
 *
 * The composition matters. SHA-256 runs first, so an attacker seeking a
 * collision in the 20-byte output must find inputs colliding *through*
 * SHA-256 as well; he cannot attack RIPEMD-160's weaker 80-bit collision
 * bound directly on chosen inputs. Applied to a 33-byte compressed public
 * key, this yields the 20-byte witness program of a P2WPKH output.
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/**
 * BIP-340 tagged hash: SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ msg).
 *
 * ─── Why domain separation exists ──────────────────────────────────────────
 * Suppose two different protocols both sign "SHA-256 of some 32 bytes". A
 * value that is a legitimate signable object in protocol A might also be a
 * legitimate signable object in protocol B, letting an attacker replay a
 * signature across contexts. Prefixing with a hashed, protocol-specific tag
 * makes the input spaces provably disjoint: no message under tag "X" can ever
 * collide with a message under tag "Y" without a SHA-256 collision.
 *
 * The tag hash is repeated twice so the prefix is exactly 64 bytes — one full
 * SHA-256 block — which lets implementations cache the midstate for speed.
 *
 * Included now because Taproot address support (BIP-86) and Schnorr signing
 * (BIP-340) are planned; it is unused by Phase 1 key/address code.
 */
export function taggedHash(tag: string, message: Uint8Array): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode(tag));
  const input = new Uint8Array(tagHash.length * 2 + message.length);
  input.set(tagHash, 0);
  input.set(tagHash, tagHash.length);
  input.set(message, tagHash.length * 2);
  return sha256(input);
}
