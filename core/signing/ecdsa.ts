/**
 * ECDSA — DIGITAL SIGNATURES
 *
 * ─── Signatures are not encryption ─────────────────────────────────────────
 * The confusion is worth killing explicitly, because "Bitcoin encrypts your
 * transaction with your private key" is a sentence people actually say.
 *
 *   ENCRYPTION   is for confidentiality. E(key, message) → ciphertext, and
 *                D(key, ciphertext) → message. It hides content. It is
 *                reversible by design.
 *
 *   SIGNATURE    is for authentication and integrity. Sign(privKey, message)
 *                → signature, and Verify(pubKey, message, signature) → bool.
 *                It hides nothing. It proves that whoever produced the
 *                signature knew the private key, and that the message has not
 *                changed since. There is no "decrypting" a signature.
 *
 * Bitcoin transactions are entirely public. Nothing about them is encrypted,
 * ever. Signatures answer "is this authorised?", never "what does it say?".
 *
 * ─── How ECDSA works ───────────────────────────────────────────────────────
 * To sign message hash z with private key k:
 *
 *   1. Pick a nonce n ∈ [1, order−1]
 *   2. R = n·G;  r = R.x mod order
 *   3. s = n⁻¹(z + r·k) mod order
 *   4. signature = (r, s)
 *
 * To verify with public key K = k·G:
 *
 *   u₁ = z·s⁻¹,  u₂ = r·s⁻¹,  R' = u₁·G + u₂·K,  accept iff R'.x ≡ r
 *
 * The algebra works because substituting s reduces R' back to n·G. Verifying
 * requires only K, so anyone can check the signature; producing it requires
 * k, which only the owner has.
 *
 * ─── THE NONCE IS THE WHOLE BALLGAME ───────────────────────────────────────
 * Everything that has ever gone catastrophically wrong with ECDSA in practice
 * went wrong at step 1.
 *
 * REUSED NONCE → INSTANT KEY RECOVERY. Sign two different messages z₁, z₂
 * with the same nonce n and an observer with only the two public signatures
 * computes:
 *
 *     n = (z₁ − z₂) / (s₁ − s₂)      then      k = (s₁·n − z₁) / r
 *
 * That is it. Two signatures, some modular arithmetic, private key
 * recovered. No brute force, no weakness in the curve. This exact bug:
 *   - broke the Sony PlayStation 3 signing key in 2010 (a fixed nonce),
 *   - drained Android Bitcoin wallets in 2013 (a broken SecureRandom),
 *   - and continues to empty addresses whose wallets had faulty RNGs.
 *
 * BIASED NONCE → LATTICE ATTACK. Even a *slightly* non-uniform nonce — say,
 * one produced by reducing a random 256-bit value mod n instead of rejection
 * sampling — leaks a few bits per signature. A few dozen signatures and
 * lattice reduction (LLL/BKZ) recovers the key. This is why the bias
 * discussion in core/keys/privateKey.ts matters far more here than it does
 * for key generation.
 *
 * ─── RFC 6979: removing the RNG from the equation ──────────────────────────
 * Veyra never generates a random nonce. @noble/curves implements RFC 6979
 * deterministic nonces:
 *
 *     nonce = HMAC-SHA256 derived from (private key, message hash)
 *
 * Properties this buys:
 *   - Same key + same message → same nonce, always. But different messages
 *     give unrelated nonces, so reuse across distinct signatures is
 *     impossible by construction.
 *   - No dependence on the RNG at signing time at all. A machine with a
 *     broken CSPRNG can still sign safely.
 *   - Signatures are reproducible, which makes them testable against fixed
 *     vectors — a property a randomised signer cannot offer.
 *
 * This is strictly better than random nonces for a wallet, and it is why the
 * tests below can assert exact signature bytes.
 *
 * ─── Low-S: malleability, again ────────────────────────────────────────────
 * If (r, s) is a valid signature, so is (r, order − s) — the curve is
 * symmetric about the x-axis, and both satisfy the verification equation.
 * A third party can flip S on a broadcast transaction, changing its
 * signature bytes without invalidating it.
 *
 * Pre-SegWit this changed the txid (malleability). Post-SegWit it only
 * changes the wtxid, so it is far less damaging — but BIP-62/BIP-146 made
 * low-S a relay policy rule regardless: a high-S signature will simply not
 * propagate. @noble/curves enforces low-S by default; the tests below assert
 * it explicitly rather than trusting the default to stay put.
 *
 * ─── DER encoding ──────────────────────────────────────────────────────────
 * Bitcoin serialises signatures as DER, then appends one byte for the sighash
 * type. Strict DER (BIP-66) is a consensus rule since 2015: no extra padding,
 * no negative-looking integers, exact lengths. Lenient parsing of the sort
 * OpenSSL once permitted was itself a malleability source.
 *
 * ─── Library boundary ──────────────────────────────────────────────────────
 * @noble/curves is responsible for: constant-time scalar arithmetic, RFC 6979
 * nonce derivation, low-S normalisation, and strict DER.
 * Veyra is responsible for: never signing a digest it did not construct
 * itself, appending the correct sighash byte, and verifying before broadcast.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { PrivateKey } from "../keys/privateKey.js";
import { PublicKey } from "../keys/publicKey.js";
import { concatBytes, bytesToHex } from "../crypto/bytes.js";
import { SIGHASH_ALL } from "./sighash.js";
import { VeyraError } from "../errors/index.js";

export class SignatureError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Signature: ${reason}`);
    this.name = "SignatureError";
  }
}

/** Half the curve order. A signature is "low-S" when s <= this. */
export const HALF_CURVE_ORDER = secp256k1.CURVE.n / 2n;

/**
 * Sign a 32-byte digest.
 *
 * Takes a DIGEST, not a message. The function will not hash for you, and that
 * is deliberate: Bitcoin's sighash construction is intricate (see
 * ./sighash.ts) and a signing function that quietly hashes its input invites
 * signing the wrong thing. The caller must have constructed the digest
 * through the sighash path.
 */
export function signDigest(digest: Uint8Array, privateKey: PrivateKey): Uint8Array {
  if (digest.length !== 32) {
    throw new SignatureError(`digest must be 32 bytes, received ${digest.length}`);
  }
  const secret = privateKey.toBytes();
  try {
    // prehash: false — the input IS the digest and must not be hashed again.
    // lowS defaults to true; asserted by the tests.
    const signature = secp256k1.sign(digest, secret, { prehash: false });
    return signature.toBytes("der");
  } finally {
    secret.fill(0);
  }
}

/**
 * Sign and append the sighash type byte — the form that goes in a witness.
 *
 * The trailing byte is not part of the DER structure. It tells verifiers
 * which sighash algorithm was used, and it is itself committed to inside the
 * preimage (field 10), so it cannot be altered independently.
 */
export function signDigestWithSighashType(
  digest: Uint8Array,
  privateKey: PrivateKey,
  sighashType: number = SIGHASH_ALL,
): Uint8Array {
  if (sighashType !== SIGHASH_ALL) {
    throw new SignatureError("only SIGHASH_ALL is supported");
  }
  return concatBytes(signDigest(digest, privateKey), new Uint8Array([sighashType]));
}

/**
 * Verify a DER signature against a digest and public key.
 *
 * Returns a boolean rather than throwing. Verification failure is an expected
 * outcome — it is the entire point of verifying — not an exceptional one.
 * A function that throws on invalid signatures tempts callers into a
 * try/catch that swallows the result.
 */
export function verifyDigest(
  digest: Uint8Array,
  signatureDer: Uint8Array,
  publicKey: PublicKey,
): boolean {
  if (digest.length !== 32) return false;
  try {
    return secp256k1.verify(signatureDer, digest, publicKey.toBytes(), {
      prehash: false,
      format: "der",
    });
  } catch {
    // Malformed DER, out-of-range values, etc. All mean "not valid".
    return false;
  }
}

/** Verify a signature carrying a trailing sighash-type byte. */
export function verifyWitnessSignature(
  digest: Uint8Array,
  signatureWithType: Uint8Array,
  publicKey: PublicKey,
): boolean {
  if (signatureWithType.length < 2) return false;
  const sighashType = signatureWithType[signatureWithType.length - 1]!;
  if (sighashType !== SIGHASH_ALL) return false;
  return verifyDigest(digest, signatureWithType.slice(0, -1), publicKey);
}

/** Parsed signature components. */
export interface SignatureComponents {
  readonly r: bigint;
  readonly s: bigint;
  readonly isLowS: boolean;
}

/** Decompose a DER signature, for inspection and testing. */
export function parseSignature(signatureDer: Uint8Array): SignatureComponents {
  try {
    const sig = secp256k1.Signature.fromBytes(signatureDer, "der");
    return { r: sig.r, s: sig.s, isLowS: sig.s <= HALF_CURVE_ORDER };
  } catch {
    throw new SignatureError("malformed DER signature");
  }
}

/**
 * Is this signature low-S, as relay policy requires?
 *
 * Checked explicitly before broadcast rather than assumed. A high-S signature
 * verifies fine but will not propagate across the network, producing a
 * transaction that appears signed and simply never confirms — one of the more
 * confusing failure modes to debug after the fact.
 */
export function isLowS(signatureDer: Uint8Array): boolean {
  try {
    return parseSignature(signatureDer).isLowS;
  } catch {
    return false;
  }
}

/** Hex form, for logs and tests. Signatures are public data. */
export function signatureToHex(signature: Uint8Array): string {
  return bytesToHex(signature);
}
