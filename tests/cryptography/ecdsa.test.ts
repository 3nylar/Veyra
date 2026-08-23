/**
 * ECDSA TESTS
 *
 * Spec §11 requires exactly four properties, tested first:
 *   1. valid message + valid signature      -> succeeds
 *   2. modified message + original signature -> fails
 *   3. invalid signature                     -> fails
 *   4. wrong public key                      -> fails
 */
import { describe, it, expect } from "vitest";
import {
  signDigest, verifyDigest, signDigestWithSighashType, verifyWitnessSignature,
  parseSignature, isLowS, HALF_CURVE_ORDER,
} from "../../core/signing/ecdsa.js";
import { PrivateKey, CURVE_ORDER } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { sha256 } from "../../core/crypto/hashes.js";
import { bytesToHex } from "../../core/crypto/bytes.js";
import { SIGHASH_ALL } from "../../core/signing/sighash.js";

const digestOf = (s: string) => sha256(new TextEncoder().encode(s));

describe("§11: the four required signature properties", () => {
  const priv = PrivateKey.fromHex("0".repeat(63) + "1");
  const pub = PublicKey.fromPrivateKey(priv);
  const digest = digestOf("pay alice 0.1 BTC");
  const signature = signDigest(digest, priv);

  it("1. valid message + valid signature -> SUCCEEDS", () => {
    expect(verifyDigest(digest, signature, pub)).toBe(true);
  });

  it("2. modified message + original signature -> FAILS", () => {
    expect(verifyDigest(digestOf("pay alice 1.0 BTC"), signature, pub)).toBe(false);
  });

  it("3. invalid signature -> FAILS", () => {
    const corrupted = Uint8Array.from(signature);
    corrupted[10] = corrupted[10]! ^ 0xff;
    expect(verifyDigest(digest, corrupted, pub)).toBe(false);
    expect(verifyDigest(digest, new Uint8Array(70), pub)).toBe(false);
    expect(verifyDigest(digest, new Uint8Array(0), pub)).toBe(false);
  });

  it("4. wrong public key -> FAILS", () => {
    const wrongPub = PublicKey.fromPrivateKey(PrivateKey.fromBigInt(2n));
    expect(verifyDigest(digest, signature, wrongPub)).toBe(false);
  });

  it("EVERY single-bit flip in the digest breaks verification", () => {
    let tested = 0;
    for (let byte = 0; byte < 32; byte++) {
      for (let bit = 0; bit < 8; bit++) {
        const mutated = Uint8Array.from(digest);
        mutated[byte] = mutated[byte]! ^ (1 << bit);
        expect(verifyDigest(mutated, signature, pub)).toBe(false);
        tested++;
      }
    }
    expect(tested).toBe(256); // guards against a vacuous loop
  });
});

describe("RFC 6979 deterministic nonces", () => {
  const priv = PrivateKey.fromHex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");

  it("the same key and digest always produce the SAME signature", () => {
    // Only possible with deterministic nonces. A randomised signer could not
    // pass this, and could not be tested against fixed vectors at all.
    const digest = digestOf("deterministic");
    const a = bytesToHex(signDigest(digest, priv));
    for (let i = 0; i < 20; i++) {
      expect(bytesToHex(signDigest(digest, priv))).toBe(a);
    }
  });

  it("different digests produce different nonces, so r differs", () => {
    // If r ever repeated across distinct messages, the key would be
    // recoverable by the arithmetic described in ecdsa.ts.
    const rs = new Set<string>();
    for (let i = 0; i < 100; i++) {
      rs.add(parseSignature(signDigest(digestOf(`message ${i}`), priv)).r.toString(16));
    }
    expect(rs.size).toBe(100);
  });

  it("different keys on the same digest produce different signatures", () => {
    const digest = digestOf("same message");
    const a = bytesToHex(signDigest(digest, PrivateKey.fromBigInt(11n)));
    const b = bytesToHex(signDigest(digest, PrivateKey.fromBigInt(12n)));
    expect(a).not.toBe(b);
  });

  it("signing does not consume randomness — a broken RNG cannot break signing", () => {
    // RFC 6979 derives the nonce from (key, digest) via HMAC. Asserted by
    // the determinism above; restated here as the security property it is.
    const digest = digestOf("no rng needed");
    expect(bytesToHex(signDigest(digest, priv))).toBe(bytesToHex(signDigest(digest, priv)));
  });
});

describe("low-S normalisation (BIP-62 / BIP-146 relay policy)", () => {
  it("every generated signature is low-S", () => {
    for (let i = 0; i < 100; i++) {
      const sig = signDigest(digestOf(`msg ${i}`), PrivateKey.generate());
      const { s } = parseSignature(sig);
      expect(s <= HALF_CURVE_ORDER).toBe(true);
      expect(isLowS(sig)).toBe(true);
    }
  });

  it("HALF_CURVE_ORDER is exactly half the group order", () => {
    expect(HALF_CURVE_ORDER * 2n).toBe(CURVE_ORDER - (CURVE_ORDER % 2n));
  });

  it("r and s are both in the valid range [1, n-1]", () => {
    for (let i = 0; i < 30; i++) {
      const { r, s } = parseSignature(signDigest(digestOf(`m${i}`), PrivateKey.generate()));
      expect(r > 0n && r < CURVE_ORDER).toBe(true);
      expect(s > 0n && s < CURVE_ORDER).toBe(true);
    }
  });
});

describe("DER encoding", () => {
  const priv = PrivateKey.generate();
  const sig = signDigest(digestOf("der test"), priv);

  it("begins with the SEQUENCE tag 0x30", () => {
    expect(sig[0]).toBe(0x30);
  });

  it("has a plausible DER length (70-72 bytes typical)", () => {
    expect(sig.length).toBeGreaterThanOrEqual(68);
    expect(sig.length).toBeLessThanOrEqual(72);
  });

  it("rejects malformed DER on parse", () => {
    expect(() => parseSignature(new Uint8Array([0x30, 0x00]))).toThrow(/malformed DER/);
    expect(() => parseSignature(new Uint8Array(0))).toThrow();
    expect(() => parseSignature(new Uint8Array(71).fill(0xff))).toThrow();
  });

  it("isLowS returns false rather than throwing on garbage", () => {
    expect(isLowS(new Uint8Array([1, 2, 3]))).toBe(false);
  });
});

describe("witness signatures (with the trailing sighash byte)", () => {
  const priv = PrivateKey.generate();
  const pub = PublicKey.fromPrivateKey(priv);
  const digest = digestOf("witness");

  it("appends exactly one sighash-type byte", () => {
    const bare = signDigest(digest, priv);
    const witness = signDigestWithSighashType(digest, priv, SIGHASH_ALL);
    expect(witness.length).toBe(bare.length + 1);
    expect(witness[witness.length - 1]).toBe(SIGHASH_ALL);
  });

  it("verifies with the type byte present", () => {
    expect(verifyWitnessSignature(digest, signDigestWithSighashType(digest, priv), pub)).toBe(true);
  });

  it("rejects a signature carrying a non-ALL sighash type", () => {
    const sig = signDigestWithSighashType(digest, priv);
    const tampered = Uint8Array.from(sig);
    tampered[tampered.length - 1] = 0x02; // SIGHASH_NONE
    expect(verifyWitnessSignature(digest, tampered, pub)).toBe(false);
  });

  it("refuses to CREATE a non-ALL signature", () => {
    expect(() => signDigestWithSighashType(digest, priv, 0x02)).toThrow(/only SIGHASH_ALL/);
  });

  it("rejects truncated input without throwing", () => {
    expect(verifyWitnessSignature(digest, new Uint8Array(1), pub)).toBe(false);
    expect(verifyWitnessSignature(digest, new Uint8Array(0), pub)).toBe(false);
  });
});

describe("input validation", () => {
  const priv = PrivateKey.generate();
  const pub = PublicKey.fromPrivateKey(priv);

  it("refuses to sign anything that is not a 32-byte digest", () => {
    // The signer must never hash for the caller: Bitcoin's sighash is
    // intricate, and a signer that quietly hashes invites signing the wrong
    // thing entirely.
    expect(() => signDigest(new Uint8Array(31), priv)).toThrow(/32 bytes/);
    expect(() => signDigest(new Uint8Array(33), priv)).toThrow(/32 bytes/);
    expect(() => signDigest(new Uint8Array(0), priv)).toThrow();
  });

  it("verification returns false (never throws) on a wrong-length digest", () => {
    const sig = signDigest(digestOf("x"), priv);
    expect(verifyDigest(new Uint8Array(31), sig, pub)).toBe(false);
  });

  it("signatures do not leak the private key", () => {
    const marker = PrivateKey.fromHex("c0ffee".padEnd(64, "a"));
    const sig = bytesToHex(signDigest(digestOf("leak?"), marker));
    expect(sig).not.toContain(marker.toHexUnsafe());
  });
});

describe("edge-case keys", () => {
  it.each([
    ["k = 1", 1n],
    ["k = 2", 2n],
    ["k = n-1", CURVE_ORDER - 1n],
    ["k = n-2", CURVE_ORDER - 2n],
  ])("signs and verifies correctly for %s", (_label, scalar) => {
    const priv = PrivateKey.fromBigInt(scalar);
    const pub = PublicKey.fromPrivateKey(priv);
    const digest = digestOf("boundary");
    expect(verifyDigest(digest, signDigest(digest, priv), pub)).toBe(true);
  });

  it("handles an all-zero digest", () => {
    const priv = PrivateKey.generate();
    const pub = PublicKey.fromPrivateKey(priv);
    const zero = new Uint8Array(32);
    expect(verifyDigest(zero, signDigest(zero, priv), pub)).toBe(true);
  });

  it("handles an all-0xFF digest (above the curve order)", () => {
    const priv = PrivateKey.generate();
    const pub = PublicKey.fromPrivateKey(priv);
    const max = new Uint8Array(32).fill(0xff);
    expect(verifyDigest(max, signDigest(max, priv), pub)).toBe(true);
  });
});
