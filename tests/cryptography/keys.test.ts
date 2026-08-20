/**
 * KEY GENERATION AND DERIVATION TESTS
 *
 * Boundary values matter enormously here. The interesting cases are not
 * "does a normal key work" but "what happens at exactly n, at n-1, at 0".
 * Off-by-one at the curve order is a real class of bug.
 */
import { describe, it, expect } from "vitest";
import { PrivateKey, CURVE_ORDER } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { bytesToHex, hexToBytes, bigIntToBytesBE } from "../../core/crypto/bytes.js";

describe("PrivateKey — valid range enforcement [1, n-1]", () => {
  it("accepts 1, the smallest valid scalar", () => {
    expect(PrivateKey.fromBigInt(1n).toBigInt()).toBe(1n);
  });

  it("accepts n-1, the largest valid scalar", () => {
    expect(PrivateKey.fromBigInt(CURVE_ORDER - 1n).toBigInt()).toBe(CURVE_ORDER - 1n);
  });

  it("rejects 0 — 0*G is the point at infinity, not a public key", () => {
    expect(() => PrivateKey.fromBytes(new Uint8Array(32))).toThrow(/zero/);
    expect(() => PrivateKey.fromBigInt(0n)).toThrow();
  });

  it("rejects exactly n — n*G is also the point at infinity", () => {
    expect(() => PrivateKey.fromBytes(bigIntToBytesBE(CURVE_ORDER, 32))).toThrow(/curve order/);
  });

  it("rejects n+1 — would silently alias to the key 1", () => {
    expect(() => PrivateKey.fromBytes(bigIntToBytesBE(CURVE_ORDER + 1n, 32))).toThrow();
  });

  it("rejects the all-0xFF scalar (above n)", () => {
    expect(() => PrivateKey.fromBytes(new Uint8Array(32).fill(0xff))).toThrow();
  });

  it("rejects wrong lengths — no silent padding or truncation", () => {
    expect(() => PrivateKey.fromBytes(new Uint8Array(31).fill(1))).toThrow(/32 bytes/);
    expect(() => PrivateKey.fromBytes(new Uint8Array(33).fill(1))).toThrow(/32 bytes/);
    expect(() => PrivateKey.fromBytes(new Uint8Array(0))).toThrow();
  });

  it("rejects malformed hex rather than repairing it", () => {
    expect(() => PrivateKey.fromHex("0x01")).toThrow();          // no prefixes
    expect(() => PrivateKey.fromHex("01".repeat(31) + "0")).toThrow(); // odd length
    expect(() => PrivateKey.fromHex("zz".repeat(32))).toThrow();  // non-hex
    expect(() => PrivateKey.fromHex(" " + "01".repeat(32))).toThrow(); // whitespace
  });
});

describe("PrivateKey — generation", () => {
  it("always produces an in-range scalar", () => {
    for (let i = 0; i < 200; i++) {
      const k = PrivateKey.generate().toBigInt();
      expect(k).toBeGreaterThan(0n);
      expect(k).toBeLessThan(CURVE_ORDER);
    }
  });

  it("never repeats", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i++) seen.add(PrivateKey.generate().toHexUnsafe());
    expect(seen.size).toBe(500);
  });

  it("REJECTION SAMPLING: discards an out-of-range draw and redraws", () => {
    // Inject a source that returns n (invalid) first, then 42 (valid).
    // A `mod n` implementation would silently return 0 here and pass; a
    // correct rejection sampler must discard and try again.
    const draws = [bigIntToBytesBE(CURVE_ORDER, 32), bigIntToBytesBE(42n, 32)];
    let i = 0;
    const source = (out: Uint8Array) => { out.set(draws[i++]!); };
    expect(PrivateKey.generate(source).toBigInt()).toBe(42n);
    expect(i).toBe(2); // it really did draw twice
  });

  it("REJECTION SAMPLING: discards zero", () => {
    const draws = [new Uint8Array(32), bigIntToBytesBE(7n, 32)];
    let i = 0;
    const source = (out: Uint8Array) => { out.set(draws[i++]!); };
    expect(PrivateKey.generate(source).toBigInt()).toBe(7n);
  });

  it("fails loudly rather than looping forever on a permanently broken RNG", () => {
    const stuck = (out: Uint8Array) => out.fill(0xff); // always out of range
    expect(() => PrivateKey.generate(stuck)).toThrow(/may be defective/);
  });

  it("copies input bytes, so a caller mutating their buffer cannot alter the key", () => {
    const buf = bigIntToBytesBE(123456789n, 32);
    const key = PrivateKey.fromBytes(buf);
    buf.fill(0xaa);
    expect(key.toBigInt()).toBe(123456789n);
  });

  it("returns copies from toBytes(), so callers cannot mutate internal state", () => {
    const key = PrivateKey.fromBigInt(999n);
    key.toBytes().fill(0);
    expect(key.toBigInt()).toBe(999n);
  });
});

describe("PublicKey — derivation K = kG", () => {
  // Vector: private key 1 maps to the generator point G itself, whose
  // compressed encoding is a published secp256k1 constant.
  it("k=1 derives exactly the generator point G", () => {
    const pub = PublicKey.fromPrivateKey(PrivateKey.fromBigInt(1n));
    expect(pub.toHex()).toBe(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
  });

  it("k=2 derives 2G", () => {
    const pub = PublicKey.fromPrivateKey(PrivateKey.fromBigInt(2n));
    expect(pub.toHex()).toBe(
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    );
  });

  it("k = n-1 derives -G (same x as G, opposite y parity)", () => {
    const pub = PublicKey.fromPrivateKey(PrivateKey.fromBigInt(CURVE_ORDER - 1n));
    // (n-1)G = -G: identical x, and the parity prefix flips 02 -> 03.
    expect(pub.toHex()).toBe(
      "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
  });

  it("BIP-32 test-vector key derives its documented public key", () => {
    // From the BIP-32 master key for seed 000102...0f (m).
    const priv = PrivateKey.fromHex(
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    );
    expect(PublicKey.fromPrivateKey(priv).toHex()).toBe(
      "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
    );
  });

  it("is deterministic: the same key always gives the same public key", () => {
    const priv = PrivateKey.generate();
    expect(PublicKey.fromPrivateKey(priv).toHex()).toBe(
      PublicKey.fromPrivateKey(priv).toHex(),
    );
  });

  it("is injective in practice: distinct keys give distinct public keys", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      seen.add(PublicKey.fromPrivateKey(PrivateKey.generate()).toHex());
    }
    expect(seen.size).toBe(200);
  });

  it("always produces compressed (33-byte) keys — required by BIP-143", () => {
    for (let i = 0; i < 20; i++) {
      const bytes = PublicKey.fromPrivateKey(PrivateKey.generate()).toBytes();
      expect(bytes.length).toBe(33);
      expect([0x02, 0x03]).toContain(bytes[0]);
    }
  });
});

describe("PublicKey — parsing and validation", () => {
  const valid = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

  it("round-trips a compressed key", () => {
    expect(PublicKey.fromHex(valid).toHex()).toBe(valid);
  });

  it("normalises an uncompressed key to compressed form", () => {
    const uncompressed = bytesToHex(PublicKey.fromHex(valid).toUncompressedBytes());
    expect(uncompressed.length).toBe(130);
    expect(uncompressed.startsWith("04")).toBe(true);
    expect(PublicKey.fromHex(uncompressed).toHex()).toBe(valid);
  });

  it("rejects a point that is not on the curve", () => {
    // x = 5 gives y^2 = 5^3 + 7 = 132, and 132 is a quadratic NON-residue
    // mod p (verified by Euler's criterion), so no y exists and the point
    // cannot be decompressed.
    //
    // Worth noting how this test was written: the first attempt used x = 1,
    // on the assumption that a small x would obviously be off-curve. It is
    // not — y^2 = 8 does have a square root mod p, and the test failed. About
    // half of all x values lie on the curve, so "off-curve" must be computed,
    // never assumed. The mistake is preserved in this comment because it is
    // exactly the sort of assumption that produces a validator which passes
    // its tests while checking nothing.
    const offCurve = "02" + "00".repeat(31) + "05";
    expect(() => PublicKey.fromHex(offCurve)).toThrow(/not a valid secp256k1 curve point/);
  });

  it("accepts x = 1, which IS on the curve (y^2 = 8 is a residue mod p)", () => {
    // The counterpart to the test above: small does not mean invalid.
    expect(() => PublicKey.fromHex("02" + "00".repeat(31) + "01")).not.toThrow();
  });

  it("rejects an all-zero x coordinate", () => {
    expect(() => PublicKey.fromHex("02" + "00".repeat(32))).toThrow();
  });

  it("rejects invalid prefixes", () => {
    expect(() => PublicKey.fromHex("01" + valid.slice(2))).toThrow(/0x02 or 0x03/);
    expect(() => PublicKey.fromHex("05" + valid.slice(2))).toThrow();
  });

  it("rejects wrong lengths", () => {
    expect(() => PublicKey.fromHex(valid.slice(0, 64))).toThrow(/33 or 65/);
    expect(() => PublicKey.fromHex(valid + "00")).toThrow(/33 or 65/);
    expect(() => PublicKey.fromHex("")).toThrow();
  });

  it("does not echo attacker-supplied bytes back in the error message", () => {
    const marker = "deadbeef".repeat(8);
    try {
      PublicKey.fromHex("02" + marker);
      expect.unreachable("should have thrown");
    } catch (e) {
      expect((e as Error).message).not.toContain("deadbeef");
    }
  });
});

describe("PublicKey — hash160 (the P2WPKH witness program)", () => {
  it("produces 20 bytes", () => {
    expect(PublicKey.fromHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
      .hash160().length).toBe(20);
  });

  it("matches the known hash160 for a standard test public key", () => {
    const pub = PublicKey.fromHex(
      "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
    );
    expect(bytesToHex(pub.hash160())).toBe("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");
  });

  it("compressed and uncompressed forms of the SAME key hash differently", async () => {
    // This is the classic 'my funds disappeared' bug. Assert the difference
    // explicitly so nobody assumes the encodings are interchangeable.
    const pub = PublicKey.fromHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const { hash160 } = await import("../../core/crypto/hashes.js");
    expect(bytesToHex(pub.hash160()))
      .not.toBe(bytesToHex(hash160(pub.toUncompressedBytes())));
  });
});
