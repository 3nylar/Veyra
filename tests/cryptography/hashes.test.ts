/**
 * Hash primitive tests.
 *
 * Vectors are from NIST FIPS 180-4 (SHA-256), the RIPEMD-160 reference
 * publication, and Bitcoin's own well-known values.
 */
import { describe, it, expect } from "vitest";
import { sha256, ripemd160, hash256, hash160, taggedHash } from "../../core/crypto/hashes.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("SHA-256 — FIPS 180-4 vectors", () => {
  it("hashes the empty string", () => {
    expect(bytesToHex(sha256(new Uint8Array(0)))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("hashes 'abc' (FIPS one-block vector)", () => {
    expect(bytesToHex(sha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("hashes the FIPS two-block vector", () => {
    const msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    expect(bytesToHex(sha256(utf8(msg)))).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("exhibits the avalanche property: a 1-bit input change flips ~half the output bits", () => {
    const a = sha256(utf8("veyra"));
    const b = sha256(utf8("veyrb")); // differs by 2 bits in one byte
    let differing = 0;
    for (let i = 0; i < 32; i++) {
      let x = a[i]! ^ b[i]!;
      while (x) { differing += x & 1; x >>= 1; }
    }
    // 256 bits; expect ~128. A wide band still rules out weak diffusion.
    expect(differing).toBeGreaterThan(96);
    expect(differing).toBeLessThan(160);
  });
});

describe("RIPEMD-160 — reference vectors", () => {
  it("hashes the empty string", () => {
    expect(bytesToHex(ripemd160(new Uint8Array(0)))).toBe(
      "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    );
  });

  it("hashes 'abc'", () => {
    expect(bytesToHex(ripemd160(utf8("abc")))).toBe(
      "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    );
  });
});

describe("Bitcoin hash compositions", () => {
  it("hash256 is SHA-256 applied twice", () => {
    expect(bytesToHex(hash256(utf8("hello")))).toBe(
      bytesToHex(sha256(sha256(utf8("hello")))),
    );
  });

  it("hash160 is RIPEMD-160 of SHA-256, and produces 20 bytes", () => {
    const out = hash160(utf8("hello"));
    expect(out.length).toBe(20);
    expect(bytesToHex(out)).toBe(bytesToHex(ripemd160(sha256(utf8("hello")))));
  });

  it("hash160 of the Satoshi genesis-era public key gives the known payload", () => {
    // Compressed pubkey of the well-known BIP-32 style test key; the
    // corresponding hash160 is fixed by the composition, not by us.
    const pk = hexToBytes("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352");
    expect(bytesToHex(hash160(pk))).toBe("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");
  });

  it("hash160 and hash256 are different compositions (a swap is a consensus bug)", () => {
    expect(bytesToHex(hash160(utf8("x")))).not.toBe(bytesToHex(hash256(utf8("x"))).slice(0, 40));
  });
});

describe("BIP-340 tagged hash — domain separation", () => {
  it("matches the BIP-340 construction SHA256(SHA256(tag)||SHA256(tag)||msg)", () => {
    const tag = "BIP0340/challenge";
    const msg = utf8("message");
    const th = sha256(utf8(tag));
    const manual = new Uint8Array(th.length * 2 + msg.length);
    manual.set(th, 0); manual.set(th, 32); manual.set(msg, 64);
    expect(bytesToHex(taggedHash(tag, msg))).toBe(bytesToHex(sha256(manual)));
  });

  it("separates domains: the same message under different tags never collides", () => {
    const msg = utf8("same message");
    expect(bytesToHex(taggedHash("TagA", msg))).not.toBe(bytesToHex(taggedHash("TagB", msg)));
  });
});
