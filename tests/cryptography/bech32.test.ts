/**
 * BECH32 / BECH32M TESTS — BIP-173 and BIP-350
 *
 * The INVALID vectors matter more than the valid ones. Any implementation
 * can encode correctly; the security property is rejecting malformed input.
 * Funds sent to a malformed address are gone permanently, so a parser that
 * is merely permissive is a fund-loss bug.
 */
import { describe, it, expect } from "vitest";
import {
  bech32Encode, bech32Decode, convertBits,
  encodeSegwitAddress, decodeSegwitAddress,
  BECH32_CONST, BECH32M_CONST,
} from "../../core/addresses/bech32.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

describe("checksum constants", () => {
  it("bech32 uses 1 and bech32m uses 0x2bc830a3 — the only difference", () => {
    expect(BECH32_CONST).toBe(1);
    expect(BECH32M_CONST).toBe(0x2bc830a3);
  });
});

describe("BIP-173 valid bech32 strings", () => {
  it.each([
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "?1ezyfcl",
  ])("decodes %s", (input) => {
    expect(bech32Decode(input).variant).toBe("bech32");
  });

  it("finds the separator as the LAST '1', so an HRP may contain '1'", () => {
    // The data alphabet excludes '1', so the final '1' is unambiguous.
    const decoded = bech32Decode(
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    );
    expect(decoded.hrp).toContain("1");
  });
});

describe("BIP-173 / BIP-350 invalid strings are rejected", () => {
  it.each([
    ["mixed case", "A12UeL5L"],
    ["empty HRP", "1qzzfhee"],
    ["invalid data character 'b'", "abc1rzg"],
    ["too short a checksum", "a12uel5"],
    ["no separator", "qzzfhee"],
    ["invalid checksum", "A12UEL5X"],
  ])("rejects %s", (_label, input) => {
    expect(() => bech32Decode(input)).toThrow();
  });

  it("rejects strings over 90 characters — the BCH guarantee only holds below it", () => {
    expect(() => bech32Decode("a1" + "q".repeat(95))).toThrow(/90 characters/);
  });

  it("rejects non-printable and out-of-range ASCII", () => {
    expect(() => bech32Decode("a\x201qqqqq")).toThrow();
    expect(() => bech32Decode("a\x7f1qqqqq")).toThrow();
  });

  it("MIXED CASE is rejected rather than normalised", () => {
    // Quietly lowercasing would mask corruption the checksum exists to catch.
    expect(() => bech32Decode("A12UeL5L")).toThrow(/mixed case/);
  });
});

describe("BIP-173 valid SegWit v0 addresses", () => {
  it.each([
    ["bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["tb", "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
     "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"],
  ])("encodes and decodes a %s address", (hrp, address, expectedScript) => {
    const { version, program } = decodeSegwitAddress(hrp, address);
    expect(version).toBe(0);
    // Reconstruct the scriptPubKey: OP_0 (0x00) + push length + program.
    const script = bytesToHex(new Uint8Array([0x00, program.length, ...program]));
    expect(script).toBe(expectedScript);
    // Round-trip back to the canonical lowercase form.
    expect(encodeSegwitAddress(hrp, version, program)).toBe(address.toLowerCase());
  });
});

describe("BIP-350 — bech32m for witness v1+", () => {
  it("decodes a valid Taproot (v1) address using bech32m", () => {
    const address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const { version, program } = decodeSegwitAddress("bc", address);
    expect(version).toBe(1);
    expect(program.length).toBe(32);
  });

  it("REJECTS a v0 address encoded with bech32m", () => {
    // BIP-350 invalid vector: correct data, wrong checksum variant.
    expect(() => decodeSegwitAddress("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh")).toThrow();
  });

  it("REJECTS a v1 address encoded with bech32", () => {
    expect(() => decodeSegwitAddress("bc", "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4")).toThrow();
  });

  it("picks the variant by witness version, never by caller preference", () => {
    const program20 = new Uint8Array(20).fill(0xab);
    const program32 = new Uint8Array(32).fill(0xab);
    // v0 -> bech32
    expect(bech32Decode(encodeSegwitAddress("bc", 0, program20)).variant).toBe("bech32");
    // v1 -> bech32m
    expect(bech32Decode(encodeSegwitAddress("bc", 1, program32)).variant).toBe("bech32m");
  });
});

describe("SegWit consensus rules", () => {
  it("rejects witness versions above 16", () => {
    expect(() => encodeSegwitAddress("bc", 17, new Uint8Array(20))).toThrow(/between 0 and 16/);
  });

  it("rejects v0 programs that are not 20 or 32 bytes", () => {
    expect(() => encodeSegwitAddress("bc", 0, new Uint8Array(21))).toThrow(/20 or 32/);
    expect(() => encodeSegwitAddress("bc", 0, new Uint8Array(19))).toThrow(/20 or 32/);
  });

  it("rejects programs outside the 2-40 byte range for any version", () => {
    expect(() => encodeSegwitAddress("bc", 1, new Uint8Array(1))).toThrow();
    expect(() => encodeSegwitAddress("bc", 1, new Uint8Array(41))).toThrow();
  });

  it("rejects an address whose HRP does not match the expected network", () => {
    expect(() => decodeSegwitAddress("tb", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"))
      .toThrow(/expected human-readable part/);
  });
});

describe("convertBits — the padding rules", () => {
  it("round-trips bytes through 5-bit groups", () => {
    const original = [...hexToBytes("751e76e8199196d454941c45d1b3a323f1433bd6")];
    const to5 = convertBits(original, 8, 5, true);
    const back = convertBits(to5, 5, 8, false);
    expect(back).toEqual(original);
  });

  it("rejects NON-ZERO padding when converting 5->8", () => {
    // Non-zero padding means two different 5-bit sequences decode to the same
    // bytes — malleability. BIP-173 requires rejection.
    expect(() => convertBits([1, 1, 1, 1, 1, 1, 1, 1, 1], 5, 8, false)).toThrow(/padding/);
  });

  it("rejects EXCESS padding when converting 5->8", () => {
    expect(() => convertBits(new Array(9).fill(0), 5, 8, false)).toThrow(/excess padding/);
  });

  it("rejects values out of range for the source base", () => {
    expect(() => convertBits([32], 5, 8, true)).toThrow(/out of range/);
    expect(() => convertBits([256], 8, 5, true)).toThrow(/out of range/);
    expect(() => convertBits([-1], 5, 8, true)).toThrow();
  });
});

describe("checksum error-detection guarantee", () => {
  const address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

  it("detects every single-character substitution", () => {
    const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let tested = 0;
    // Walk the data part only (after the separator).
    for (let i = 3; i < address.length; i++) {
      for (const replacement of CHARSET) {
        if (address[i] === replacement) continue;
        const corrupted = address.slice(0, i) + replacement + address.slice(i + 1);
        expect(() => bech32Decode(corrupted)).toThrow();
        tested++;
      }
    }
    // Confirm the loop actually ran, so this cannot pass vacuously.
    expect(tested).toBeGreaterThan(1000);
  });

  it("detects transposition of adjacent characters", () => {
    let detected = 0;
    let attempted = 0;
    for (let i = 3; i < address.length - 1; i++) {
      if (address[i] === address[i + 1]) continue;
      const swapped =
        address.slice(0, i) + address[i + 1] + address[i] + address.slice(i + 2);
      attempted++;
      try { bech32Decode(swapped); } catch { detected++; }
    }
    expect(attempted).toBeGreaterThan(20);
    expect(detected).toBe(attempted);
  });
});

describe("low-level encode/decode", () => {
  it("round-trips arbitrary 5-bit data", () => {
    const data = [0, 1, 2, 3, 30, 31];
    const encoded = bech32Encode("veyra", data, "bech32");
    const decoded = bech32Decode(encoded);
    expect(decoded.hrp).toBe("veyra");
    expect(decoded.data).toEqual(data);
  });

  it("rejects an empty HRP on encode", () => {
    expect(() => bech32Encode("", [0], "bech32")).toThrow();
  });

  it("rejects data values outside 0-31", () => {
    expect(() => bech32Encode("bc", [32], "bech32")).toThrow(/5-bit range/);
  });

  it("the HRP is part of the checksum — same data, different HRP, different checksum", () => {
    const data = [0, 1, 2, 3];
    const a = bech32Encode("bc", data, "bech32").split("1").pop();
    const b = bech32Encode("tb", data, "bech32").split("1").pop();
    expect(a).not.toBe(b);
  });
});
