/**
 * REFERENCE IMPLEMENTATION TESTS
 *
 * Two jobs:
 *
 *   1. Prove the educational implementations are CORRECT — that the readable
 *      code in core/crypto/reference/ genuinely computes what the audited
 *      library computes. If they diverge, the teaching material is lying.
 *
 *   2. Prove the educational implementations are ISOLATED — that no
 *      production module imports them. Spec §4: "The educational
 *      implementation must never accidentally become the production security
 *      boundary." That is enforced here by scanning the source tree, because
 *      it cannot be enforced by behaviour.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { referenceSha256 } from "../../core/crypto/reference/sha256.js";
import * as ref from "../../core/crypto/reference/secp256k1.js";
import { sha256 } from "../../core/crypto/hashes.js";
import { bytesToHex } from "../../core/crypto/bytes.js";
import { PrivateKey } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("reference SHA-256 — correctness", () => {
  it("matches the FIPS 180-4 empty-string vector", () => {
    expect(bytesToHex(referenceSha256(new Uint8Array(0)))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("matches the FIPS 180-4 'abc' vector", () => {
    expect(bytesToHex(referenceSha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("agrees with @noble/hashes across message lengths, including block boundaries", () => {
    // 55/56 and 63/64 are where the padding logic decides whether an extra
    // block is required. Those are exactly where naive implementations break.
    for (const len of [0, 1, 3, 54, 55, 56, 57, 63, 64, 65, 119, 127, 128, 129, 1000]) {
      const msg = new Uint8Array(len);
      for (let i = 0; i < len; i++) msg[i] = (i * 37 + 11) & 0xff;
      expect(bytesToHex(referenceSha256(msg))).toBe(bytesToHex(sha256(msg)));
    }
  });

  it("agrees with @noble/hashes on random inputs (differential fuzz)", () => {
    for (let i = 0; i < 300; i++) {
      const len = Math.floor(Math.random() * 500);
      const msg = new Uint8Array(len);
      crypto.getRandomValues(msg);
      expect(bytesToHex(referenceSha256(msg))).toBe(bytesToHex(sha256(msg)));
    }
  });
});

describe("reference secp256k1 — curve parameters", () => {
  it("G is on the curve", () => {
    expect(ref.isOnCurve(ref.G)).toBe(true);
  });

  it("the point at infinity is treated as on-curve (it is the identity)", () => {
    expect(ref.isOnCurve(null)).toBe(true);
  });

  it("has cofactor 1: n*G = O, so G generates the whole group", () => {
    expect(ref.multiply(ref.N, ref.G)).toBeNull();
  });

  it("p and n are the published secp256k1 constants", () => {
    expect(ref.P.toString(16)).toBe(
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    );
    expect(ref.N.toString(16)).toBe(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
  });

  it("n < p, and the curve equation uses a=0, b=7", () => {
    expect(ref.N).toBeLessThan(ref.P);
    expect(ref.A).toBe(0n);
    expect(ref.B).toBe(7n);
  });
});

describe("reference secp256k1 — group law", () => {
  it("O is the additive identity: P + O = P", () => {
    expect(ref.add(ref.G, null)).toEqual(ref.G);
    expect(ref.add(null, ref.G)).toEqual(ref.G);
  });

  it("P + (-P) = O", () => {
    expect(ref.add(ref.G, ref.negate(ref.G))).toBeNull();
  });

  it("addition is commutative: P + Q = Q + P", () => {
    const P2 = ref.multiply(2n, ref.G);
    const P3 = ref.multiply(3n, ref.G);
    expect(ref.add(P2, P3)).toEqual(ref.add(P3, P2));
  });

  it("addition is associative: (P+Q)+R = P+(Q+R)", () => {
    const a = ref.multiply(5n, ref.G);
    const b = ref.multiply(9n, ref.G);
    const c = ref.multiply(23n, ref.G);
    expect(ref.add(ref.add(a, b), c)).toEqual(ref.add(a, ref.add(b, c)));
  });

  it("doubling agrees with self-addition: 2P = P + P", () => {
    expect(ref.double(ref.G)).toEqual(ref.add(ref.G, ref.G));
  });

  it("scalar multiplication is homomorphic: (a+b)G = aG + bG", () => {
    const a = 0x1234567890abcdefn;
    const b = 0xfedcba0987654321n;
    expect(ref.multiply(a + b, ref.G)).toEqual(
      ref.add(ref.multiply(a, ref.G), ref.multiply(b, ref.G)),
    );
  });

  it("all derived points stay on the curve", () => {
    for (const k of [1n, 2n, 3n, 7n, 12345n, ref.N - 1n]) {
      expect(ref.isOnCurve(ref.multiply(k, ref.G))).toBe(true);
    }
  });

  it("scalars wrap modulo n: (n+5)G = 5G — which is why keys >= n are rejected", () => {
    expect(ref.multiply(ref.N + 5n, ref.G)).toEqual(ref.multiply(5n, ref.G));
  });
});

describe("reference secp256k1 — agreement with @noble/curves", () => {
  it("derives the same public key for fixed scalars", () => {
    for (const k of [1n, 2n, 3n, 255n, 65537n, ref.N - 1n]) {
      const refKey = bytesToHex(ref.referenceCompressPoint(ref.referencePublicKeyPoint(k)));
      const libKey = PublicKey.fromPrivateKey(PrivateKey.fromBigInt(k)).toHex();
      expect(refKey).toBe(libKey);
    }
  });

  it("derives the same public key for random scalars (differential fuzz)", () => {
    for (let i = 0; i < 25; i++) {
      const priv = PrivateKey.generate();
      const k = priv.toBigInt();
      expect(bytesToHex(ref.referenceCompressPoint(ref.referencePublicKeyPoint(k))))
        .toBe(PublicKey.fromPrivateKey(priv).toHex());
    }
  });

  it("rejects out-of-range scalars, matching the production validator", () => {
    expect(() => ref.referencePublicKeyPoint(0n)).toThrow();
    expect(() => ref.referencePublicKeyPoint(ref.N)).toThrow();
    expect(() => ref.referencePublicKeyPoint(-1n)).toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────
//  ISOLATION GUARD — spec §4
// ─────────────────────────────────────────────────────────────────────────

/**
 * Path relative to `from`, always with forward slashes.
 *
 * Windows `relative()` returns "crypto\\reference"; comparing that against
 * "crypto/reference" is always false. That bug does not make these guards
 * FAIL — it makes them silently pass while checking nothing, because the
 * reference-file filters match zero files and the assertions become vacuous.
 *
 * A security guard that quietly stops guarding is worse than no guard, since
 * it produces a green tick that nobody re-examines. Normalising here is the
 * whole fix; the `expect(...).toBeGreaterThan(0)` assertions below are the
 * backstop that would catch it if this ever regresses.
 */
function relativePosix(from: string, to: string): string {
  return relative(from, to).split(sep).join("/");
}

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...tsFiles(full));
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

describe("SECURITY GUARD: reference code is never a production dependency", () => {
  const coreRoot = fileURLToPath(new URL("../../core", import.meta.url));
  const files = tsFiles(coreRoot);

  const referenceFiles = files.filter((f) =>
    relativePosix(coreRoot, f).startsWith("crypto/reference"),
  );

  it("finds core source files to scan", () => {
    expect(files.length).toBeGreaterThan(4);
  });

  /**
   * BACKSTOP against a vacuous guard.
   *
   * The three tests below all iterate `referenceFiles`. If that array is ever
   * empty — a renamed directory, a broken path join, a separator mismatch on
   * some platform — every one of them passes trivially, having verified
   * nothing at all. This assertion is what converts that silent failure into
   * a loud one.
   *
   * The count is asserted exactly, not as "> 0", so that deleting a reference
   * file also trips it rather than quietly shrinking what gets checked.
   */
  it("the reference-file filter actually matches files (guard against a vacuous guard)", () => {
    expect(referenceFiles.map((f) => relativePosix(coreRoot, f)).sort()).toEqual([
      "crypto/reference/secp256k1.ts",
      "crypto/reference/sha256.ts",
    ]);
  });

  it("no module outside core/crypto/reference/ imports from it", () => {
    const offenders = files
      .filter((f) => !relativePosix(coreRoot, f).startsWith("crypto/reference"))
      .filter((f) => {
        const code = readFileSync(f, "utf8")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/\/\/.*$/gm, "");
        return /(from|import)\s*\(?\s*['"][^'"]*reference\//.test(code);
      })
      .map((f) => relativePosix(coreRoot, f));
    expect(offenders).toEqual([]);
  });

  it("reference modules import nothing at all — no chance of entangling production code", () => {
    for (const f of referenceFiles) {
      const code = readFileSync(f, "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/.*$/gm, "");
      expect(code).not.toMatch(/^\s*import\s/m);
    }
  });

  it("every reference file carries the NOT-A-SECURITY-BOUNDARY banner", () => {
    for (const f of referenceFiles) {
      expect(readFileSync(f, "utf8")).toContain("NOT A SECURITY BOUNDARY");
    }
  });
});
