/**
 * ENTROPY TESTS
 *
 * Testing a random number generator is philosophically awkward: you cannot
 * prove randomness from samples, and any specific output is equally likely.
 * What you CAN do is:
 *
 *   1. Assert structural properties (length, no repeats, no constant output).
 *   2. Run cheap statistical sanity checks that catch gross failures — a
 *      generator stuck at zero, returning a counter, or with a tiny period.
 *   3. Inspect the SOURCE TREE for predictable-randomness usage, which is the
 *      only way to catch the failure mode where output looks fine but is not.
 *
 * Point 3 is the one that matters most and is the reason for the guard test
 * at the bottom of this file. See core/crypto/entropy.ts for why: a wallet
 * built on Math.random() behaves perfectly and is worthless.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  randomBytes, generateWalletEntropy, wipe,
  MIN_ENTROPY_BYTES, DEFAULT_ENTROPY_BYTES, MAX_ENTROPY_BYTES,
} from "../../core/crypto/entropy.js";
import { bytesToHex } from "../../core/crypto/bytes.js";

describe("randomBytes — structure and policy", () => {
  it("returns the requested number of bytes", () => {
    expect(randomBytes(16).length).toBe(16);
    expect(randomBytes(32).length).toBe(32);
    expect(randomBytes(64).length).toBe(64);
  });

  it("defaults to 256 bits", () => {
    expect(randomBytes().length).toBe(DEFAULT_ENTROPY_BYTES);
    expect(DEFAULT_ENTROPY_BYTES).toBe(32);
  });

  it("refuses to produce fewer than 128 bits", () => {
    expect(() => randomBytes(MIN_ENTROPY_BYTES - 1)).toThrow(/minimum permitted/);
    expect(() => randomBytes(0)).toThrow();
    expect(() => randomBytes(8)).toThrow();
  });

  it("refuses absurd sizes, so a bad caller cannot exhaust memory", () => {
    expect(() => randomBytes(MAX_ENTROPY_BYTES + 1)).toThrow();
    expect(() => randomBytes(2 ** 30)).toThrow();
  });

  it("rejects non-integer sizes rather than coercing them", () => {
    expect(() => randomBytes(32.5)).toThrow();
    expect(() => randomBytes(Number.NaN)).toThrow();
    expect(() => randomBytes(Number.POSITIVE_INFINITY)).toThrow();
  });
});

describe("randomBytes — statistical sanity", () => {
  it("never returns an all-zero buffer", () => {
    for (let i = 0; i < 50; i++) {
      expect(randomBytes(32).every((b) => b === 0)).toBe(false);
    }
  });

  it("produces no duplicates across many draws (a stuck or low-period RNG fails here)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(bytesToHex(randomBytes(32)));
    expect(seen.size).toBe(1000);
  });

  it("covers the full byte range with roughly uniform frequency", () => {
    // 256 * 400 = 102,400 samples; expected count per value = 400.
    const counts = new Array(256).fill(0);
    for (let i = 0; i < 3200; i++) {
      for (const b of randomBytes(32)) counts[b]++;
    }
    expect(counts.every((c) => c > 0)).toBe(true);
    // Generous bounds: this catches a broken generator, not a subtly biased
    // one. Detecting subtle bias needs a real suite (Dieharder / NIST STS),
    // which is out of scope for a unit test and noted in docs/TESTING.md.
    const min = Math.min(...counts);
    const max = Math.max(...counts);
    expect(min).toBeGreaterThan(250);
    expect(max).toBeLessThan(550);
  });

  it("has a bit balance close to 50/50", () => {
    let ones = 0;
    const draws = 400;
    for (let i = 0; i < draws; i++) {
      for (const b of randomBytes(32)) {
        let x = b;
        while (x) { ones += x & 1; x >>= 1; }
      }
    }
    const totalBits = draws * 32 * 8;
    const ratio = ones / totalBits;
    expect(ratio).toBeGreaterThan(0.48);
    expect(ratio).toBeLessThan(0.52);
  });
});

describe("generateWalletEntropy", () => {
  it("always yields 256 bits", () => {
    expect(generateWalletEntropy().length).toBe(32);
  });

  it("accepts no arguments — weak sources cannot be injected into wallet creation", () => {
    // The absence of a parameter is the security property; assert it on the
    // function object so a future refactor that adds one fails here.
    expect(generateWalletEntropy.length).toBe(0);
  });
});

describe("wipe", () => {
  it("zeroes the buffer in place", () => {
    const secret = randomBytes(32);
    wipe(secret);
    expect(secret.every((b) => b === 0)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────
//  SOURCE-TREE GUARD
//
//  Spec §2.1: "Test that wallet generation does not use predictable
//  application-level randomness."
//
//  No behavioural test can catch Math.random() in the key path, because the
//  wallet would still work. So we read the source instead. This is the single
//  most valuable test in this file.
// ─────────────────────────────────────────────────────────────────────────

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

describe("SECURITY GUARD: no predictable randomness in core/", () => {
  // fileURLToPath, NOT .pathname. On Windows `.pathname` yields
  // "/C:/Veyra/core" — a leading slash and forward slashes — which join()
  // then mangles into "C:\\C:\\Veyra\\core". fileURLToPath handles the
  // platform conversion correctly.
  const files = sourceFiles(fileURLToPath(new URL("../../core", import.meta.url)));

  it("finds source files to scan (guards against the guard silently passing)", () => {
    expect(files.length).toBeGreaterThan(4);
  });

  it.each([
    ["Math.random", /Math\s*\.\s*random\s*\(/],
    ["Date.now as entropy", /(seed|entropy|nonce|key)\w*\s*=\s*Date\s*\.\s*now/i],
    ["performance.now as entropy", /(seed|entropy|nonce|key)\w*\s*=\s*performance\s*\.\s*now/i],
  ])("no production module uses %s", (_label, pattern) => {
    const offenders = files.filter((f) => {
      const src = readFileSync(f, "utf8");
      // Strip block and line comments so prose ABOUT Math.random doesn't trip it.
      const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      return pattern.test(code);
    });
    expect(offenders).toEqual([]);
  });
});
