/**
 * BIP-39 TESTS
 *
 * Vectors are the official Trezor set published with BIP-39. Testing against
 * our own output would prove only internal consistency — which is worthless
 * here, because the entire purpose of BIP-39 is that OTHER wallets can read
 * the phrase. A self-consistent but non-standard implementation produces
 * backups that restore nowhere.
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  generateMnemonic, validateMnemonic, entropyToMnemonic,
  mnemonicToEntropy, mnemonicToSeed,
} from "../../core/mnemonic/index.js";
import { ENGLISH_WORDLIST } from "../../core/mnemonic/wordlist.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

describe("wordlist integrity — consensus-critical", () => {
  it("contains exactly 2048 words (2^11, so each word is 11 bits)", () => {
    expect(ENGLISH_WORDLIST.length).toBe(2048);
  });

  it("matches the SHA-256 digest published in BIP-39", () => {
    // Reconstruct the canonical file format: words separated by \n, trailing \n.
    const canonical = ENGLISH_WORDLIST.join("\n") + "\n";
    expect(createHash("sha256").update(canonical, "utf8").digest("hex")).toBe(
      "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    );
  });

  it("is lexicographically sorted (permits binary search, fixes index order)", () => {
    for (let i = 1; i < ENGLISH_WORDLIST.length; i++) {
      expect(ENGLISH_WORDLIST[i - 1]! < ENGLISH_WORDLIST[i]!).toBe(true);
    }
  });

  it("has no duplicates", () => {
    expect(new Set(ENGLISH_WORDLIST).size).toBe(2048);
  });

  it("is uniquely identified by the first four letters — the reason 4-char entry works", () => {
    expect(new Set(ENGLISH_WORDLIST.map((w) => w.slice(0, 4))).size).toBe(2048);
  });

  it("contains only 3-8 character lowercase ASCII", () => {
    for (const word of ENGLISH_WORDLIST) expect(word).toMatch(/^[a-z]{3,8}$/);
  });

  it("boundary words are correct", () => {
    expect(ENGLISH_WORDLIST[0]).toBe("abandon");
    expect(ENGLISH_WORDLIST[2047]).toBe("zoo");
  });
});

/**
 * Official BIP-39 vectors (Trezor), passphrase "TREZOR".
 *
 * Split into two lists deliberately. ENTROPY_VECTORS covers the
 * entropy↔mnemonic mapping; SEED_VECTORS covers PBKDF2 seed derivation.
 *
 * Why split: a vector is only worth having if its expected value came from
 * the published spec. An entry whose expected output was produced by THIS
 * implementation proves nothing — it asserts that the code agrees with
 * itself. Rather than carry a seed value I could not source, the "legal
 * winner..." vector appears in ENTROPY_VECTORS only. Five independently
 * published seeds is ample; a sixth fabricated one would be worse than none,
 * because it would look like verification while providing none.
 */
const ENTROPY_VECTORS: Array<[string, string]> = [
  ["00000000000000000000000000000000",
   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"],
  ["7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
   "legal winner thank year wave sausage worth useful legal winner thank yellow"],
  ["80808080808080808080808080808080",
   "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"],
  ["ffffffffffffffffffffffffffffffff",
   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"],
  ["0000000000000000000000000000000000000000000000000000000000000000",
   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"],
  ["f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
   "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"],
];

/** Vectors where the published seed (passphrase "TREZOR") is also asserted. */
const SEED_VECTORS: Array<[string, string]> = [
  ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
   "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"],
  ["letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
   "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"],
  ["zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
   "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"],
  ["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
   "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"],
  ["void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
   "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"],
];

describe("BIP-39 official Trezor vectors", () => {
  it.each(ENTROPY_VECTORS)("entropy %s encodes to the expected mnemonic", (entropy, mnemonic) => {
    expect(entropyToMnemonic(hexToBytes(entropy))).toBe(mnemonic);
  });

  it.each(ENTROPY_VECTORS)("mnemonic for %s decodes back to the original entropy", (entropy, mnemonic) => {
    expect(bytesToHex(mnemonicToEntropy(mnemonic))).toBe(entropy);
  });

  it.each(SEED_VECTORS)("seed derivation matches the published vector", (mnemonic, seed) => {
    expect(bytesToHex(mnemonicToSeed(mnemonic, "TREZOR"))).toBe(seed);
  });
});

describe("checksum validation", () => {
  it("accepts every valid vector", () => {
    for (const [, mnemonic] of ENTROPY_VECTORS) {
      expect(validateMnemonic(mnemonic)).toBe(true);
    }
  });

  it("rejects a phrase with a swapped word — the error the checksum exists for", () => {
    // Swapping two words changes the bit pattern and almost always breaks the
    // checksum. "Almost": for 12 words the checksum is 4 bits, so ~1/16 of
    // corruptions slip through. The checksum catches typos, not attacks.
    expect(validateMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon",
    )).toBe(false);
  });

  it("rejects a word not in the wordlist", () => {
    expect(validateMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon veyra",
    )).toBe(false);
  });

  it("rejects wrong word counts", () => {
    expect(validateMnemonic("abandon abandon abandon")).toBe(false);
    expect(validateMnemonic("abandon ".repeat(13).trim())).toBe(false);
    expect(validateMnemonic("")).toBe(false);
  });

  it("rejects an altered final word (the checksum-bearing one)", () => {
    expect(validateMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo",
    )).toBe(false);
  });

  it("does not leak the mnemonic in error messages", () => {
    try {
      mnemonicToEntropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zebra");
      expect.unreachable();
    } catch (e) {
      const message = (e as Error).message;
      expect(message).not.toContain("abandon");
      expect(message).not.toContain("zebra");
    }
  });
});

describe("passphrase handling", () => {
  const mnemonic = ENTROPY_VECTORS[0]![1];

  it("a different passphrase produces a completely different seed", () => {
    const a = bytesToHex(mnemonicToSeed(mnemonic, "TREZOR"));
    const b = bytesToHex(mnemonicToSeed(mnemonic, "trezor"));
    expect(a).not.toBe(b);
  });

  it("EVERY passphrase is valid — there is no 'wrong passphrase' error", () => {
    // This is the footgun: a typo does not fail, it silently opens a
    // different, empty wallet. Asserting it here so the behaviour is
    // documented as intentional rather than discovered later.
    for (const passphrase of ["", "a", "wrong", "🔑", " "]) {
      const seed = mnemonicToSeed(mnemonic, passphrase);
      expect(seed.length).toBe(64);
    }
  });

  it("NFKD normalisation: composed and decomposed forms give the same seed", () => {
    // "é" as one code point vs "e" + combining accent. Visually identical,
    // different bytes. Without normalisation these would give different
    // wallets and the user would see an empty balance with no explanation.
    const composed = "caf\u00e9";
    const decomposed = "cafe\u0301";
    expect(composed).not.toBe(decomposed);
    expect(bytesToHex(mnemonicToSeed(mnemonic, composed)))
      .toBe(bytesToHex(mnemonicToSeed(mnemonic, decomposed)));
  });

  it("produces a 64-byte seed regardless of input", () => {
    expect(mnemonicToSeed(mnemonic).length).toBe(64);
  });
});

describe("generation", () => {
  it("defaults to 24 words", () => {
    expect(generateMnemonic().split(" ").length).toBe(24);
  });

  it.each([12, 15, 18, 21, 24] as const)("generates %i words on request", (count) => {
    const mnemonic = generateMnemonic(count);
    expect(mnemonic.split(" ").length).toBe(count);
    expect(validateMnemonic(mnemonic)).toBe(true);
  });

  it("never repeats across many generations", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) seen.add(generateMnemonic(12));
    expect(seen.size).toBe(200);
  });

  it("every generated mnemonic round-trips through entropy", () => {
    for (let i = 0; i < 50; i++) {
      const mnemonic = generateMnemonic(24);
      expect(entropyToMnemonic(mnemonicToEntropy(mnemonic))).toBe(mnemonic);
    }
  });

  it("takes no random-source parameter — weak entropy cannot be injected", () => {
    expect(generateMnemonic.length).toBeLessThanOrEqual(1);
    // The single parameter is wordCount, not a source.
    expect(generateMnemonic.toString()).not.toContain("source");
  });

  it("rejects invalid entropy sizes", () => {
    expect(() => entropyToMnemonic(new Uint8Array(15))).toThrow();
    expect(() => entropyToMnemonic(new Uint8Array(31))).toThrow();
    expect(() => entropyToMnemonic(new Uint8Array(0))).toThrow();
  });
});

describe("whitespace and formatting tolerance", () => {
  const mnemonic = ENTROPY_VECTORS[0]![1];

  it("tolerates extra internal and surrounding whitespace", () => {
    expect(validateMnemonic("  " + mnemonic.replace(/ /g, "   ") + "  ")).toBe(true);
  });

  it("does NOT tolerate case changes — the wordlist is lowercase-only", () => {
    expect(validateMnemonic(mnemonic.toUpperCase())).toBe(false);
  });
});
