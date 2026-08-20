/**
 * BIP-39 — MNEMONIC SEED PHRASES
 *
 * ─── The single most important thing to understand ─────────────────────────
 *
 *     mnemonic ≠ private key
 *
 * A mnemonic is not a key, and it is not an encoding of one key. It is a
 * human-transcribable encoding of the ENTROPY from which an entire tree of
 * keys is derived:
 *
 *     entropy (128–256 bits)
 *        ↓   + 4–8 bit checksum, split into 11-bit groups
 *     mnemonic (12–24 words)
 *        ↓   PBKDF2-HMAC-SHA512, 2048 iterations, salt = "mnemonic" + passphrase
 *     seed (512 bits)
 *        ↓   HMAC-SHA512 with key "Bitcoin seed"  (BIP-32)
 *     master key
 *        ↓   hardened + non-hardened child derivation
 *     derived keys → addresses
 *
 * Note the arrows are one-way in the *practical* sense but NOT all equally so.
 * The mnemonic→seed step is deliberately slow. The entropy→mnemonic step is
 * fully reversible — the words ARE the entropy, plus a checksum. Anyone who
 * reads your 12 words owns every key in the tree, forever, including
 * addresses you have not generated yet.
 *
 * ─── Why does the checksum exist? ──────────────────────────────────────────
 * The last few bits of the final word are a checksum over the entropy. This
 * catches transcription errors — a swapped word, a misread word — before the
 * user funds an address they cannot recover from.
 *
 * The check is probabilistic, not absolute. For a 12-word phrase the checksum
 * is 4 bits, so a random corrupted phrase passes with probability 1/16. It
 * catches honest mistakes; it is NOT a security control and cannot detect a
 * deliberately crafted valid-but-different phrase.
 *
 * ─── Why PBKDF2 with 2048 iterations? ──────────────────────────────────────
 * The mnemonic is low-entropy *relative to an attacker who has partial
 * information* — for example, someone who knows 20 of your 24 words, or who
 * is attacking a user-chosen passphrase. Key stretching multiplies the cost
 * of each guess.
 *
 * Being honest about the strength here: 2048 iterations is weak by modern
 * standards. Argon2id or scrypt would be far better, and 2048 rounds of
 * HMAC-SHA512 is trivially GPU-parallelisable. BIP-39 was specified in 2013
 * and the parameter cannot be changed without breaking compatibility with
 * every wallet in existence. Veyra follows the standard because
 * interoperability of a *backup phrase* is worth more than a stronger KDF
 * that no other wallet can read. The correct defence is full-entropy
 * mnemonics (which we always generate), not a stronger KDF.
 *
 * ─── The passphrase (BIP-39 "25th word") ───────────────────────────────────
 * An optional passphrase is concatenated into the PBKDF2 salt. Critically:
 *
 *   - It is NOT a password. There is no "wrong passphrase" error.
 *   - EVERY passphrase produces a valid, different, empty-looking wallet.
 *   - A forgotten passphrase is unrecoverable. There is nothing to brute
 *     force against, because there is no way to recognise success except by
 *     finding funds.
 *
 * This is a genuine footgun, and it is also the feature: it gives plausible
 * deniability, since a coerced user can reveal the bare mnemonic and show a
 * decoy wallet.
 *
 * ─── Where used in Veyra ───────────────────────────────────────────────────
 * Wallet creation and wallet restore. The mnemonic is the ONLY backup
 * artefact; everything else in the wallet is reproducible from it.
 *
 * ─── If implemented incorrectly ────────────────────────────────────────────
 *   - Wrong normalisation → seed differs → funds unreachable from other wallets.
 *   - Wrong iteration count or salt → same.
 *   - Accepting an invalid checksum → user trusts a corrupt backup.
 *   - Generating from weak entropy → see core/crypto/entropy.ts.
 *
 * Every one of these is SILENT. The wallet works; the backup is worthless.
 * That is why this module is tested exclusively against the official
 * Trezor/BIP-39 vectors rather than against itself.
 */

import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { sha256 } from "../crypto/hashes.js";
import { generateWalletEntropy, wipe } from "../crypto/entropy.js";
import { ENGLISH_WORDLIST } from "./wordlist.js";
import { VeyraError } from "../errors/index.js";

/** Permitted entropy sizes in bytes, and the word count each produces. */
export const ENTROPY_SIZES = Object.freeze({
  16: 12,
  20: 15,
  24: 18,
  28: 21,
  32: 24,
} as const);

export type MnemonicWordCount = 12 | 15 | 18 | 21 | 24;

export class InvalidMnemonicError extends VeyraError {
  constructor(reason: string) {
    // NOTE: `reason` must never contain the mnemonic or any of its words.
    // Every call site below passes a constant or a positional index only.
    super("INVALID_ENCODING", `Invalid mnemonic: ${reason}`);
    this.name = "InvalidMnemonicError";
  }
}

/**
 * Index lookup for the wordlist. Built once.
 *
 * A Map rather than `indexOf` — not for speed on 2048 entries, but so that
 * lookup time does not depend on where in the list a word sits. `indexOf`
 * takes longer for "zoo" than for "abandon", which leaks word positions to
 * anyone able to time validation.
 */
const WORD_INDEX: ReadonlyMap<string, number> = new Map(
  ENGLISH_WORDLIST.map((word, index) => [word, index]),
);

/**
 * NFKD-normalise. BIP-39 mandates this for both mnemonic and passphrase.
 *
 * Why it matters: "é" can be encoded as one code point (U+00E9) or as "e"
 * followed by a combining accent (U+0065 U+0301). These are visually
 * identical and compare as different byte strings. Without normalisation, a
 * passphrase typed on one keyboard could produce a different seed than the
 * same passphrase typed on another — and the user would see an empty wallet
 * with no error and no explanation.
 */
function nfkd(input: string): string {
  return input.normalize("NFKD");
}

/** Convert bytes to a big-endian bit string. Clear over clever; sizes are tiny. */
function bytesToBits(bytes: Uint8Array): string {
  let bits = "";
  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  return bits;
}

/**
 * Derive the BIP-39 checksum bits: the first (entropyBits / 32) bits of
 * SHA-256(entropy).
 *
 * 128-bit entropy → 4 checksum bits → 132 bits → 12 words
 * 256-bit entropy → 8 checksum bits → 264 bits → 24 words
 */
function checksumBits(entropy: Uint8Array): string {
  const checksumLength = (entropy.length * 8) / 32;
  return bytesToBits(sha256(entropy)).slice(0, checksumLength);
}

/**
 * Encode entropy as a mnemonic phrase.
 *
 * @param entropy 16, 20, 24, 28, or 32 bytes.
 */
export function entropyToMnemonic(entropy: Uint8Array): string {
  const wordCount = (ENTROPY_SIZES as Record<number, number>)[entropy.length];
  if (wordCount === undefined) {
    throw new InvalidMnemonicError(
      `entropy must be 16, 20, 24, 28, or 32 bytes, received ${entropy.length}`,
    );
  }

  const bits = bytesToBits(entropy) + checksumBits(entropy);
  const words: string[] = [];
  for (let i = 0; i < bits.length; i += 11) {
    const index = Number.parseInt(bits.slice(i, i + 11), 2);
    words.push(ENGLISH_WORDLIST[index]!);
  }
  return words.join(" ");
}

/**
 * Recover the entropy encoded by a mnemonic, verifying the checksum.
 *
 * Throws on any structural problem. Note that error messages report *what*
 * kind of problem and *where* (by index), never the offending word itself —
 * a log containing "unknown word 'abandon' at position 3" is a partial
 * mnemonic disclosure.
 */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  const words = nfkd(mnemonic).trim().split(/\s+/);

  const validCounts = Object.values(ENTROPY_SIZES) as number[];
  if (!validCounts.includes(words.length)) {
    throw new InvalidMnemonicError(
      `expected 12, 15, 18, 21, or 24 words, received ${words.length}`,
    );
  }

  let bits = "";
  for (let i = 0; i < words.length; i++) {
    const index = WORD_INDEX.get(words[i]!);
    if (index === undefined) {
      throw new InvalidMnemonicError(`word at position ${i + 1} is not in the wordlist`);
    }
    bits += index.toString(2).padStart(11, "0");
  }

  const entropyBits = (bits.length * 32) / 33;
  const entropy = new Uint8Array(entropyBits / 8);
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = Number.parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }

  if (bits.slice(entropyBits) !== checksumBits(entropy)) {
    throw new InvalidMnemonicError("checksum mismatch — the phrase is mistyped or corrupted");
  }
  return entropy;
}

/**
 * Generate a fresh mnemonic.
 *
 * Defaults to 24 words (256-bit entropy). Takes no random-source parameter:
 * as with `generateWalletEntropy`, there is no syntactic path for a caller to
 * inject a weak generator into wallet creation.
 */
export function generateMnemonic(wordCount: MnemonicWordCount = 24): string {
  const entry = Object.entries(ENTROPY_SIZES).find(([, count]) => count === wordCount);
  if (!entry) {
    throw new InvalidMnemonicError(`unsupported word count ${wordCount}`);
  }
  const entropyBytes = Number(entry[0]);

  // generateWalletEntropy always returns 32 bytes; slice for shorter phrases.
  // The slice is of already-uniform bytes, so no bias is introduced.
  const full = generateWalletEntropy();
  const entropy = full.slice(0, entropyBytes);
  try {
    return entropyToMnemonic(entropy);
  } finally {
    wipe(full);
    wipe(entropy);
  }
}

/** True if the mnemonic is well-formed and its checksum verifies. */
export function validateMnemonic(mnemonic: string): boolean {
  try {
    mnemonicToEntropy(mnemonic);
    return true;
  } catch {
    return false;
  }
}

/**
 * Derive the 64-byte BIP-39 seed.
 *
 * PBKDF2-HMAC-SHA512(password = NFKD(mnemonic), salt = NFKD("mnemonic" + passphrase),
 *                    iterations = 2048, dkLen = 64)
 *
 * ⚠️ This function does NOT validate the checksum, and that is deliberate and
 * specified: BIP-39 defines the seed for ANY string. Wallets that skip
 * validation will happily derive from a typo'd phrase and show an empty
 * wallet. Veyra's wallet layer validates first and then derives — but this
 * primitive stays faithful to the spec so the official test vectors (several
 * of which use phrases with deliberately unusual entropy) can be run against
 * it directly.
 */
export function mnemonicToSeed(mnemonic: string, passphrase = ""): Uint8Array {
  const password = new TextEncoder().encode(nfkd(mnemonic));
  const salt = new TextEncoder().encode(nfkd("mnemonic" + passphrase));
  try {
    return pbkdf2(sha512, password, salt, { c: 2048, dkLen: 64 });
  } finally {
    wipe(password);
    wipe(salt);
  }
}
