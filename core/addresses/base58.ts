/**
 * BASE58CHECK
 *
 * The encoding Bitcoin used before Bech32, still required for one thing Veyra
 * needs: **extended keys**. An `xpub` is Base58Check, and there is no Bech32
 * equivalent in wide use, so exchanging account keys with other wallets means
 * speaking this.
 *
 * ─── The alphabet ──────────────────────────────────────────────────────────
 * 58 characters: all alphanumerics except `0`, `O`, `I`, and `l`. The
 * exclusions are the pairs a human most often confuses when copying by hand —
 * the same motivation as Bech32's, arrived at fifteen years earlier and less
 * rigorously.
 *
 * ─── Why it is worse than Bech32, and why we still need it ─────────────────
 *   · Mixed case, so it cannot be dictated reliably or typed on a phone
 *     keypad, and it is inefficient in QR codes.
 *   · The checksum is the first 4 bytes of HASH256. It detects errors but
 *     offers **no guarantee** about which error patterns it catches — unlike
 *     Bech32's BCH code, which provably detects any 4 or fewer substitutions.
 *   · Encoding is base conversion over a big integer, so it is O(n²) in the
 *     input length rather than linear.
 *
 * None of that is fixable without the ecosystem moving, and the ecosystem has
 * not moved for extended keys. So: implemented, used only where required, and
 * not offered as an address format.
 *
 * ─── Leading zeros ─────────────────────────────────────────────────────────
 * Base conversion loses leading zero BYTES, because a leading zero contributes
 * nothing to the integer's value. They are re-added as leading `1` characters
 * — one per zero byte. Omitting this is the classic Base58 bug: it produces a
 * shorter string that decodes to different bytes, and for a P2PKH address
 * (version byte 0x00) it happens on every single one.
 */

import { hash256 } from "../crypto/hashes.js";
import { equalsConstantTime } from "../crypto/bytes.js";
import { VeyraError } from "../errors/index.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = 58n;

const INDEX: ReadonlyMap<string, bigint> = new Map(
  [...ALPHABET].map((char, i) => [char, BigInt(i)]),
);

export class Base58Error extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Base58: ${reason}`);
    this.name = "Base58Error";
  }
}

/**
 * Longest input we will encode.
 *
 * Encoding is quadratic in length, so an unbounded input is a denial of
 * service. Everything Base58 is legitimately used for here is 82 bytes.
 */
const MAX_INPUT_BYTES = 256;

export function base58Encode(data: Uint8Array): string {
  if (data.length > MAX_INPUT_BYTES) {
    throw new Base58Error(`input exceeds ${MAX_INPUT_BYTES} bytes`);
  }
  if (data.length === 0) return "";

  let value = 0n;
  for (const byte of data) value = value * 256n + BigInt(byte);

  let out = "";
  while (value > 0n) {
    out = ALPHABET[Number(value % BASE)]! + out;
    value /= BASE;
  }

  // Leading zero bytes become leading '1's. Base conversion cannot represent
  // them, and dropping them yields a string that decodes to different bytes.
  for (const byte of data) {
    if (byte !== 0) break;
    out = "1" + out;
  }
  return out;
}

export function base58Decode(text: string): Uint8Array {
  if (typeof text !== "string") throw new Base58Error("input must be a string");
  if (text.length > MAX_INPUT_BYTES * 2) throw new Base58Error("input is too long");
  if (text.length === 0) return new Uint8Array(0);

  let value = 0n;
  for (const char of text) {
    const digit = INDEX.get(char);
    if (digit === undefined) {
      // The character is NOT echoed: this decodes user-supplied strings, and
      // reflecting input into an error is a habit worth not having.
      throw new Base58Error("string contains a character outside the Base58 alphabet");
    }
    value = value * BASE + digit;
  }

  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value /= 256n;
  }

  for (const char of text) {
    if (char !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/**
 * Append a 4-byte checksum: the first 4 bytes of HASH256(payload).
 *
 * Four bytes gives roughly a 1-in-4-billion chance of a corrupted string
 * passing. Adequate, and notably weaker than Bech32's *proven* bound.
 */
export function base58CheckEncode(payload: Uint8Array): string {
  const checksum = hash256(payload).slice(0, 4);
  const combined = new Uint8Array(payload.length + 4);
  combined.set(payload);
  combined.set(checksum, payload.length);
  return base58Encode(combined);
}

/** Decode and verify the checksum. Throws on mismatch. */
export function base58CheckDecode(text: string): Uint8Array {
  const decoded = base58Decode(text);
  if (decoded.length < 5) throw new Base58Error("too short to contain a checksum");

  const payload = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);
  const expected = hash256(payload).slice(0, 4);

  // Constant-time, out of habit. A checksum is not secret, but comparison
  // helpers that short-circuit have a way of being reused somewhere that
  // matters.
  if (!equalsConstantTime(checksum, expected)) {
    throw new Base58Error("checksum mismatch — the string is mistyped or corrupted");
  }
  return payload;
}
