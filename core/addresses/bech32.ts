/**
 * BECH32 / BECH32M — BIP-173 and BIP-350
 *
 * ─── Why a new address format existed at all ───────────────────────────────
 * Base58Check addresses (the "1..." and "3..." ones) have real problems:
 *   - Mixed case, so they cannot be read aloud reliably or typed on a phone
 *     keypad, and they are inefficient in QR codes (which have a compact
 *     alphanumeric mode covering only uppercase and digits).
 *   - The 4-byte double-SHA256 checksum detects errors but cannot locate
 *     them, and offers no guarantee about which error patterns it catches.
 *
 * Bech32 fixes both. It is lowercase-only (or uppercase-only), uses a 32-
 * character alphabet excluding "1", "b", "i", and "o" — the characters most
 * often confused with each other and with digits — and its checksum is a BCH
 * code with a proven guarantee: **it detects any 4 or fewer character
 * substitutions, and detects longer errors with probability ~1 in 10^9.**
 *
 * That "proven" is the important part. It is not merely "unlikely to miss an
 * error"; the algebraic structure guarantees the bound for small errors.
 *
 * ─── Why there are TWO variants ────────────────────────────────────────────
 * A genuine, instructive bug in the original design.
 *
 * Bech32's checksum constant was 1. It was later discovered that if the final
 * character of a Bech32 string is "p", inserting or deleting "q" characters
 * immediately before it does not change the checksum. So certain
 * length-altering errors go undetected — precisely the failure mode the
 * checksum was supposed to rule out.
 *
 * For SegWit v0 (P2WPKH/P2WSH) this is harmless, because those addresses have
 * fixed, validated lengths — a wrong-length v0 address is rejected on length
 * before the checksum matters. But for future witness versions with variable
 * lengths it was a real risk.
 *
 * BIP-350 therefore defines **Bech32m**, identical except the checksum
 * constant is 0x2bc830a3 instead of 1. The rule is now:
 *
 *     witness version 0  (P2WPKH, P2WSH)  → Bech32
 *     witness version 1+ (P2TR, Taproot)  → Bech32m
 *
 * Using the wrong one produces an address that other wallets reject — or,
 * worse, an address that looks valid and is unspendable. This module keeps
 * the two explicitly separate and never guesses.
 *
 * ─── Why Veyra implements this rather than importing it ────────────────────
 * Bech32 is an error-detecting CODE, not a cryptographic secret. There is no
 * key material, no timing sensitivity, and no side channel — the entire input
 * is public by definition. The constant-time argument that keeps
 * core/crypto/reference/ out of production simply does not apply here.
 *
 * It is also the single best-specified algorithm in Bitcoin, with an
 * extensive published vector set including deliberately invalid cases. That
 * makes it genuinely testable, which is the standard this project applies.
 *
 * ─── If implemented incorrectly ────────────────────────────────────────────
 * Funds sent to a malformed address are unrecoverable. There is no bounce, no
 * error, no support desk. This module is therefore tested against every
 * published valid AND invalid vector from BIP-173 and BIP-350, including the
 * adversarial ones (wrong HRP, mixed case, invalid padding, out-of-range
 * witness versions).
 */

import { VeyraError } from "../errors/index.js";

/**
 * The 32-character alphabet.
 *
 * Note the deliberate omissions: "1", "b", "i", "o". Excluding "1" also means
 * "1" can serve as the separator between the human-readable part and the data
 * part without ambiguity — and since it is excluded from the data alphabet,
 * the LAST "1" in the string is unambiguously the separator, even if the HRP
 * itself contains one.
 */
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const CHARSET_REV: ReadonlyMap<string, number> = new Map(
  [...CHARSET].map((char, index) => [char, index]),
);

/** Checksum constants. The whole difference between the two variants. */
export const BECH32_CONST = 1;
export const BECH32M_CONST = 0x2bc830a3;

export type Bech32Variant = "bech32" | "bech32m";

export class Bech32Error extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Bech32: ${reason}`);
    this.name = "Bech32Error";
  }
}

/**
 * The BCH code's generator polynomial step, over GF(32).
 *
 * This is the mathematical heart of the checksum. Each of the five constants
 * corresponds to a coefficient of the generator polynomial; the shift-and-
 * conditionally-XOR structure is polynomial multiplication modulo that
 * generator. The algebra is what delivers the "detects any 4 substitutions"
 * guarantee — it is not a hash, and its properties are proven rather than
 * assumed.
 */
function polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GEN[i]!;
    }
  }
  return chk >>> 0;
}

/**
 * Expand the human-readable part for checksum purposes.
 *
 * The HRP is folded in as high bits, then a zero, then low bits. Including
 * the HRP means "bc1..." and "tb1..." with identical data have different
 * checksums — so a mainnet address cannot be misread as a testnet one, which
 * is a real fund-loss scenario this design deliberately prevents.
 */
function hrpExpand(hrp: string): number[] {
  const high: number[] = [];
  const low: number[] = [];
  for (const char of hrp) {
    const code = char.charCodeAt(0);
    high.push(code >>> 5);
    low.push(code & 31);
  }
  return [...high, 0, ...low];
}

function verifyChecksum(hrp: string, data: number[]): Bech32Variant | null {
  const check = polymod([...hrpExpand(hrp), ...data]);
  if (check === BECH32_CONST) return "bech32";
  if (check === BECH32M_CONST) return "bech32m";
  return null;
}

function createChecksum(hrp: string, data: number[], variant: Bech32Variant): number[] {
  const constant = variant === "bech32" ? BECH32_CONST : BECH32M_CONST;
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = polymod(values) ^ constant;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) out.push((mod >>> (5 * (5 - i))) & 31);
  return out;
}

/** Encode 5-bit groups with an HRP. Low-level; most callers want `encodeSegwitAddress`. */
export function bech32Encode(hrp: string, data: number[], variant: Bech32Variant): string {
  if (hrp.length < 1) throw new Bech32Error("human-readable part must not be empty");
  const combined = [...data, ...createChecksum(hrp, data, variant)];
  let result = hrp + "1";
  for (const value of combined) {
    if (value < 0 || value > 31) throw new Bech32Error("data value out of 5-bit range");
    result += CHARSET[value]!;
  }
  // BIP-173 caps total length at 90 characters. The BCH guarantee is only
  // proven within that bound, so exceeding it silently weakens error detection.
  if (result.length > 90) throw new Bech32Error("encoded string exceeds 90 characters");
  return result;
}

/** Decode, verifying the checksum and returning which variant matched. */
export function bech32Decode(
  input: string,
): { hrp: string; data: number[]; variant: Bech32Variant } {
  if (input.length > 90) throw new Bech32Error("string exceeds 90 characters");

  // Mixed case is REJECTED, not normalised. An address is valid all-lower or
  // all-upper; mixed case indicates corruption or tampering, and quietly
  // lowercasing it would mask a real error the checksum was meant to catch.
  const hasLower = /[a-z]/.test(input);
  const hasUpper = /[A-Z]/.test(input);
  if (hasLower && hasUpper) throw new Bech32Error("mixed case is not permitted");

  const normalised = input.toLowerCase();

  for (const char of normalised) {
    const code = char.charCodeAt(0);
    if (code < 33 || code > 126) {
      throw new Bech32Error("string contains a character outside the printable ASCII range");
    }
  }

  // The separator is the LAST "1", because the HRP may itself contain "1"
  // while the data part never can (it is excluded from the alphabet).
  const separator = normalised.lastIndexOf("1");
  if (separator < 1) throw new Bech32Error("missing or misplaced separator");
  if (separator + 7 > normalised.length) {
    throw new Bech32Error("data part is too short to contain a checksum");
  }

  const hrp = normalised.slice(0, separator);
  const data: number[] = [];
  for (const char of normalised.slice(separator + 1)) {
    const value = CHARSET_REV.get(char);
    if (value === undefined) throw new Bech32Error("data part contains an invalid character");
    data.push(value);
  }

  const variant = verifyChecksum(hrp, data);
  if (variant === null) throw new Bech32Error("checksum mismatch");

  return { hrp, data: data.slice(0, -6), variant };
}

/**
 * Regroup bits between bases (8-bit bytes ↔ 5-bit groups).
 *
 * The padding rules are where naive implementations go wrong, and BIP-173
 * calls them out explicitly:
 *   - When padding IS allowed (8→5), leftover bits are zero-padded up.
 *   - When it is NOT (5→8), any leftover bits must be fewer than 5 AND must
 *     be zero. Non-zero padding means the encoder produced something
 *     malleable — two different 5-bit sequences decoding to the same bytes —
 *     and MUST be rejected.
 */
export function convertBits(
  data: readonly number[],
  fromBits: number,
  toBits: number,
  pad: boolean,
): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << toBits) - 1;

  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) {
      throw new Bech32Error("input value out of range for the source base");
    }
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits > 0) out.push((acc << (toBits - bits)) & maxv);
  } else {
    if (bits >= fromBits) throw new Bech32Error("excess padding");
    if (((acc << (toBits - bits)) & maxv) !== 0) throw new Bech32Error("non-zero padding");
  }
  return out;
}

/**
 * Encode a SegWit address (BIP-173 / BIP-350).
 *
 * The variant is chosen by witness version and is NOT a caller option — that
 * is the whole lesson of BIP-350, and making it configurable would invite
 * exactly the mistake the second variant exists to prevent.
 */
export function encodeSegwitAddress(
  hrp: string,
  witnessVersion: number,
  witnessProgram: Uint8Array,
): string {
  if (witnessVersion < 0 || witnessVersion > 16) {
    throw new Bech32Error("witness version must be between 0 and 16");
  }
  if (witnessProgram.length < 2 || witnessProgram.length > 40) {
    throw new Bech32Error("witness program must be between 2 and 40 bytes");
  }
  // Version 0 defines exactly two program sizes: 20 (P2WPKH) and 32 (P2WSH).
  if (witnessVersion === 0 && witnessProgram.length !== 20 && witnessProgram.length !== 32) {
    throw new Bech32Error("version 0 witness program must be 20 or 32 bytes");
  }

  const variant: Bech32Variant = witnessVersion === 0 ? "bech32" : "bech32m";
  const data = [witnessVersion, ...convertBits([...witnessProgram], 8, 5, true)];
  return bech32Encode(hrp, data, variant);
}

/** Decode a SegWit address, enforcing every consensus-relevant rule. */
export function decodeSegwitAddress(
  hrp: string,
  address: string,
): { version: number; program: Uint8Array } {
  const decoded = bech32Decode(address);
  if (decoded.hrp !== hrp) {
    throw new Bech32Error(`expected human-readable part '${hrp}', found '${decoded.hrp}'`);
  }
  if (decoded.data.length < 1) throw new Bech32Error("missing witness version");

  const version = decoded.data[0]!;
  if (version > 16) throw new Bech32Error("witness version must be between 0 and 16");

  // The variant must match the version. This check is what makes a v0 address
  // encoded with bech32m (or vice versa) invalid rather than silently accepted.
  const expected: Bech32Variant = version === 0 ? "bech32" : "bech32m";
  if (decoded.variant !== expected) {
    throw new Bech32Error(
      `witness version ${version} requires ${expected} encoding`,
    );
  }

  const program = Uint8Array.from(convertBits(decoded.data.slice(1), 5, 8, false));
  if (program.length < 2 || program.length > 40) {
    throw new Bech32Error("witness program must be between 2 and 40 bytes");
  }
  if (version === 0 && program.length !== 20 && program.length !== 32) {
    throw new Bech32Error("version 0 witness program must be 20 or 32 bytes");
  }
  return { version, program };
}
