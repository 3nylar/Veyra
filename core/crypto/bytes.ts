/**
 * Byte and hex utilities.
 *
 * Small, boring, and security-relevant. Two things here matter:
 *
 * 1. `hexToBytes` is strict. Loose hex parsers that skip whitespace, accept
 *    odd lengths, or tolerate a "0x" prefix are a recurring source of bugs
 *    where a malformed key or address is silently reinterpreted as a valid
 *    but different value. We reject rather than repair.
 *
 * 2. `equalsConstantTime` avoids early-exit comparison. `a === b` on strings,
 *    or a loop with `if (a[i] !== b[i]) return false`, leaks how many leading
 *    bytes matched. Where the compared value is secret-derived (a checksum, an
 *    HMAC tag, an auth token in the API layer), that leak lets an attacker
 *    recover the correct value one byte at a time.
 */

import { InvalidEncodingError, InvalidLengthError } from "../errors/index.js";

const HEX_CHARS = "0123456789abcdef";

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += HEX_CHARS[b >> 4]! + HEX_CHARS[b & 0x0f]!;
  }
  return out;
}

/**
 * Parse a strict lowercase-or-uppercase hex string. No prefix, no whitespace,
 * even length only.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new InvalidEncodingError("hex input must be a string");
  }
  if (hex.length % 2 !== 0) {
    throw new InvalidEncodingError("hex string must have an even length");
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new InvalidEncodingError("hex string contains non-hex characters");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Big-endian bytes → BigInt. Bitcoin encodes scalars big-endian throughout. */
export function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

/** BigInt → fixed-length big-endian bytes. Throws if the value does not fit. */
export function bigIntToBytesBE(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new InvalidEncodingError("value must be non-negative");
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new InvalidEncodingError(`value does not fit in ${length} bytes`);
  }
  return out;
}

/**
 * Compare two byte arrays without leaking the position of the first
 * difference through timing.
 *
 * The length check does short-circuit. That is acceptable and unavoidable:
 * the length of a fixed-format field is not secret, and allocating a padded
 * comparison would leak just as much.
 */
export function equalsConstantTime(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Assert an exact byte length, with a non-secret-bearing error. */
export function assertLength(
  what: string,
  bytes: Uint8Array,
  expected: number,
): void {
  if (bytes.length !== expected) {
    throw new InvalidLengthError(what, expected, bytes.length);
  }
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
