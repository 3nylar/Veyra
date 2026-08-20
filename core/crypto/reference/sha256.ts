/**
 * ══════════════════════════════════════════════════════════════════════════
 *  EDUCATIONAL REFERENCE IMPLEMENTATION — NOT A SECURITY BOUNDARY
 * ══════════════════════════════════════════════════════════════════════════
 *
 * This is a readable, dependency-free SHA-256 written to be *understood*,
 * not to be used. Nothing in core/ outside this directory imports it. A test
 * in tests/cryptography/reference-isolation.test.ts scans the source tree and
 * fails CI if any production module ever does.
 *
 * Why keep it at all?
 *   Because "the library hashed it" is not understanding. You should be able
 *   to read this file and see that SHA-256 is not magic: it is 64 rounds of
 *   additions, rotations, and XORs over eight 32-bit words.
 *
 * Why must it never be production?
 *   1. It is not constant-time-audited. Real implementations are reviewed for
 *      data-dependent branches and memory access. This one is not.
 *   2. It has not been differentially fuzzed or formally reviewed.
 *   3. It is written for clarity, which is often in direct tension with the
 *      defensive coding real crypto requires.
 *   The pattern of "we wrote our own crypto to prove we understood it, then
 *   shipped it" is one of the most reliable sources of catastrophic wallet
 *   bugs. Veyra separates the two on purpose.
 *
 * Correctness is asserted against @noble/hashes and against the NIST FIPS
 * 180-4 published vectors in tests/cryptography/reference-sha256.test.ts.
 *
 * ─── How SHA-256 works ─────────────────────────────────────────────────────
 *
 * SHA-256 is a Merkle–Damgård construction over a Davies–Meyer compression
 * function:
 *
 *   1. PAD the message so its length is a multiple of 512 bits. The padding
 *      is: one 0x80 byte, then zero bytes, then the original message length
 *      in bits as a 64-bit big-endian integer. Encoding the length is what
 *      makes the padding unambiguous — without it, "abc" and "abc\x80" could
 *      pad to the same block.
 *
 *   2. Initialise eight 32-bit state words H0..H7 to fixed constants: the
 *      first 32 bits of the fractional parts of the square roots of the first
 *      eight primes. These are "nothing-up-my-sleeve" numbers — their
 *      derivation is public and arbitrary-looking, which is evidence that the
 *      designer did not choose them to hide a backdoor.
 *
 *   3. For each 512-bit block, run a 64-round compression, then add the result
 *      back into the running state (that feed-forward addition is the
 *      Davies–Meyer step; it is what makes the compression function one-way
 *      even though the round function itself is invertible).
 *
 *   4. Output the concatenated state, big-endian: 32 bytes.
 *
 * The round function mixes via:
 *   Ch(e,f,g)  = (e AND f) XOR (NOT e AND g)      — "choose": e selects f or g
 *   Maj(a,b,c) = majority bit of a, b, c          — nonlinearity
 *   Σ0, Σ1, σ0, σ1 = fixed rotation/shift mixes   — diffusion across bit positions
 *
 * Diffusion is the goal: flipping one input bit should flip about half the
 * output bits, unpredictably. That is the avalanche property, and it is
 * demonstrated directly in the reference test file.
 */

/**
 * Round constants K[0..63]: first 32 bits of the fractional parts of the cube
 * roots of the first 64 primes. Another nothing-up-my-sleeve set.
 */
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** Initial state: first 32 bits of the fractional parts of sqrt of primes 2..19. */
const H_INIT = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19,
]);

/** Rotate a 32-bit word right by n bits. `>>> 0` forces unsigned 32-bit. */
function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/**
 * Apply SHA-256 padding: 0x80, then zeros, then 64-bit big-endian bit length.
 */
function pad(message: Uint8Array): Uint8Array {
  const bitLength = BigInt(message.length) * 8n;
  // +1 for the 0x80 byte, +8 for the length field; round up to a 64-byte block.
  const paddedLength = Math.ceil((message.length + 9) / 64) * 64;
  const out = new Uint8Array(paddedLength);
  out.set(message, 0);
  out[message.length] = 0x80;
  const view = new DataView(out.buffer);
  view.setBigUint64(paddedLength - 8, bitLength, false); // false = big-endian
  return out;
}

/**
 * Compute SHA-256 of `message`. Reference implementation — study only.
 */
export function referenceSha256(message: Uint8Array): Uint8Array {
  const padded = pad(message);
  const H = H_INIT.slice(); // running state, copied so H_INIT stays pristine
  const W = new Uint32Array(64); // message schedule
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);

  for (let blockStart = 0; blockStart < padded.length; blockStart += 64) {
    // ── Message schedule ──────────────────────────────────────────────────
    // The first 16 words are the block itself, big-endian.
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(blockStart + t * 4, false);
    }
    // Words 16..63 are derived by mixing four earlier words. This is what
    // spreads every input bit across all 64 rounds rather than only the
    // round its block position lands in.
    for (let t = 16; t < 64; t++) {
      const w15 = W[t - 15]!;
      const w2 = W[t - 2]!;
      const s0 = (rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3)) >>> 0;
      const s1 = (rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10)) >>> 0;
      W[t] = (W[t - 16]! + s0 + W[t - 7]! + s1) >>> 0;
    }

    // ── Compression ───────────────────────────────────────────────────────
    let [a, b, c, d, e, f, g, h] = [
      H[0]!, H[1]!, H[2]!, H[3]!, H[4]!, H[5]!, H[6]!, H[7]!,
    ];

    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[t]! + W[t]!) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    // ── Davies–Meyer feed-forward ─────────────────────────────────────────
    // Adding the pre-block state back in is what makes this one-way. Without
    // it the 64 rounds are fully invertible and SHA-256 would be a bijection.
    H[0] = (H[0]! + a) >>> 0;
    H[1] = (H[1]! + b) >>> 0;
    H[2] = (H[2]! + c) >>> 0;
    H[3] = (H[3]! + d) >>> 0;
    H[4] = (H[4]! + e) >>> 0;
    H[5] = (H[5]! + f) >>> 0;
    H[6] = (H[6]! + g) >>> 0;
    H[7] = (H[7]! + h) >>> 0;
  }

  const digest = new Uint8Array(32);
  const outView = new DataView(digest.buffer);
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, H[i]!, false);
  return digest;
}
