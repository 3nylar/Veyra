/**
 * ══════════════════════════════════════════════════════════════════════════
 *  EDUCATIONAL REFERENCE IMPLEMENTATION — NOT A SECURITY BOUNDARY
 * ══════════════════════════════════════════════════════════════════════════
 *
 * secp256k1 elliptic-curve arithmetic in affine coordinates with BigInt.
 * Written to be read. Never imported by production code.
 *
 * ─── WHY THIS MUST NEVER SIGN ANYTHING REAL ────────────────────────────────
 * This implementation leaks the private key through timing.
 *
 * `multiply()` below is textbook double-and-add: it iterates the bits of the
 * scalar and performs an addition only when the bit is 1. So the running time
 * is proportional to the Hamming weight of the secret, and the *sequence* of
 * operations reveals the bit pattern directly to anyone who can observe
 * timing, cache behaviour, or power draw. This is not a hypothetical: it is
 * the classic simple-power-analysis attack, and it recovers keys.
 *
 * Additionally, JavaScript's BigInt is not constant-time — its operations
 * branch on operand magnitude, so even a "constant sequence" of BigInt ops
 * would still leak.
 *
 * @noble/curves solves this with projective coordinates, windowed
 * multiplication with precomputed tables, and constant-time conditional
 * selection. Veyra uses that for anything touching a real key.
 *
 * ─── WHAT IS AN ELLIPTIC CURVE? ────────────────────────────────────────────
 * For our purposes: the set of points (x, y) satisfying
 *
 *     y² = x³ + ax + b   (mod p)
 *
 * plus a special "point at infinity" O that acts as the identity element.
 * For secp256k1, a = 0 and b = 7, so:
 *
 *     y² = x³ + 7   (mod p),   p = 2²⁵⁶ − 2³² − 977
 *
 * The word "curve" is a little misleading — over a finite field this is not a
 * smooth line but a scattered cloud of roughly p discrete points.
 *
 * ─── THE GROUP LAW ─────────────────────────────────────────────────────────
 * These points form an abelian group under a geometric addition rule:
 *
 *   P + Q  (P ≠ Q): draw the line through P and Q. It meets the curve at
 *          exactly one third point; reflect that point across the x-axis.
 *   P + P:  the "line through P and P" is the tangent at P. Same reflection.
 *   P + (−P) = O, where −P is P reflected across the x-axis.
 *
 * Over a finite field the geometry is gone but the algebra survives verbatim,
 * which is what the formulas in `add()` and `double()` implement.
 *
 * ─── SCALAR MULTIPLICATION AND THE ONE-WAY PROPERTY ────────────────────────
 * Define kG = G + G + ... + G (k times). Computing kG from k is cheap:
 * double-and-add does it in ~256 doublings and ~128 additions.
 *
 * Recovering k from kG and G is the ELLIPTIC CURVE DISCRETE LOGARITHM
 * PROBLEM. No algorithm is known that does better than generic square-root
 * methods (Pollard's rho, ~sqrt(n) ≈ 2^128 operations) on a well-chosen curve
 * like secp256k1. That asymmetry — trivial forward, infeasible backward — is
 * the entire foundation of Bitcoin key ownership:
 *
 *     private key  k       (a secret integer in [1, n−1])
 *            ↓  scalar multiplication  — easy
 *     public key   K = kG  (a curve point)
 *            ↓  discrete log           — infeasible
 *     private key  k
 *
 * Note carefully: this is *conjectured* hardness, not proven. Nobody has
 * proved ECDLP is hard; we have only strong evidence that decades of effort
 * have not broken it. Shor's algorithm on a sufficiently large quantum
 * computer would break it outright.
 *
 * ─── secp256k1's PARTICULAR PROPERTIES ─────────────────────────────────────
 *   - a = 0 permits a fast endomorphism (the GLV method), roughly 25% speedup.
 *   - The parameters are not random: p and n have compact closed forms and
 *     G was published with the curve. Compared with the NIST P-256 curves,
 *     whose seeds are unexplained, secp256k1's structure is easier to argue
 *     is backdoor-free. This is a common reason cited for Bitcoin's choice.
 *   - Cofactor h = 1, meaning every point except O has order n. There are no
 *     small subgroups, so small-subgroup confinement attacks do not apply.
 *   - n < p, and n is prime.
 */

/** Field prime: 2^256 − 2^32 − 977. Coordinates live in GF(p). */
export const P = 2n ** 256n - 2n ** 32n - 977n;

/** Group order: the number of points on the curve, including O. Prime. */
export const N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** Curve coefficients: y² = x³ + Ax + B. */
export const A = 0n;
export const B = 7n;

/** Generator point G — the agreed-upon basepoint every public key derives from. */
export const Gx =
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
export const Gy =
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

/**
 * A curve point in affine coordinates. `null` represents the point at
 * infinity O (the group identity), which has no (x, y) representation.
 */
export type Point = { x: bigint; y: bigint } | null;

export const G: Point = { x: Gx, y: Gy };

/**
 * True modulo. JavaScript's `%` returns a negative result for negative
 * operands (-3n % 7n === -3n), which is wrong for field arithmetic where we
 * need a canonical representative in [0, m).
 */
export function mod(a: bigint, m: bigint = P): bigint {
  return ((a % m) + m) % m;
}

/**
 * Modular inverse via the extended Euclidean algorithm: find x with a·x ≡ 1.
 *
 * Division does not exist in a finite field; multiplying by the inverse is
 * how you divide. This is the expensive operation in affine arithmetic (~100x
 * a multiplication), and avoiding it is precisely why real implementations use
 * projective coordinates — they defer all inversions to a single one at the end.
 *
 * NOT constant-time: the loop count depends on the operand values.
 */
export function modInverse(a: bigint, m: bigint = P): bigint {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("modInverse: value is not invertible");
  return mod(old_s, m);
}

/** Is this point actually on the curve? Checks y² ≡ x³ + 7 (mod p). */
export function isOnCurve(point: Point): boolean {
  if (point === null) return true; // O is on the curve by definition
  const { x, y } = point;
  if (x < 0n || x >= P || y < 0n || y >= P) return false;
  return mod(y * y) === mod(x * x * x + A * x + B);
}

/** Point negation: reflect across the x-axis. */
export function negate(point: Point): Point {
  if (point === null) return null;
  return { x: point.x, y: mod(-point.y) };
}

/**
 * Point doubling: R = 2P, using the tangent line at P.
 *
 *   λ = (3x² + a) / (2y)          slope of the tangent (implicit differentiation)
 *   xR = λ² − 2x
 *   yR = λ(x − xR) − y            the subtraction encodes the reflection
 */
export function double(point: Point): Point {
  if (point === null) return null;
  const { x, y } = point;
  // y = 0 means the tangent is vertical: P is its own negative, so 2P = O.
  if (y === 0n) return null;

  const lambda = mod(3n * x * x + A) * modInverse(mod(2n * y)) % P;
  const xR = mod(lambda * lambda - 2n * x);
  const yR = mod(lambda * (x - xR) - y);
  return { x: xR, y: yR };
}

/**
 * Point addition: R = P + Q, using the chord through P and Q.
 *
 *   λ = (y₂ − y₁) / (x₂ − x₁)
 *   xR = λ² − x₁ − x₂
 *   yR = λ(x₁ − xR) − y₁
 */
export function add(p: Point, q: Point): Point {
  if (p === null) return q;
  if (q === null) return p;

  if (p.x === q.x) {
    // Same x: either the same point (use the tangent) or opposite points
    // (the chord is vertical and meets the curve only at infinity).
    if (mod(p.y + q.y) === 0n) return null;
    return double(p);
  }

  const lambda = mod(q.y - p.y) * modInverse(mod(q.x - p.x)) % P;
  const xR = mod(lambda * lambda - p.x - q.x);
  const yR = mod(lambda * (p.x - xR) - p.y);
  return { x: xR, y: yR };
}

/**
 * Scalar multiplication kP via double-and-add.
 *
 * ⚠️  TIMING-UNSAFE BY CONSTRUCTION. The `if (k & 1n)` branch below executes
 * an addition only on set bits, so runtime and power trace reveal the secret
 * scalar's bit pattern. Read it to understand the algorithm; never run it on
 * a key that guards funds.
 *
 * The algorithm itself: to compute 13P, write 13 = 1101₂ and accumulate
 * P + 4P + 8P by scanning bits low-to-high while repeatedly doubling.
 * O(log k) operations instead of O(k) — the difference between microseconds
 * and heat death of the universe.
 */
export function multiply(k: bigint, point: Point = G): Point {
  if (k === 0n) return null;
  if (k < 0n) return negate(multiply(-k, point));

  let result: Point = null;
  let addend: Point = point;
  let scalar = k;

  while (scalar > 0n) {
    if (scalar & 1n) result = add(result, addend);
    addend = double(addend);
    scalar >>= 1n;
  }
  return result;
}

/**
 * Derive a public key point from a private scalar: K = kG.
 *
 * Rejects k outside [1, n−1]. k = 0 would give the point at infinity (no
 * valid public key); k ≥ n wraps around, so k and k−n would produce the same
 * public key — a silent collision that breaks the one-key-one-point mapping.
 */
export function referencePublicKeyPoint(privateKey: bigint): Point {
  if (privateKey <= 0n || privateKey >= N) {
    throw new Error("private scalar out of range [1, n-1]");
  }
  return multiply(privateKey, G);
}

/**
 * SEC1 compressed encoding: 0x02 or 0x03, then the 32-byte big-endian x.
 *
 * Why 33 bytes suffice for a point that "is" two 32-byte numbers: given x,
 * y² = x³ + 7 has at most two solutions, y and p − y. Since p is odd, exactly
 * one of them is even. So one parity bit recovers y completely. The prefix
 * encodes that parity: 0x02 for even y, 0x03 for odd.
 *
 * Compressed keys are not optional in modern Bitcoin — SegWit v0 outputs
 * (BIP-143) *require* them, and using an uncompressed key produces a
 * different address for the same private key, which is a classic way to
 * "lose" funds that are in fact still there under the other encoding.
 */
export function referenceCompressPoint(point: Point): Uint8Array {
  if (point === null) throw new Error("cannot encode the point at infinity");
  const out = new Uint8Array(33);
  out[0] = point.y % 2n === 0n ? 0x02 : 0x03;
  let x = point.x;
  for (let i = 32; i >= 1; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
