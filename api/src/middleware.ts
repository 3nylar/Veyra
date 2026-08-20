/**
 * API MIDDLEWARE — authentication, rate limiting, body limits
 *
 * These three exist because §21 requires testing authentication,
 * authorization, rate limits, oversized requests, and replay. Each is
 * implemented here with the reasoning attached, because a rate limiter or an
 * auth check that looks right and is subtly wrong is worse than none — it
 * creates confidence without protection.
 */

import { timingSafeEqual, randomBytes, createHash } from "node:crypto";
import { unauthorized, rateLimited, payloadTooLarge, badRequest } from "./errors.js";
import type { IncomingMessage } from "node:http";

// ─────────────────────────────────────────────────────────────────────────
//  AUTHENTICATION
// ─────────────────────────────────────────────────────────────────────────

/**
 * Compare two secrets without leaking their contents through timing.
 *
 * ─── Why `a === b` is a vulnerability here ────────────────────────────────
 * String comparison short-circuits at the first differing byte. So comparing
 * an attacker-supplied token against the real one takes measurably longer the
 * more leading bytes match. Given enough samples, an attacker recovers the
 * token one byte at a time — 256 × 32 guesses instead of 256^32.
 *
 * This is not theoretical over a network for a fast comparison, but it is
 * entirely practical for a local attacker or a co-located tenant, and the fix
 * costs nothing.
 *
 * ─── Why hash first ───────────────────────────────────────────────────────
 * `timingSafeEqual` throws when the buffers differ in length — and that throw
 * is itself an oracle revealing the token's length. Hashing both sides to a
 * fixed 32 bytes removes the length signal entirely, and the comparison then
 * runs over equal-length buffers always.
 */
export function secretsMatch(provided: string, expected: string): boolean {
  const a = createHash("sha256").update(provided, "utf8").digest();
  const b = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(a, b);
}

/** Generate a token with 256 bits of entropy. */
export function generateApiToken(): string {
  return randomBytes(32).toString("hex");
}

export interface AuthConfig {
  /** The bearer token clients must present. */
  readonly token: string;
}

/**
 * Verify the Authorization header.
 *
 * Failures are deliberately indistinguishable: missing header, wrong scheme,
 * and wrong token all produce the same 401 with the same message. Telling an
 * attacker "wrong scheme" confirms they found the right header name; telling
 * them "invalid token" confirms the format is right.
 */
export function authenticate(request: IncomingMessage, config: AuthConfig): void {
  const header = request.headers.authorization;

  if (typeof header !== "string") throw unauthorized("no authorization header");

  const [scheme, ...rest] = header.split(" ");
  const token = rest.join(" ");

  if (scheme !== "Bearer" || token.length === 0) {
    // Still runs a comparison, so a malformed header is not measurably
    // faster to reject than a well-formed one with a wrong token.
    secretsMatch("", config.token);
    throw unauthorized("malformed authorization header");
  }
  if (!secretsMatch(token, config.token)) {
    throw unauthorized("token mismatch");
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  RATE LIMITING
// ─────────────────────────────────────────────────────────────────────────

export interface RateLimitConfig {
  readonly windowMs: number;
  readonly maxRequests: number;
}

interface Bucket {
  count: number;
  resetAt: number;
}

/**
 * A fixed-window rate limiter.
 *
 * ─── Honest about what this does and does not do ──────────────────────────
 * Fixed windows have a known flaw: a client can send `max` requests at the end
 * of one window and `max` more at the start of the next, briefly achieving
 * twice the intended rate. A sliding window or token bucket avoids this.
 *
 * We use fixed windows anyway because the threat here is casual abuse and
 * runaway clients, not a determined attacker — and because this limiter is
 * in-memory and per-process, which is a much larger limitation: it resets on
 * restart and does not coordinate across instances. Anything facing the real
 * internet needs a shared store.
 *
 * Stating both limitations is the point. A rate limiter presented as stronger
 * than it is produces exactly the false confidence §47 warns against.
 */
export class RateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(private readonly config: RateLimitConfig) {}

  /** Throws if the caller has exceeded its allowance. */
  check(key: string, now = Date.now()): void {
    this.evictExpired(now);

    const bucket = this.buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      this.buckets.set(key, { count: 1, resetAt: now + this.config.windowMs });
      return;
    }
    bucket.count++;
    if (bucket.count > this.config.maxRequests) {
      throw rateLimited(`key ${key} exceeded ${this.config.maxRequests} requests`);
    }
  }

  /**
   * Drop expired buckets.
   *
   * Without this the map grows without bound as distinct keys arrive — an
   * attacker sending one request each from many addresses would turn the rate
   * limiter itself into a memory-exhaustion vector. The defence becoming the
   * vulnerability is a classic enough pattern to guard against explicitly.
   */
  private evictExpired(now: number): void {
    if (this.buckets.size < 1000) return; // cheap: only sweep when it matters
    for (const [key, bucket] of this.buckets) {
      if (now >= bucket.resetAt) this.buckets.delete(key);
    }
  }

  reset(): void {
    this.buckets.clear();
  }

  get size(): number {
    return this.buckets.size;
  }
}

/**
 * Identify a caller for rate-limiting purposes.
 *
 * ⚠️ Uses the socket address only. `X-Forwarded-For` is deliberately IGNORED,
 * because it is client-controlled: honouring it lets an attacker spoof a new
 * identity per request and bypass the limiter entirely. Behind a trusted proxy
 * you must instead configure that proxy's address explicitly and read the
 * header only from it — not implemented here, and noted so nobody assumes it.
 */
export function callerKey(request: IncomingMessage): string {
  return request.socket.remoteAddress ?? "unknown";
}

// ─────────────────────────────────────────────────────────────────────────
//  BODY READING
// ─────────────────────────────────────────────────────────────────────────

/**
 * Read and parse a JSON body with a hard size cap.
 *
 * The cap is enforced DURING streaming, not after. Checking
 * `Content-Length` alone is insufficient — a client may lie about it, or omit
 * it entirely with chunked encoding — so we count bytes as they arrive and
 * destroy the socket the moment the limit is passed. Buffering first and
 * checking later is exactly the memory-exhaustion bug the limit exists to
 * prevent.
 */
export async function readJsonBody(
  request: IncomingMessage,
  maxBytes: number,
): Promise<unknown> {
  // Reject an obvious lie early, before reading anything.
  const declared = Number(request.headers["content-length"]);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw payloadTooLarge(`declared ${declared} bytes`);
  }

  const chunks: Buffer[] = [];
  let total = 0;

  await new Promise<void>((resolve, reject) => {
    request.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        request.destroy();
        reject(payloadTooLarge(`streamed past ${maxBytes} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve());
    request.on("error", (error) => reject(badRequest("Malformed request", error.message)));
  });

  const text = Buffer.concat(chunks).toString("utf8");
  if (text.trim().length === 0) return {};

  try {
    return JSON.parse(text);
  } catch {
    // Never echo the body back — it is attacker-controlled and may be large
    // or contain content we should not reflect.
    throw badRequest("Request body is not valid JSON");
  }
}
