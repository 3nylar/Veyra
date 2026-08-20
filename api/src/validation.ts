/**
 * INPUT VALIDATION
 *
 * ─── Parse, don't validate ─────────────────────────────────────────────────
 * Each function here takes `unknown` and returns a precise type, or throws.
 * There is no "check then use" pattern, because that pattern lets an
 * unchecked path exist. If you have the typed value, it was validated.
 *
 * ─── Written by hand rather than with a schema library ────────────────────
 * §46 requires a reason for every dependency. A validation library would be
 * convenient, but these are about sixty lines, they are the boundary where
 * hostile input meets money arithmetic, and reading them end to end is worth
 * more than the convenience. The trade-off is real — a library would be
 * better tested than this code — and it is why the API test suite attacks
 * these functions directly with malformed input.
 *
 * ─── Rejecting rather than coercing ────────────────────────────────────────
 * `"100"` is not accepted where a number is expected. `1e3` is not accepted as
 * an amount. Coercion feels helpful and hides bugs: a client sending a string
 * where it meant a number has a bug, and silently accepting it means that bug
 * surfaces later, somewhere less obvious, possibly after money moved.
 */

import { badRequest } from "./errors.js";

/** The object at the top of a request body, or reject. */
export function asObject(value: unknown, context = "body"): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw badRequest(`Expected ${context} to be a JSON object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Reject any key not on the allowlist.
 *
 * Unknown fields are an error, not something to ignore. Ignoring them means a
 * client that misspells `amount` as `ammount` gets a confusing downstream
 * failure instead of a clear one — and it is how mass-assignment bugs happen
 * when a field later gains meaning.
 */
export function rejectUnknownKeys(
  body: Record<string, unknown>,
  allowed: readonly string[],
): void {
  const unknown = Object.keys(body).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    // Echoing the KEY NAMES is safe: they came from the client and contain no
    // server state. Values are never echoed.
    throw badRequest(
      `Unexpected field${unknown.length > 1 ? "s" : ""}: ${unknown.slice(0, 5).map(sanitizeForMessage).join(", ")}`,
    );
  }
}

/**
 * Make a client-supplied string safe to include in an error message.
 *
 * Truncates and strips control characters. A field name containing newlines or
 * ANSI escapes could otherwise forge log entries — log injection is a real
 * technique for hiding an attack in plain sight.
 */
function sanitizeForMessage(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, "?").slice(0, 40);
}

export function requireString(
  body: Record<string, unknown>,
  field: string,
  options: { maxLength?: number; pattern?: RegExp } = {},
): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw badRequest(`Field '${field}' must be a string`);
  }
  const maxLength = options.maxLength ?? 1000;
  if (value.length === 0) throw badRequest(`Field '${field}' must not be empty`);
  if (value.length > maxLength) {
    throw badRequest(`Field '${field}' exceeds ${maxLength} characters`);
  }
  if (options.pattern && !options.pattern.test(value)) {
    // Note what is NOT included: the offending value. An error that echoes
    // input invites using the API as a reflection gadget.
    throw badRequest(`Field '${field}' has an invalid format`);
  }
  return value;
}

/**
 * A satoshi amount.
 *
 * Accepts a JSON number or a decimal string, and returns BigInt. Strings are
 * accepted because JSON numbers above 2^53 lose precision silently — a client
 * dealing in large amounts SHOULD send a string, and refusing to accept one
 * would force it into the lossy path.
 */
export function requireSatoshis(body: Record<string, unknown>, field: string): bigint {
  const value = body[field];

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw badRequest(
        `Field '${field}' must be a whole number of satoshis; ` +
          `send a string for values above 2^53`,
      );
    }
    if (value < 0) throw badRequest(`Field '${field}' must not be negative`);
    return BigInt(value);
  }

  if (typeof value === "string") {
    // Strict: no signs, no exponents, no whitespace, no leading '+'.
    if (!/^\d+$/.test(value)) {
      throw badRequest(`Field '${field}' must be a whole number of satoshis`);
    }
    if (value.length > 20) throw badRequest(`Field '${field}' is implausibly large`);
    return BigInt(value);
  }

  throw badRequest(`Field '${field}' must be a number or a decimal string`);
}

export function requireNumber(
  body: Record<string, unknown>,
  field: string,
  options: { min?: number; max?: number; integer?: boolean } = {},
): number {
  const value = body[field];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw badRequest(`Field '${field}' must be a finite number`);
  }
  if (options.integer && !Number.isInteger(value)) {
    throw badRequest(`Field '${field}' must be an integer`);
  }
  if (options.min !== undefined && value < options.min) {
    throw badRequest(`Field '${field}' must be at least ${options.min}`);
  }
  if (options.max !== undefined && value > options.max) {
    throw badRequest(`Field '${field}' must be at most ${options.max}`);
  }
  return value;
}

export function optionalEnum<T extends string>(
  body: Record<string, unknown>,
  field: string,
  allowed: readonly T[],
): T | undefined {
  const value = body[field];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw badRequest(`Field '${field}' must be one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

/**
 * A Bitcoin address, shape-checked only.
 *
 * Real validation — checksum, network, witness version — happens in the core
 * address module. This exists so obviously hostile input never reaches it, and
 * so path traversal or injection attempts are rejected at the edge.
 */
export function requireAddress(body: Record<string, unknown>, field: string): string {
  return requireString(body, field, { maxLength: 100, pattern: /^[a-zA-Z0-9]+$/ });
}

/** An opaque server-issued identifier. */
export function requireId(body: Record<string, unknown>, field: string): string {
  return requireString(body, field, { maxLength: 64, pattern: /^[a-f0-9]{32,64}$/ });
}
