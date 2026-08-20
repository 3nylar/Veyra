/**
 * API ERRORS
 *
 * ─── The rule: errors must not teach an attacker anything ──────────────────
 * §21 requires that API errors do not expose private implementation details.
 * The failure mode is subtle, because helpful errors are good engineering
 * everywhere else:
 *
 *   "Invalid signature for key m/84'/1'/0'/0/3"   ← reveals the derivation path
 *   "ENOENT: /home/veyra/.wallet/seed.dat"        ← reveals the filesystem
 *   "TypeError at Wallet.send (wallet.ts:412)"    ← reveals the stack
 *   "Unknown wallet id 7"                         ← confirms ids 1-6 exist
 *
 * The last is the important one and the least obvious. An error that
 * distinguishes "does not exist" from "not yours" is an enumeration oracle:
 * an attacker walks the id space and maps what exists. Veyra returns the same
 * 404 for both.
 *
 * ─── Two-message design ────────────────────────────────────────────────────
 * Every error carries:
 *   - `publicMessage`  sent to the client. Constant strings, no interpolation
 *                      of internal state.
 *   - `internalDetail` logged server-side only. May contain anything useful.
 *
 * Keeping them as separate fields makes the mistake hard: you cannot
 * accidentally send the internal one, because the serialiser only ever reads
 * `publicMessage`.
 */

export type ApiErrorCode =
  | "BAD_REQUEST"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "CONFLICT"
  | "PAYLOAD_TOO_LARGE"
  | "RATE_LIMITED"
  | "UNPROCESSABLE"
  | "INTERNAL";

const STATUS_BY_CODE: Record<ApiErrorCode, number> = {
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  PAYLOAD_TOO_LARGE: 413,
  RATE_LIMITED: 429,
  UNPROCESSABLE: 422,
  INTERNAL: 500,
};

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  readonly publicMessage: string;
  readonly internalDetail: string | undefined;

  constructor(code: ApiErrorCode, publicMessage: string, internalDetail?: string) {
    // `message` is the PUBLIC one, so an accidental `${error}` in a response
    // path still cannot leak internals.
    super(publicMessage);
    this.name = "ApiError";
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.publicMessage = publicMessage;
    this.internalDetail = internalDetail;
  }

  /** The exact shape sent to clients. Nothing else is ever serialised. */
  toResponse(): { error: { code: ApiErrorCode; message: string } } {
    return { error: { code: this.code, message: this.publicMessage } };
  }
}

export const badRequest = (message: string, detail?: string) =>
  new ApiError("BAD_REQUEST", message, detail);

export const unauthorized = (detail?: string) =>
  // Deliberately vague: distinguishing "no token" from "wrong token" tells an
  // attacker whether they have found a valid header format.
  new ApiError("UNAUTHORIZED", "Authentication required", detail);

export const forbidden = (detail?: string) =>
  new ApiError("FORBIDDEN", "Not permitted", detail);

export const notFound = (detail?: string) =>
  // The SAME message for "does not exist" and "not yours". Distinguishing
  // them is an enumeration oracle (IDOR reconnaissance).
  new ApiError("NOT_FOUND", "Not found", detail);

export const conflict = (message: string, detail?: string) =>
  new ApiError("CONFLICT", message, detail);

export const payloadTooLarge = (detail?: string) =>
  new ApiError("PAYLOAD_TOO_LARGE", "Request body too large", detail);

export const rateLimited = (detail?: string) =>
  new ApiError("RATE_LIMITED", "Too many requests", detail);

export const unprocessable = (message: string, detail?: string) =>
  new ApiError("UNPROCESSABLE", message, detail);

/**
 * The catch-all.
 *
 * Any error that is not an ApiError becomes this, with a constant message. An
 * unexpected `TypeError` must never reach the client — its message and stack
 * describe our internals, and in the worst case a value we were operating on.
 */
export const internalError = (detail?: string) =>
  new ApiError("INTERNAL", "Internal error", detail);

/**
 * Convert any thrown value into a safe ApiError.
 *
 * Core errors (VeyraError and friends) carry messages written to be
 * user-facing and secret-free — see core/errors/index.ts — but we do NOT
 * forward them blindly. Only an explicit allowlist of codes is surfaced;
 * everything else collapses to a generic 500 with the detail logged.
 */
const SAFE_CORE_CODES = new Set([
  "INVALID_ENCODING",
  "INVALID_PRIVATE_KEY",
  "INVALID_PUBLIC_KEY",
  "INVALID_LENGTH",
  "ENTROPY_INSUFFICIENT",
]);

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;

  const code = (error as { code?: string })?.code;
  const message = (error as Error)?.message ?? "unknown";

  if (typeof code === "string" && SAFE_CORE_CODES.has(code)) {
    // Core messages are constant strings that never interpolate secrets.
    // Still capped: a message that grew unexpectedly should not become a leak.
    return new ApiError("UNPROCESSABLE", message.slice(0, 300), message);
  }
  return internalError(`${(error as Error)?.name ?? "Error"}: ${message}`);
}
