/**
 * Veyra error taxonomy.
 *
 * Why a dedicated error module exists:
 *
 * 1. Security. Errors thrown by the core must never carry secret material.
 *    A stack trace or an error message containing a private key, a seed, or
 *    even a partial byte range of either is a key-disclosure vulnerability.
 *    Every error in this file is constructed from *constant* strings and
 *    non-secret metadata only. There is no `error.value = privateKey` path.
 *
 * 2. Boundary discipline. The API layer (api/) must be able to map core
 *    failures onto safe HTTP responses without string-matching on messages.
 *    A stable `code` makes that mapping mechanical.
 *
 * 3. Fail-closed semantics. Cryptographic code should never return a
 *    sentinel value like `null` or `-1` for "something went wrong", because
 *    callers forget to check. Throwing is loud and unignorable.
 */

export type VeyraErrorCode =
  | "ENTROPY_UNAVAILABLE"
  | "ENTROPY_INSUFFICIENT"
  | "INVALID_PRIVATE_KEY"
  | "INVALID_PUBLIC_KEY"
  | "INVALID_LENGTH"
  | "INVALID_ENCODING";

export class VeyraError extends Error {
  readonly code: VeyraErrorCode;

  constructor(code: VeyraErrorCode, message: string) {
    super(message);
    this.name = "VeyraError";
    this.code = code;
  }
}

/** The runtime does not expose a cryptographically secure RNG. Refuse to continue. */
export class EntropyUnavailableError extends VeyraError {
  constructor() {
    super(
      "ENTROPY_UNAVAILABLE",
      "No cryptographically secure random source is available in this runtime.",
    );
    this.name = "EntropyUnavailableError";
  }
}

/** Caller asked for fewer bytes of entropy than the security policy allows. */
export class EntropyInsufficientError extends VeyraError {
  constructor(requestedBytes: number, minimumBytes: number) {
    super(
      "ENTROPY_INSUFFICIENT",
      `Requested ${requestedBytes} bytes of entropy; minimum permitted is ${minimumBytes}.`,
    );
    this.name = "EntropyInsufficientError";
  }
}

/**
 * A scalar was not a valid secp256k1 private key.
 *
 * Note what this message deliberately does NOT contain: the rejected value.
 * Logging a rejected candidate key would leak information about the RNG
 * stream, and in the worst case would log an actual key that a caller
 * mistakenly passed through the wrong function.
 */
export class InvalidPrivateKeyError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_PRIVATE_KEY", `Invalid private key: ${reason}`);
    this.name = "InvalidPrivateKeyError";
  }
}

export class InvalidPublicKeyError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_PUBLIC_KEY", `Invalid public key: ${reason}`);
    this.name = "InvalidPublicKeyError";
  }
}

export class InvalidLengthError extends VeyraError {
  constructor(what: string, expected: number, actual: number) {
    super(
      "INVALID_LENGTH",
      `${what} must be ${expected} bytes, received ${actual}.`,
    );
    this.name = "InvalidLengthError";
  }
}

export class InvalidEncodingError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Invalid encoding: ${reason}`);
    this.name = "InvalidEncodingError";
  }
}
