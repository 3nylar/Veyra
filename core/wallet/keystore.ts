/**
 * ENCRYPTED KEYSTORE
 *
 * A mnemonic on disk in plaintext is readable by every process running as that
 * user, every backup that touches the directory, and anyone who later obtains
 * the drive. This encrypts it under a passphrase.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  WHAT THIS DOES AND DOES NOT PROTECT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ✅ Protects against: a stolen laptop or drive, a leaked backup, a
 *      misconfigured sync folder, another user on a shared machine, and a
 *      process that can read files but not memory.
 *
 *   ❌ Does NOT protect against: an attacker who can read this process's
 *      memory while the wallet is unlocked. Once decrypted, the seed is in the
 *      heap, and at-rest encryption is irrelevant to that.
 *
 * So this narrows the window rather than closing it, and `autoLockMs` exists
 * to make that window as small as the operator chooses.
 *
 * ─── scrypt, not PBKDF2 ────────────────────────────────────────────────────
 * A human-chosen passphrase has far less entropy than a key, so the KDF is the
 * only thing standing between a leaked file and the funds. PBKDF2 is cheap to
 * parallelise on a GPU — the attacker's advantage over the defender is
 * enormous. scrypt is *memory-hard*: each guess needs N·r·128 bytes of fast
 * memory, which is expensive to replicate thousands of times on a GPU or ASIC.
 *
 * Parameters below use N=2^17, r=8, p=1 — about 128 MB and roughly a second on
 * a normal machine. That is deliberately uncomfortable: it is the difference
 * between an offline attacker trying billions of passphrases and thousands.
 *
 * (Note the contrast with BIP-39's 2048 PBKDF2 rounds, which we cannot change
 * without breaking interoperability. Here nothing interoperates, so there is no
 * reason to inherit a 2013 parameter choice.)
 *
 * ─── Portable by construction ──────────────────────────────────────────────
 * scrypt comes from @noble/hashes and AES-GCM from WebCrypto, both of which
 * exist identically in Node, browsers, and React Native. An earlier version
 * used `node:crypto`, which made this module — and therefore the whole wallet
 * — impossible to run client-side. See docs/ATTACKS.md VEY-014.
 *
 * WebCrypto has no scrypt, only PBKDF2, which is why the KDF is not taken from
 * there: PBKDF2 is the thing we are deliberately avoiding.
 *
 * ─── AES-256-GCM, not CBC ──────────────────────────────────────────────────
 * GCM is authenticated: tampering with the ciphertext is *detected* rather
 * than producing garbage plaintext. With CBC, an attacker who can modify the
 * file can flip bits in the decrypted output — and a corrupted mnemonic that
 * still passes as text is a wallet that silently derives the wrong addresses.
 *
 * The salt, the KDF parameters, and the version are all fed in as additional
 * authenticated data, so an attacker cannot weaken the file by editing the
 * header to claim a cheaper KDF and re-submitting it.
 */

import { scryptAsync } from "@noble/hashes/scrypt.js";
import { wipe, randomBytes } from "../crypto/entropy.js";
import { bytesToBase64, base64ToBytes, concatBytes } from "../crypto/bytes.js";
import { validateMnemonic } from "../mnemonic/index.js";
import { VeyraError } from "../errors/index.js";

export class KeystoreError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Keystore: ${reason}`);
    this.name = "KeystoreError";
  }
}

/**
 * scrypt parameters.
 *
 * N=2^17, r=8, p=1 → about 128 MB and roughly one second. Stored in the file
 * so a future increase can be adopted without orphaning existing keystores.
 */
export const SCRYPT_PARAMS = Object.freeze({
  N: 131_072,
  r: 8,
  p: 1,
  keyLength: 32,
  /** Node caps scrypt memory; raise it to match N·r·128 plus headroom. */
  maxmem: 256 * 1024 * 1024,
});

/** Format version, so a future change is detectable rather than silent. */
export const KEYSTORE_VERSION = 1;

/** Minimum passphrase length. */
export const MIN_PASSPHRASE_LENGTH = 8;

export interface EncryptedKeystore {
  readonly version: number;
  readonly kdf: "scrypt";
  readonly kdfParams: { N: number; r: number; p: number };
  /** Base64. */
  readonly salt: string;
  readonly iv: string;
  readonly ciphertext: string;
  readonly authTag: string;
  /** Non-secret metadata, for identifying a file without unlocking it. */
  readonly network?: string;
  readonly fingerprint?: string;
  readonly createdAt: string;
}

/**
 * Additional authenticated data: the header.
 *
 * Binding the KDF parameters into the authentication tag means an attacker
 * cannot edit the file to claim N=2 and hand it back for a cheap decryption
 * attempt — the tag would not verify.
 */
interface AuthenticatedHeader {
  readonly version: number;
  readonly kdf: string;
  readonly kdfParams: { N: number; r: number; p: number };
  readonly salt: string;
  readonly iv: string;
}

function headerAad(store: AuthenticatedHeader): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      version: store.version,
      kdf: store.kdf,
      kdfParams: store.kdfParams,
      salt: store.salt,
      iv: store.iv,
    }),
  );
}

/**
 * The subset of WebCrypto this module uses.
 *
 * Declared structurally rather than importing DOM types: core/ targets no
 * particular runtime, and pulling in `lib.dom` to name one interface would
 * make every browser global visible to code that must not rely on them.
 */
interface SubtleLike {
  importKey(
    format: "raw",
    keyData: Uint8Array,
    algorithm: string,
    extractable: boolean,
    usages: string[],
  ): Promise<CryptoKey>;
  encrypt(
    algorithm: { name: string; iv: Uint8Array; additionalData?: Uint8Array; tagLength?: number },
    key: CryptoKey,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
  decrypt(
    algorithm: { name: string; iv: Uint8Array; additionalData?: Uint8Array; tagLength?: number },
    key: CryptoKey,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
}

/** Opaque handle; never inspected. */
type CryptoKey = object;

/** WebCrypto, or a clear failure. Never a weaker fallback. */
function subtle(): SubtleLike {
  const api = (globalThis as { crypto?: { subtle?: SubtleLike } }).crypto?.subtle;
  if (!api) {
    throw new KeystoreError(
      "WebCrypto is unavailable in this runtime; refusing to encrypt with anything weaker",
    );
  }
  return api;
}

/** Derive the encryption key. Memory-hard by design — see the header. */
async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  params: { N: number; r: number; p: number },
): Promise<Uint8Array> {
  return scryptAsync(
    new TextEncoder().encode(passphrase.normalize("NFKD")),
    salt,
    { N: params.N, r: params.r, p: params.p, dkLen: SCRYPT_PARAMS.keyLength },
  );
}

/**
 * Encrypt a mnemonic under a passphrase.
 *
 * The mnemonic is validated first: encrypting a typo'd phrase produces a file
 * that unlocks correctly and derives an empty wallet, which the user would
 * discover only when their funds appear to be missing.
 */
export async function encryptMnemonic(
  mnemonic: string,
  passphrase: string,
  metadata: { network?: string; fingerprint?: string } = {},
): Promise<EncryptedKeystore> {
  if (!validateMnemonic(mnemonic)) {
    throw new KeystoreError(
      "refusing to encrypt a mnemonic that fails its checksum — it is mistyped",
    );
  }
  if (typeof passphrase !== "string" || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new KeystoreError(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }

  const salt = randomBytes(32);
  // 96-bit IV, the size GCM is specified for. A longer one is hashed down and
  // buys nothing; a reused one with the same key is catastrophic, so it comes
  // fresh from the CSPRNG every time. (randomBytes enforces a 16-byte floor,
  // so the IV is drawn at 16 and truncated — still uniform.)
  const iv = randomBytes(16).slice(0, 12);

  const header = {
    version: KEYSTORE_VERSION,
    kdf: "scrypt" as const,
    kdfParams: { N: SCRYPT_PARAMS.N, r: SCRYPT_PARAMS.r, p: SCRYPT_PARAMS.p },
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
  };

  const key = await deriveKey(passphrase, salt, header.kdfParams);

  try {
    const cryptoKey = await subtle().importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const sealed = new Uint8Array(
      await subtle().encrypt(
        { name: "AES-GCM", iv, additionalData: headerAad(header), tagLength: 128 },
        cryptoKey,
        new TextEncoder().encode(mnemonic.normalize("NFKD")),
      ),
    );
    // WebCrypto appends the 128-bit tag to the ciphertext; Node's API returns
    // it separately. Split it so the stored format is identical either way.
    const ciphertext = sealed.slice(0, sealed.length - 16);
    const authTag = sealed.slice(sealed.length - 16);

    return {
      ...header,
      ciphertext: bytesToBase64(ciphertext),
      authTag: bytesToBase64(authTag),
      ...(metadata.network ? { network: metadata.network } : {}),
      ...(metadata.fingerprint ? { fingerprint: metadata.fingerprint } : {}),
      createdAt: new Date().toISOString(),
    };
  } finally {
    wipe(key);
  }
}

/**
 * Decrypt a keystore.
 *
 * A wrong passphrase and a tampered file both fail at the GCM tag, and both
 * produce the SAME error. Distinguishing them would tell an attacker with a
 * modified file whether their passphrase guess was right — turning one oracle
 * into two.
 */
export async function decryptMnemonic(
  store: EncryptedKeystore,
  passphrase: string,
): Promise<string> {
  if (store.version !== KEYSTORE_VERSION) {
    throw new KeystoreError(`unsupported keystore version ${store.version}`);
  }
  if (store.kdf !== "scrypt") throw new KeystoreError(`unsupported KDF '${store.kdf}'`);

  const { N, r, p } = store.kdfParams;
  // Bound the parameters from the FILE. A hostile keystore claiming N=2^30
  // would otherwise exhaust memory on any machine that opened it.
  if (!Number.isInteger(N) || N < 16384 || N > 2 ** 20) {
    throw new KeystoreError("scrypt N parameter is outside the permitted range");
  }
  if (!Number.isInteger(r) || r < 1 || r > 32) throw new KeystoreError("scrypt r out of range");
  if (!Number.isInteger(p) || p < 1 || p > 16) throw new KeystoreError("scrypt p out of range");

  const salt = base64ToBytes(store.salt);
  const iv = base64ToBytes(store.iv);
  if (salt.length < 16) throw new KeystoreError("salt is too short");
  if (iv.length !== 12) throw new KeystoreError("IV must be 12 bytes");

  const key = await deriveKey(passphrase, salt, { N, r, p });

  try {
    const cryptoKey = await subtle().importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    // WebCrypto expects the tag appended to the ciphertext.
    const sealed = concatBytes(base64ToBytes(store.ciphertext), base64ToBytes(store.authTag));

    const opened = new Uint8Array(
      await subtle().decrypt(
        {
          name: "AES-GCM",
          iv,
          // Exactly the fields encrypt() authenticated — createdAt is
          // metadata and deliberately NOT covered, so it can be edited
          // without invalidating the file.
          additionalData: headerAad({
            version: store.version,
            kdf: store.kdf,
            kdfParams: store.kdfParams,
            salt: store.salt,
            iv: store.iv,
          }),
          tagLength: 128,
        },
        cryptoKey,
        sealed,
      ),
    );
    const mnemonic = new TextDecoder().decode(opened);
    wipe(opened);

    if (!validateMnemonic(mnemonic)) {
      throw new KeystoreError("decrypted data is not a valid mnemonic");
    }
    return mnemonic;
  } catch (error) {
    if (error instanceof KeystoreError) throw error;
    // Identical message for a wrong passphrase and a tampered file. Telling
    // them apart would let an attacker with a modified file test passphrases.
    throw new KeystoreError("could not decrypt — wrong passphrase, or the file has been altered");
  } finally {
    wipe(key);
  }
}

/**
 * A keystore that holds a decrypted mnemonic for a bounded time.
 *
 * `autoLockMs` is the only control here that addresses the memory-resident
 * risk at all: it does not prevent a memory read, it shortens the interval
 * during which one succeeds. That is a real reduction and not a solution, and
 * the distinction is worth keeping in view.
 */
export class UnlockedKeystore {
  #mnemonic: string | null = null;
  #lockTimer: ReturnType<typeof setTimeout> | null = null;
  #unlockedAt = 0;

  constructor(
    private readonly store: EncryptedKeystore,
    private readonly autoLockMs: number = 15 * 60 * 1000,
  ) {}

  get isLocked(): boolean {
    return this.#mnemonic === null;
  }

  /** Milliseconds until the automatic lock, or null when locked. */
  get lockingIn(): number | null {
    if (this.isLocked) return null;
    return Math.max(0, this.#unlockedAt + this.autoLockMs - Date.now());
  }

  async unlock(passphrase: string): Promise<void> {
    const mnemonic = await decryptMnemonic(this.store, passphrase);
    this.#mnemonic = mnemonic;
    this.#unlockedAt = Date.now();

    if (this.#lockTimer) clearTimeout(this.#lockTimer);
    this.#lockTimer = setTimeout(() => this.lock(), this.autoLockMs);
    // Do not hold a Node process open just to expire a timer. Absent in
    // browsers, hence the optional call.
    (this.#lockTimer as { unref?: () => void }).unref?.();
  }

  /**
   * The decrypted mnemonic.
   *
   * Named to be greppable and uncomfortable at a call site. Every use extends
   * the window during which the secret is reachable.
   */
  readMnemonicUnsafe(): string {
    if (this.#mnemonic === null) throw new KeystoreError("keystore is locked");
    return this.#mnemonic;
  }

  /**
   * Lock, discarding the plaintext.
   *
   * ⚠️ Best-effort, for the reasons `wipe()` documents: JavaScript strings are
   * immutable and garbage-collected, so the original characters may persist in
   * the heap until collection, and may have been copied during it. This
   * removes our reference; it does not scrub memory. Claiming otherwise would
   * be exactly the overstatement this project avoids elsewhere.
   */
  lock(): void {
    this.#mnemonic = null;
    this.#unlockedAt = 0;
    if (this.#lockTimer) {
      clearTimeout(this.#lockTimer);
      this.#lockTimer = null;
    }
  }

  toString(): string {
    return `UnlockedKeystore<${this.isLocked ? "locked" : "unlocked"}>`;
  }

  toJSON(): string {
    return this.toString();
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}


