/**
 * BIP-143 — THE SEGWIT SIGNATURE HASH
 *
 * ─── What exactly does a signature commit to? ──────────────────────────────
 * This is the single most important question in a wallet, and §15 of the
 * Veyra spec demands an exact answer. Here it is.
 *
 * A signature does not sign "the transaction". It signs a 32-byte digest
 * computed over a specific, defined set of fields. Anything INSIDE that set
 * is protected — altering it invalidates the signature. Anything OUTSIDE it
 * can be changed by a third party without breaking anything.
 *
 * For SIGHASH_ALL under BIP-143, the preimage is:
 *
 *    1. nVersion            4 bytes
 *    2. hashPrevouts       32 bytes   HASH256 of all input outpoints
 *    3. hashSequence       32 bytes   HASH256 of all input sequences
 *    4. outpoint           36 bytes   THIS input's outpoint
 *    5. scriptCode        varies      the script being satisfied
 *    6. amount             8 bytes    THIS input's value        ← new in SegWit
 *    7. nSequence          4 bytes    THIS input's sequence
 *    8. hashOutputs        32 bytes   HASH256 of all outputs
 *    9. nLocktime          4 bytes
 *   10. sighash type       4 bytes
 *
 *   sighash = HASH256(preimage)
 *
 * So with SIGHASH_ALL the signature commits to: every input being spent,
 * every output being created (amounts AND destinations), this input's value,
 * the locktime, and the sighash type itself. Changing the recipient, the
 * amount, the fee, or which coins are spent all invalidate it.
 *
 * What it does NOT commit to: other inputs' signatures. That is precisely the
 * point of SegWit — signatures are outside the txid, so they cannot be used
 * to malleate it.
 *
 * ─── Why item 6 (the amount) is the critical SegWit fix ────────────────────
 * Legacy sighash did NOT include the value of the input being spent. A wallet
 * therefore had to learn input values from an external source, and could be
 * LIED TO about them.
 *
 * The attack: a compromised or malicious node tells a hardware wallet that
 * an input is worth 0.01 BTC when it is actually worth 10 BTC. The user
 * approves what looks like a small payment with a small fee. The signature is
 * valid regardless — the value was never signed. The difference, 9.99 BTC,
 * silently becomes the miner's fee. This was a real, exploited class of
 * vulnerability against hardware wallets, and BIP-143 exists substantially to
 * close it.
 *
 * Now the amount is inside the preimage. If the stated value is wrong, the
 * signature simply does not verify, and the transaction is rejected by the
 * network rather than draining the user. Veyra's `SignableInput` requires the
 * value for exactly this reason — it is not an optimisation.
 *
 * ─── Why the hashPrevouts/hashSequence/hashOutputs structure ───────────────
 * Legacy sighash re-serialised the entire transaction once PER INPUT, making
 * signing O(n²) in the number of inputs. A large transaction could take
 * minutes to validate — a denial-of-service vector against nodes.
 *
 * BIP-143 hoists the three whole-transaction digests out. They are computed
 * once and reused across every input, making the whole operation O(n).
 * Veyra caches them in `SighashCache` for the same reason.
 *
 * ─── The scriptCode for P2WPKH is deliberately odd ─────────────────────────
 * For a P2WPKH input, the scriptCode is NOT the witness program. It is the
 * equivalent LEGACY P2PKH script:
 *
 *     0x19 76 a9 14 <20-byte pubkey hash> 88 ac
 *      │   │  │  │                        │  └─ OP_CHECKSIG
 *      │   │  │  │                        └──── OP_EQUALVERIFY
 *      │   │  │  └───────────────────────────── push 20 bytes
 *      │   │  └──────────────────────────────── OP_HASH160
 *      │   └─────────────────────────────────── OP_DUP
 *      └─────────────────────────────────────── length prefix (25 bytes)
 *
 * This is specified in BIP-143 and exists so that the SegWit verification
 * path reuses the existing P2PKH script semantics. Using the witness program
 * here instead produces a valid-looking signature that no node will accept —
 * a silent, confusing failure, and a common implementation mistake.
 *
 * ─── If implemented incorrectly ────────────────────────────────────────────
 *   - Wrong field order or endianness → signature never verifies → funds
 *     stuck (recoverable: just re-sign correctly).
 *   - Committing to too LITTLE → a third party can alter the uncommitted part
 *     → funds stolen (not recoverable).
 *
 * The second is why the tests in tests/security/signature-tampering.test.ts
 * mutate every committed field and assert the signature breaks.
 */

import { hash256 } from "../crypto/hashes.js";
import { ByteWriter } from "../bitcoin/serialization.js";
import { concatBytes } from "../crypto/bytes.js";
import type { Transaction, TxInput } from "../transactions/transaction.js";
import { VeyraError } from "../errors/index.js";

export class SighashError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Sighash: ${reason}`);
    this.name = "SighashError";
  }
}

/**
 * Sighash types.
 *
 * Veyra supports SIGHASH_ALL only, and this is a deliberate restriction
 * rather than an omission. The other modes commit to less:
 *
 *   NONE          signs no outputs at all — anyone can redirect the money
 *   SINGLE        signs only the output at the same index
 *   ANYONECANPAY  signs only this input, letting others be added
 *
 * They have legitimate uses in specialised protocols (CoinJoin, atomic
 * swaps), and every one of them is a foot-cannon in a normal wallet. A
 * SIGHASH_NONE signature is a bearer instrument: anyone who sees it can spend
 * the input to themselves. Veyra does not generate them, and rejects them
 * where a type is supplied.
 */
export const SIGHASH_ALL = 0x01;
export const SIGHASH_NONE = 0x02;
export const SIGHASH_SINGLE = 0x03;
export const SIGHASH_ANYONECANPAY = 0x80;

/** An input plus the data BIP-143 requires in order to sign it. */
export interface SignableInput {
  /** The value of the output being spent, in satoshis. Committed to by the signature. */
  readonly value: bigint;
  /**
   * HASH160 of the public key controlling this input. P2WPKH only.
   *
   * Ignored when `scriptCode` is supplied.
   */
  readonly publicKeyHash?: Uint8Array;
  /**
   * An explicit scriptCode, for script-based inputs such as P2WSH multisig.
   *
   * For P2WSH the scriptCode is the **witnessScript itself** — not its hash,
   * and not wrapped in anything. That is what makes the signature commit to
   * the exact spending conditions: change one public key in a multisig script
   * and every existing signature stops verifying.
   *
   * When absent, a P2WPKH scriptCode is built from `publicKeyHash`.
   */
  readonly scriptCode?: Uint8Array;
}

/**
 * Build the P2WPKH scriptCode: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG.
 *
 * Returned WITHOUT the length prefix; the caller writes it as a varbytes.
 */
export function p2wpkhScriptCode(publicKeyHash: Uint8Array): Uint8Array {
  if (publicKeyHash.length !== 20) {
    throw new SighashError(`public key hash must be 20 bytes, received ${publicKeyHash.length}`);
  }
  return concatBytes(
    new Uint8Array([0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 PUSH20
    publicKeyHash,
    new Uint8Array([0x88, 0xac]), // OP_EQUALVERIFY OP_CHECKSIG
  );
}

/**
 * The three whole-transaction digests, computed once and reused across inputs.
 *
 * This is what makes BIP-143 signing O(n) rather than O(n²).
 */
export class SighashCache {
  readonly hashPrevouts: Uint8Array;
  readonly hashSequence: Uint8Array;
  readonly hashOutputs: Uint8Array;

  constructor(transaction: Transaction) {
    if (transaction.inputs.length === 0) {
      throw new SighashError("cannot compute a sighash for a transaction with no inputs");
    }

    // hashPrevouts = HASH256(every input's outpoint, concatenated)
    const prevouts = new ByteWriter();
    for (const input of transaction.inputs) prevouts.writeBytes(input.serializeOutPoint());
    this.hashPrevouts = hash256(prevouts.toBytes());

    // hashSequence = HASH256(every input's nSequence, concatenated)
    const sequences = new ByteWriter();
    for (const input of transaction.inputs) sequences.writeUint32LE(input.sequence);
    this.hashSequence = hash256(sequences.toBytes());

    // hashOutputs = HASH256(every output, serialised)
    const outputs = new ByteWriter();
    for (const output of transaction.outputs) outputs.writeBytes(output.serialize());
    this.hashOutputs = hash256(outputs.toBytes());
  }
}

/**
 * Build the BIP-143 preimage for one input.
 *
 * Exposed separately from `sighash()` so tests can inspect the exact bytes
 * against the published BIP-143 vectors — verifying only the final digest
 * would tell you *that* something is wrong but never *where*.
 */
export function sighashPreimage(
  transaction: Transaction,
  inputIndex: number,
  signable: SignableInput,
  sighashType: number = SIGHASH_ALL,
  cache?: SighashCache,
): Uint8Array {
  if (!Number.isInteger(inputIndex) || inputIndex < 0 || inputIndex >= transaction.inputs.length) {
    throw new SighashError("input index out of range");
  }
  if (sighashType !== SIGHASH_ALL) {
    throw new SighashError(
      "only SIGHASH_ALL is supported; other types commit to less than the full transaction",
    );
  }
  if (signable.value < 0n) {
    throw new SighashError("input value cannot be negative");
  }

  const input: TxInput = transaction.inputs[inputIndex]!;
  const digests = cache ?? new SighashCache(transaction);

  // An explicit scriptCode wins. Requiring one of the two, rather than
  // defaulting silently, means a caller cannot accidentally sign a P2WSH
  // input with a P2WPKH scriptCode — which produces a valid-looking signature
  // that no node accepts.
  if (!signable.scriptCode && !signable.publicKeyHash) {
    throw new SighashError("either scriptCode or publicKeyHash must be supplied");
  }
  const scriptCode = signable.scriptCode ?? p2wpkhScriptCode(signable.publicKeyHash!);

  const writer = new ByteWriter();
  writer.writeUint32LE(transaction.version); //  1. nVersion
  writer.writeBytes(digests.hashPrevouts); //    2. hashPrevouts
  writer.writeBytes(digests.hashSequence); //    3. hashSequence
  writer.writeBytes(input.serializeOutPoint()); // 4. this outpoint
  writer.writeVarBytes(scriptCode); //           5. scriptCode
  writer.writeUint64LE(signable.value); //       6. amount — the SegWit fix
  writer.writeUint32LE(input.sequence); //       7. this nSequence
  writer.writeBytes(digests.hashOutputs); //     8. hashOutputs
  writer.writeUint32LE(transaction.locktime); // 9. nLocktime
  writer.writeUint32LE(sighashType); //         10. sighash type
  return writer.toBytes();
}

/** The 32-byte digest a signature is made over. */
export function sighash(
  transaction: Transaction,
  inputIndex: number,
  signable: SignableInput,
  sighashType: number = SIGHASH_ALL,
  cache?: SighashCache,
): Uint8Array {
  return hash256(sighashPreimage(transaction, inputIndex, signable, sighashType, cache));
}
