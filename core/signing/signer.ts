/**
 * P2WPKH TRANSACTION SIGNING
 *
 * Wires together the sighash construction and ECDSA to produce a broadcastable
 * transaction.
 *
 * ─── The witness stack for P2WPKH ──────────────────────────────────────────
 * Exactly two items, in this order:
 *
 *     [0] signature ‖ sighash-type byte
 *     [1] compressed public key (33 bytes)
 *
 * The scriptSig stays EMPTY. That is what makes this "native" SegWit — all
 * unlocking data lives in the witness, outside the txid.
 *
 * A verifier: hashes item [1], checks it equals the 20-byte witness program
 * in the output being spent, then checks the signature in item [0] against
 * that key and the BIP-143 digest. Both must pass.
 *
 * ─── Why signing verifies its own output ───────────────────────────────────
 * `signTransaction` verifies every signature it produces before returning.
 * This is not defensive paranoia about the crypto library — it catches the
 * far more likely failure: signing with the wrong key for an input, or
 * supplying a wrong input value. Both produce a structurally perfect
 * transaction that the network silently rejects, and the user only discovers
 * it when the payment never confirms.
 *
 * Verifying at signing time converts a confusing hours-later failure into an
 * immediate, precise error.
 *
 * ─── Fee sanity is enforced here, not left to the UI ───────────────────────
 * The signer checks that inputs cover outputs, and refuses absurd fees. §16
 * of the spec requires preventing `amount + fee > balance`; this is the last
 * place that check can be enforced before an irreversible broadcast, so it
 * lives in the core rather than the interface. A UI-only check is bypassed by
 * anyone calling the API directly.
 */

import { Transaction, TxInput, MAX_MONEY } from "../transactions/transaction.js";
import { PrivateKey } from "../keys/privateKey.js";
import { PublicKey } from "../keys/publicKey.js";
import { sighash, SighashCache, SIGHASH_ALL } from "./sighash.js";
import { signDigestWithSighashType, verifyWitnessSignature, isLowS } from "./ecdsa.js";
import { VeyraError } from "../errors/index.js";

export class SigningError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Signing: ${reason}`);
    this.name = "SigningError";
  }
}

/** Everything needed to sign one input. */
export interface InputToSign {
  /** Value of the output being spent, in satoshis. Committed to by BIP-143. */
  readonly value: bigint;
  /** The key controlling this input. */
  readonly privateKey: PrivateKey;
}

/**
 * A refusal threshold, not a fee estimate.
 *
 * If the computed fee exceeds this, something is wrong — a mis-stated input
 * value, a forgotten change output. Bitcoin has no upper fee limit and no
 * confirmation step, so a fat-finger here is unrecoverable. The bound is
 * generous enough never to block a legitimate high-priority transaction.
 */
export const MAX_REASONABLE_FEE = 1_000_000n; // 0.01 BTC

/**
 * Sign every input of a P2WPKH transaction.
 *
 * @returns a new Transaction with witnesses attached. The input is unmodified.
 */
export function signTransaction(
  transaction: Transaction,
  inputsToSign: readonly InputToSign[],
): Transaction {
  if (transaction.inputs.length === 0) {
    throw new SigningError("transaction has no inputs");
  }
  if (transaction.outputs.length === 0) {
    throw new SigningError("transaction has no outputs");
  }
  if (inputsToSign.length !== transaction.inputs.length) {
    throw new SigningError(
      `expected signing data for ${transaction.inputs.length} inputs, received ${inputsToSign.length}`,
    );
  }

  // ── Value sanity, BEFORE any signature exists ────────────────────────────
  let totalIn = 0n;
  for (const input of inputsToSign) {
    if (input.value < 0n) throw new SigningError("input value cannot be negative");
    if (input.value > MAX_MONEY) throw new SigningError("input value exceeds the money supply");
    totalIn += input.value;
  }
  const totalOut = transaction.totalOutputValue();

  if (totalOut > totalIn) {
    // The §16 rule: amount + fee must not exceed spendable balance.
    throw new SigningError(
      `outputs (${totalOut} sat) exceed inputs (${totalIn} sat); insufficient funds`,
    );
  }
  const fee = totalIn - totalOut;
  if (fee > MAX_REASONABLE_FEE) {
    throw new SigningError(
      `implied fee of ${fee} sat exceeds the safety limit of ${MAX_REASONABLE_FEE} sat; ` +
        `check input values and that a change output was included`,
    );
  }

  // Computed once, reused across inputs — the O(n) property of BIP-143.
  const cache = new SighashCache(transaction);

  let signed = transaction;
  for (let i = 0; i < transaction.inputs.length; i++) {
    const { value, privateKey } = inputsToSign[i]!;
    const publicKey = PublicKey.fromPrivateKey(privateKey);

    const digest = sighash(
      transaction, // NOTE: the ORIGINAL tx. Witnesses are not part of the preimage,
      i, //          so signing input 1 must not see input 0's witness.
      { value, publicKeyHash: publicKey.hash160() },
      SIGHASH_ALL,
      cache,
    );

    const signature = signDigestWithSighashType(digest, privateKey, SIGHASH_ALL);

    // Verify what we just produced. Catches wrong-key and wrong-value bugs
    // now rather than at broadcast time.
    if (!verifyWitnessSignature(digest, signature, publicKey)) {
      throw new SigningError(`signature for input ${i} failed self-verification`);
    }
    if (!isLowS(signature.slice(0, -1))) {
      throw new SigningError(`signature for input ${i} is not low-S and would not relay`);
    }

    signed = signed.withInput(
      i,
      new TxInput(
        signed.inputs[i]!.outpoint,
        new Uint8Array(0), // scriptSig stays empty for native SegWit
        signed.inputs[i]!.sequence,
        [signature, publicKey.toBytes()],
      ),
    );
  }
  return signed;
}

/**
 * Verify every input's signature on an already-signed transaction.
 *
 * Requires the input values, since BIP-143 commits to them — which is exactly
 * why a verifier cannot be lied to about them.
 */
export function verifyTransaction(
  transaction: Transaction,
  inputValues: readonly bigint[],
): boolean {
  if (inputValues.length !== transaction.inputs.length) return false;

  // Reconstruct the unsigned form: the preimage never includes witness data.
  let unsigned = transaction;
  for (let i = 0; i < transaction.inputs.length; i++) {
    unsigned = unsigned.withInput(
      i,
      new TxInput(
        transaction.inputs[i]!.outpoint,
        transaction.inputs[i]!.scriptSig,
        transaction.inputs[i]!.sequence,
        [],
      ),
    );
  }
  const cache = new SighashCache(unsigned);

  for (let i = 0; i < transaction.inputs.length; i++) {
    const witness = transaction.inputs[i]!.witness;
    if (witness.length !== 2) return false;

    const [signature, publicKeyBytes] = witness as [Uint8Array, Uint8Array];
    let publicKey: PublicKey;
    try {
      publicKey = PublicKey.fromBytes(publicKeyBytes);
    } catch {
      return false;
    }

    const digest = sighash(
      unsigned,
      i,
      { value: inputValues[i]!, publicKeyHash: publicKey.hash160() },
      SIGHASH_ALL,
      cache,
    );
    if (!verifyWitnessSignature(digest, signature, publicKey)) return false;
  }
  return true;
}

/** The implied fee: inputs minus outputs. */
export function calculateFee(
  transaction: Transaction,
  inputValues: readonly bigint[],
): bigint {
  const totalIn = inputValues.reduce((sum, value) => sum + value, 0n);
  return totalIn - transaction.totalOutputValue();
}

/** Fee rate in satoshis per virtual byte — the unit miners actually price in. */
export function feeRate(transaction: Transaction, inputValues: readonly bigint[]): number {
  return Number(calculateFee(transaction, inputValues)) / transaction.vsize();
}
