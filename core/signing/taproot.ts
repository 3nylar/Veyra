/**
 * BIP-341 / BIP-340 — TAPROOT KEY-PATH SIGNING
 *
 * ─── How this differs from BIP-143 ─────────────────────────────────────────
 * Both answer the same question — what does a signature commit to — but
 * Taproot's answer is broader in one important way:
 *
 *   BIP-143 (SegWit v0)   commits to THIS input's amount and script.
 *   BIP-341 (Taproot)     commits to EVERY input's amount and script.
 *
 * That difference closes a real gap. Under BIP-143, a signer knows how much
 * the input it is signing is worth, but must be told the others — so a
 * malicious PSBT could understate a co-signer's input and inflate the fee.
 * BIP-341 puts `sha_amounts` and `sha_scriptpubkeys` over all inputs into the
 * preimage, so a signer commits to the whole picture or not at all.
 *
 * ─── The preimage ──────────────────────────────────────────────────────────
 *   sighash = taggedHash("TapSighash", 0x00 ‖ sigMsg)
 *
 * where sigMsg for a key-path spend is:
 *
 *    hash_type            1    SIGHASH_DEFAULT = 0x00
 *    nVersion             4
 *    nLockTime            4
 *    sha_prevouts        32    every input's outpoint
 *    sha_amounts         32    every input's VALUE          ← new
 *    sha_scriptpubkeys   32    every input's SCRIPT         ← new
 *    sha_sequences       32
 *    sha_outputs         32
 *    spend_type           1    0 = no annex, key path
 *    input_index          4
 *
 * The leading `0x00` is the "epoch" byte from BIP-341's tagged-hash scheme —
 * a version field for the sighash format itself, so a future revision cannot
 * collide with this one.
 *
 * ─── SIGHASH_DEFAULT ───────────────────────────────────────────────────────
 * Taproot introduces 0x00, meaning SIGHASH_ALL, and — crucially — a signature
 * using it carries **no trailing type byte**. The witness is exactly 64 bytes.
 * Appending 0x00 would produce a 65-byte signature that nodes reject.
 *
 * ─── Why the witness is one item ───────────────────────────────────────────
 * P2WPKH needs a public key in the witness because the output only commits to
 * its hash. A Taproot output commits to the output key directly, so a verifier
 * already has it — nothing to reveal. The witness is the signature alone:
 *
 *     [0] 64-byte Schnorr signature
 *
 * Smaller than P2WPKH's ~108 witness bytes, which is why Taproot spends are
 * slightly cheaper.
 *
 * ─── Schnorr, not ECDSA ────────────────────────────────────────────────────
 * BIP-340 signatures are 64 bytes fixed, with no DER framing and no low-S
 * rule — both sources of malleability in ECDSA simply do not exist. Nonces are
 * derived deterministically from the key, message, and auxiliary randomness,
 * so a broken RNG cannot cause the nonce reuse that has drained ECDSA wallets.
 *
 * ─── Library boundary ──────────────────────────────────────────────────────
 * @noble/curves implements BIP-340 signing and verification.
 * Veyra is responsible for the preimage byte layout, the tweaked key, and
 * never appending a sighash byte to a SIGHASH_DEFAULT signature.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256, taggedHash } from "../crypto/hashes.js";
import { ByteWriter } from "../bitcoin/serialization.js";
import { concatBytes } from "../crypto/bytes.js";
import { tweakPrivateKey } from "../addresses/taproot.js";
import type { PrivateKey } from "../keys/privateKey.js";
import { Transaction, TxInput } from "../transactions/transaction.js";
import { VeyraError } from "../errors/index.js";

export class TaprootError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Taproot: ${reason}`);
    this.name = "TaprootError";
  }
}

/**
 * SIGHASH_DEFAULT. Means SIGHASH_ALL, and is NOT appended to the signature.
 *
 * Distinct from SIGHASH_ALL (0x01), which is still valid in Taproot but which
 * *is* appended, producing a 65-byte witness item. Veyra uses DEFAULT: fewer
 * bytes, and one less thing to get wrong.
 */
export const SIGHASH_DEFAULT = 0x00;

/** Everything BIP-341 needs about the outputs being spent. */
export interface TaprootPrevout {
  /** Value in satoshis. Committed to for EVERY input, not just this one. */
  readonly value: bigint;
  /** The scriptPubKey being spent. Also committed to for every input. */
  readonly scriptPubKey: Uint8Array;
}

/**
 * The three whole-transaction digests plus the two new ones BIP-341 adds.
 *
 * Computed once and reused across inputs, exactly as in BIP-143 — the O(n²)
 * problem is the same and the solution is the same.
 */
export class TaprootSighashCache {
  readonly shaPrevouts: Uint8Array;
  readonly shaAmounts: Uint8Array;
  readonly shaScriptPubKeys: Uint8Array;
  readonly shaSequences: Uint8Array;
  readonly shaOutputs: Uint8Array;

  constructor(transaction: Transaction, prevouts: readonly TaprootPrevout[]) {
    if (transaction.inputs.length === 0) {
      throw new TaprootError("cannot sign a transaction with no inputs");
    }
    if (prevouts.length !== transaction.inputs.length) {
      throw new TaprootError(
        `expected ${transaction.inputs.length} prevouts, received ${prevouts.length}`,
      );
    }

    // NOTE: single SHA-256 throughout, not the double SHA-256 that BIP-143
    // uses. BIP-341 changed this; using hash256 here silently produces a
    // digest no node agrees with.
    const prevouts_ = new ByteWriter();
    for (const input of transaction.inputs) prevouts_.writeBytes(input.serializeOutPoint());
    this.shaPrevouts = sha256(prevouts_.toBytes());

    const amounts = new ByteWriter();
    for (const prevout of prevouts) amounts.writeUint64LE(prevout.value);
    this.shaAmounts = sha256(amounts.toBytes());

    const scripts = new ByteWriter();
    for (const prevout of prevouts) scripts.writeVarBytes(prevout.scriptPubKey);
    this.shaScriptPubKeys = sha256(scripts.toBytes());

    const sequences = new ByteWriter();
    for (const input of transaction.inputs) sequences.writeUint32LE(input.sequence);
    this.shaSequences = sha256(sequences.toBytes());

    const outputs = new ByteWriter();
    for (const output of transaction.outputs) outputs.writeBytes(output.serialize());
    this.shaOutputs = sha256(outputs.toBytes());
  }
}

/**
 * The BIP-341 sighash for a key-path spend.
 *
 * Exposed alongside the digest so tests can inspect the exact preimage bytes —
 * verifying only the final hash tells you *that* something is wrong, never
 * *where*.
 */
export function taprootSigMsg(
  transaction: Transaction,
  inputIndex: number,
  prevouts: readonly TaprootPrevout[],
  cache?: TaprootSighashCache,
): Uint8Array {
  if (!Number.isInteger(inputIndex) || inputIndex < 0 || inputIndex >= transaction.inputs.length) {
    throw new TaprootError("input index out of range");
  }
  const digests = cache ?? new TaprootSighashCache(transaction, prevouts);

  const writer = new ByteWriter();
  writer.writeUint8(SIGHASH_DEFAULT); //          hash_type
  writer.writeUint32LE(transaction.version); //   nVersion
  writer.writeUint32LE(transaction.locktime); //  nLockTime
  writer.writeBytes(digests.shaPrevouts);
  writer.writeBytes(digests.shaAmounts); //       every input's value
  writer.writeBytes(digests.shaScriptPubKeys); // every input's script
  writer.writeBytes(digests.shaSequences);
  writer.writeBytes(digests.shaOutputs);
  // spend_type: bit 0 = annex present, bit 1 = script path. Neither here.
  writer.writeUint8(0x00);
  writer.writeUint32LE(inputIndex);
  return writer.toBytes();
}

/** The 32-byte digest a Taproot key-path signature is made over. */
export function taprootSighash(
  transaction: Transaction,
  inputIndex: number,
  prevouts: readonly TaprootPrevout[],
  cache?: TaprootSighashCache,
): Uint8Array {
  // The 0x00 epoch byte prefixes the message but is NOT part of sigMsg.
  return taggedHash(
    "TapSighash",
    concatBytes(new Uint8Array([0x00]), taprootSigMsg(transaction, inputIndex, prevouts, cache)),
  );
}

/**
 * Sign one Taproot input with the tweaked key.
 *
 * The tweak is applied here rather than by the caller, because a signature
 * made with the untweaked key verifies against the internal key and not the
 * output key the address encodes — producing an unspendable transaction that
 * looks correct until a node rejects it.
 */
export function signTaprootInput(
  transaction: Transaction,
  inputIndex: number,
  prevouts: readonly TaprootPrevout[],
  internalPrivateKey: PrivateKey,
  cache?: TaprootSighashCache,
): Uint8Array {
  const digest = taprootSighash(transaction, inputIndex, prevouts, cache);
  const tweaked = tweakPrivateKey(internalPrivateKey);
  const secret = tweaked.toBytes();
  try {
    const signature = schnorr.sign(digest, secret);
    if (signature.length !== 64) {
      throw new TaprootError(`expected a 64-byte signature, produced ${signature.length}`);
    }
    return signature;
  } finally {
    secret.fill(0);
    tweaked.destroy();
  }
}

/** Verify a Taproot key-path signature against the OUTPUT key. */
export function verifyTaprootSignature(
  digest: Uint8Array,
  signature: Uint8Array,
  outputKeyXOnly: Uint8Array,
): boolean {
  if (signature.length !== 64 || outputKeyXOnly.length !== 32) return false;
  try {
    return schnorr.verify(signature, digest, outputKeyXOnly);
  } catch {
    return false;
  }
}

/** Everything needed to sign one Taproot input. */
export interface TaprootInputToSign {
  readonly value: bigint;
  readonly scriptPubKey: Uint8Array;
  /** The INTERNAL key. Tweaking happens inside the signer. */
  readonly privateKey: PrivateKey;
}

/**
 * Sign every input of a Taproot transaction.
 *
 * Verifies each signature it produces before returning — catching a wrong key
 * or a wrong prevout value here rather than at broadcast, where the error is
 * a rejection message hours later.
 */
export function signTaprootTransaction(
  transaction: Transaction,
  inputsToSign: readonly TaprootInputToSign[],
): Transaction {
  if (transaction.inputs.length === 0) throw new TaprootError("transaction has no inputs");
  if (transaction.outputs.length === 0) throw new TaprootError("transaction has no outputs");
  if (inputsToSign.length !== transaction.inputs.length) {
    throw new TaprootError(
      `expected signing data for ${transaction.inputs.length} inputs, received ${inputsToSign.length}`,
    );
  }

  const prevouts: TaprootPrevout[] = inputsToSign.map((input) => ({
    value: input.value,
    scriptPubKey: input.scriptPubKey,
  }));
  const cache = new TaprootSighashCache(transaction, prevouts);

  let signed = transaction;
  for (let i = 0; i < transaction.inputs.length; i++) {
    const signature = signTaprootInput(
      transaction, // the ORIGINAL: witnesses are not part of the preimage
      i,
      prevouts,
      inputsToSign[i]!.privateKey,
      cache,
    );

    // Verify against the output key encoded in the scriptPubKey being spent,
    // which is what a node will check.
    const script = inputsToSign[i]!.scriptPubKey;
    if (script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) {
      throw new TaprootError(`input ${i} is not a P2TR output`);
    }
    const outputKey = script.slice(2);
    const digest = taprootSighash(transaction, i, prevouts, cache);
    if (!verifyTaprootSignature(digest, signature, outputKey)) {
      throw new TaprootError(`signature for input ${i} failed self-verification`);
    }

    signed = signed.withInput(
      i,
      new TxInput(
        signed.inputs[i]!.outpoint,
        new Uint8Array(0),
        signed.inputs[i]!.sequence,
        // ONE witness item. No public key — the output commits to it directly.
        // No trailing sighash byte — SIGHASH_DEFAULT omits it.
        [signature],
      ),
    );
  }
  return signed;
}
