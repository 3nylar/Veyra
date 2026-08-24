/**
 * MULTISIG SIGNING — independent signers, no key reconstruction
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  THE PROPERTY THIS EXISTS TO PROVIDE
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * At no point does any machine hold enough key material to spend alone.
 *
 * Each participant signs independently, on their own device, with their own
 * key, and produces a `PartialSignature` containing a signature and the public
 * key it belongs to. Those partials are then combined into a witness. The
 * combination step handles only signatures — public data — so the machine
 * doing it needs no key at all and could be a completely untrusted coordinator.
 *
 * Contrast Shamir: to sign, shares must be recombined, and for that instant
 * one machine holds the whole key. This module has no equivalent moment,
 * because there is nothing to recombine.
 *
 * `combineSignatures` takes no private keys and cannot. That is the API
 * expressing the guarantee: you could not accidentally build a coordinator
 * that reconstructs, because the function has no parameter for it.
 *
 * ─── What each signer commits to ───────────────────────────────────────────
 * The BIP-143 sighash with the **witnessScript** as scriptCode. So every
 * signature commits to the exact spending conditions: change one public key or
 * the threshold, and every existing signature stops verifying. A participant
 * cannot be tricked into signing for a 1-of-3 arrangement they believed was
 * 2-of-3.
 *
 * ─── Signature ORDER is consensus-critical ─────────────────────────────────
 * OP_CHECKMULTISIG walks signatures and public keys in a single pass, in
 * order. It does not search. So signatures must appear in the same relative
 * order as their public keys in the script — and since BIP-67 sorts the keys,
 * that means sorted by public key.
 *
 * Out-of-order signatures produce a script failure, not a rejected signature.
 * The transaction is simply invalid, with an error that says nothing about
 * ordering. `combineSignatures` sorts for you.
 */

import { Transaction, TxInput } from "../transactions/transaction.js";
import { PrivateKey } from "../keys/privateKey.js";
import { PublicKey } from "../keys/publicKey.js";
import { sighash, SighashCache, SIGHASH_ALL } from "./sighash.js";
import { signDigestWithSighashType, verifyWitnessSignature } from "./ecdsa.js";
import { MultisigAccount } from "../addresses/multisig.js";
import { bytesToHex } from "../crypto/bytes.js";
import { VeyraError } from "../errors/index.js";

export class MultisigError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Multisig: ${reason}`);
    this.name = "MultisigError";
  }
}

/**
 * One participant's contribution.
 *
 * Contains no private material — safe to transmit over any channel, store, or
 * hand to an untrusted coordinator. That is the point: collecting these
 * requires no trust, because a signature for a specific transaction is useless
 * for anything else.
 */
export interface PartialSignature {
  /** Which input this signs. */
  readonly inputIndex: number;
  /** DER signature with the trailing sighash byte. */
  readonly signature: Uint8Array;
  /** The signer's public key, so a combiner knows where it belongs. */
  readonly publicKey: PublicKey;
}

/** What a signer needs to know about the input being spent. */
export interface MultisigInput {
  /** Value of the output being spent. Committed to by BIP-143. */
  readonly value: bigint;
  /** The multisig arrangement controlling it. */
  readonly account: MultisigAccount;
}

/**
 * Produce one participant's partial signature for one input.
 *
 * Runs on the participant's own device with only their own key. Refuses to
 * sign for an arrangement the key does not participate in — otherwise a
 * participant could be induced to sign for a script that does not include
 * them, wasting the signature and leaking that they hold the key.
 */
export function signMultisigInput(
  transaction: Transaction,
  inputIndex: number,
  input: MultisigInput,
  privateKey: PrivateKey,
  cache?: SighashCache,
): PartialSignature {
  if (!Number.isInteger(inputIndex) || inputIndex < 0 || inputIndex >= transaction.inputs.length) {
    throw new MultisigError("input index out of range");
  }

  const publicKey = PublicKey.fromPrivateKey(privateKey);
  if (!input.account.includes(publicKey)) {
    throw new MultisigError(
      "this key is not a participant in the multisig arrangement for that input",
    );
  }

  const digest = sighash(
    transaction,
    inputIndex,
    // The witnessScript IS the scriptCode. Using its hash, or a P2WPKH
    // scriptCode, produces a signature that verifies locally against nothing
    // a node will check.
    { value: input.value, scriptCode: input.account.witnessScript },
    SIGHASH_ALL,
    cache,
  );

  const signature = signDigestWithSighashType(digest, privateKey, SIGHASH_ALL);

  // Verify before returning. A participant who distributes a bad signature
  // wastes a signing round and may not find out until the coordinator fails.
  if (!verifyWitnessSignature(digest, signature, publicKey)) {
    throw new MultisigError("the signature failed self-verification");
  }
  return { inputIndex, signature, publicKey };
}

/**
 * Sign every input a key participates in.
 *
 * Inputs the key does not control are skipped silently — a transaction may
 * legitimately mix arrangements, and a participant signs only what is theirs.
 */
export function signMultisigTransaction(
  transaction: Transaction,
  inputs: readonly MultisigInput[],
  privateKey: PrivateKey,
): PartialSignature[] {
  if (inputs.length !== transaction.inputs.length) {
    throw new MultisigError(
      `expected ${transaction.inputs.length} input descriptions, received ${inputs.length}`,
    );
  }
  const cache = new SighashCache(transaction);
  const publicKey = PublicKey.fromPrivateKey(privateKey);

  const partials: PartialSignature[] = [];
  for (let i = 0; i < transaction.inputs.length; i++) {
    if (!inputs[i]!.account.includes(publicKey)) continue;
    partials.push(signMultisigInput(transaction, i, inputs[i]!, privateKey, cache));
  }
  return partials;
}

/**
 * Combine partial signatures into a spendable transaction.
 *
 * ⚠️ Takes NO private keys, and cannot. The signature is the API expressing
 * the guarantee — a coordinator that reconstructs a key is not something you
 * could build by accident here, because there is no parameter for it.
 *
 * Every signature is re-verified against the digest and the claimed public
 * key. A coordinator is untrusted by assumption, so a forged or corrupted
 * partial must be caught here rather than at broadcast.
 */
export function combineSignatures(
  transaction: Transaction,
  inputs: readonly MultisigInput[],
  partials: readonly PartialSignature[],
): Transaction {
  if (inputs.length !== transaction.inputs.length) {
    throw new MultisigError("input descriptions do not match the transaction");
  }

  const cache = new SighashCache(transaction);
  let combined = transaction;

  for (let index = 0; index < transaction.inputs.length; index++) {
    const { account, value } = inputs[index]!;
    const digest = sighash(
      transaction,
      index,
      { value, scriptCode: account.witnessScript },
      SIGHASH_ALL,
      cache,
    );

    const forThisInput = partials.filter((partial) => partial.inputIndex === index);

    // Verify each partial and reject duplicates from the same signer, which
    // would otherwise let one participant appear to satisfy the threshold
    // alone.
    const seen = new Set<string>();
    const verified: PartialSignature[] = [];

    for (const partial of forThisInput) {
      const keyHex = partial.publicKey.toHex();

      if (!account.includes(partial.publicKey)) {
        throw new MultisigError(
          `input ${index}: a signature was supplied for a key that is not a participant`,
        );
      }
      if (seen.has(keyHex)) {
        throw new MultisigError(
          `input ${index}: two signatures from the same participant — one holder ` +
            `cannot satisfy two slots of the threshold`,
        );
      }
      if (!verifyWitnessSignature(digest, partial.signature, partial.publicKey)) {
        throw new MultisigError(
          `input ${index}: a signature does not verify against the claimed public key`,
        );
      }
      seen.add(keyHex);
      verified.push(partial);
    }

    if (verified.length < account.threshold) {
      throw new MultisigError(
        `input ${index}: ${verified.length} of ${account.threshold} required signatures collected`,
      );
    }

    // ORDER: signatures must follow the public-key order in the script,
    // because OP_CHECKMULTISIG walks both in a single pass and does not
    // search. Out of order produces a script failure with no clue as to why.
    verified.sort((a, b) => account.indexOf(a.publicKey) - account.indexOf(b.publicKey));

    // Extra signatures beyond the threshold are dropped: they cost witness
    // bytes and CHECKMULTISIG would fail on a leftover.
    const used = verified.slice(0, account.threshold);

    const witness: Uint8Array[] = [
      // The dummy element. OP_CHECKMULTISIG pops one item more than it needs
      // — an off-by-one that could not be fixed without a hard fork. Omitting
      // it makes the script fail.
      new Uint8Array(0),
      ...used.map((partial) => partial.signature),
      account.witnessScript,
    ];

    combined = combined.withInput(
      index,
      new TxInput(
        combined.inputs[index]!.outpoint,
        new Uint8Array(0), // native SegWit: scriptSig stays empty
        combined.inputs[index]!.sequence,
        witness,
      ),
    );
  }
  return combined;
}

/** Progress toward a spendable transaction. */
export interface SigningProgress {
  readonly inputIndex: number;
  readonly collected: number;
  readonly required: number;
  readonly complete: boolean;
  /** Participants who have not yet signed. Public keys only. */
  readonly missing: readonly string[];
}

/**
 * How far along collection is.
 *
 * Useful for a coordinator UI: "waiting on 1 of 3". Reveals nothing secret —
 * every value here is already public in the witnessScript.
 */
export function signingProgress(
  inputs: readonly MultisigInput[],
  partials: readonly PartialSignature[],
): SigningProgress[] {
  return inputs.map((input, index) => {
    const signers = new Set(
      partials
        .filter((partial) => partial.inputIndex === index)
        .map((partial) => partial.publicKey.toHex()),
    );
    const missing = input.account.publicKeys
      .map((key) => key.toHex())
      .filter((hex) => !signers.has(hex));

    return {
      inputIndex: index,
      collected: signers.size,
      required: input.account.threshold,
      complete: signers.size >= input.account.threshold,
      missing,
    };
  });
}

/**
 * Verify a fully-combined multisig transaction.
 *
 * Checks the witness structure as well as the signatures, because a
 * structurally wrong witness — a missing dummy, a wrong script — produces a
 * transaction that verifies signature-by-signature and still fails on-chain.
 */
export function verifyMultisigTransaction(
  transaction: Transaction,
  inputs: readonly MultisigInput[],
): boolean {
  if (inputs.length !== transaction.inputs.length) return false;

  // Reconstruct the unsigned form: witnesses are not part of the preimage.
  let unsigned = transaction;
  for (let i = 0; i < transaction.inputs.length; i++) {
    unsigned = unsigned.withInput(i, transaction.inputs[i]!.withWitness([]));
  }
  const cache = new SighashCache(unsigned);

  for (let index = 0; index < transaction.inputs.length; index++) {
    const { account, value } = inputs[index]!;
    const witness = transaction.inputs[index]!.witness;

    // dummy + threshold signatures + script
    if (witness.length !== account.threshold + 2) return false;
    if (witness[0]!.length !== 0) return false; // the dummy must be empty
    if (bytesToHex(witness[witness.length - 1]!) !== bytesToHex(account.witnessScript)) {
      return false;
    }

    const digest = sighash(
      unsigned,
      index,
      { value, scriptCode: account.witnessScript },
      SIGHASH_ALL,
      cache,
    );

    // Each signature must verify against a distinct participant, in order.
    let keyPosition = 0;
    for (let s = 1; s <= account.threshold; s++) {
      const signature = witness[s]!;
      let matched = false;

      while (keyPosition < account.publicKeys.length) {
        const candidate = account.publicKeys[keyPosition]!;
        keyPosition++;
        if (verifyWitnessSignature(digest, signature, candidate)) {
          matched = true;
          break;
        }
      }
      if (!matched) return false;
    }
  }
  return true;
}
