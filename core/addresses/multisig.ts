/**
 * P2WSH MULTISIG — t-of-n, with no key ever reconstructed
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  WHY THIS AND NOT SHAMIR SECRET SHARING
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Both split control of funds across several holders. They differ in one
 * decisive respect:
 *
 *   SHAMIR   splits a single private key into shares. To sign, the shares are
 *            recombined — and for that instant, one machine holds the whole
 *            key. Compromise that machine at that moment and you have
 *            everything. The split is a storage property, not a signing one.
 *
 *   MULTISIG never combines anything. Each holder has their own independent
 *            key and produces their own independent signature. No machine, at
 *            any moment, holds enough to spend alone. The split is enforced by
 *            Bitcoin's consensus rules rather than by our discipline.
 *
 * Multisig is also *verifiable by anyone*: the spending conditions are in the
 * script, on-chain, and a node enforces them. A Shamir threshold is enforced
 * only by the software that implements it — if that software has a bug, the
 * network will happily accept a transaction signed by a reconstructed key.
 *
 * The trade-offs are real and worth stating. Multisig costs more in fees (the
 * witness carries every signature and the script), it is visible on-chain
 * before Taproot, and the participant set is fixed at address-creation time.
 * Shamir is cheaper and invisible. For a wallet whose entire argument is that
 * you should be able to verify what it does, consensus-enforced beats
 * software-enforced.
 *
 * ─── The script ────────────────────────────────────────────────────────────
 *     OP_m <pubkey_1> … <pubkey_n> OP_n OP_CHECKMULTISIG
 *
 * That is the **witnessScript**. The on-chain output commits only to its
 * SHA-256:
 *
 *     OP_0 <32-byte sha256(witnessScript)>
 *
 * The script itself is revealed in the witness when spending, which is why a
 * P2WSH output tells an observer nothing about its spending conditions until
 * it is used.
 *
 * ─── SHA-256, not HASH160 ──────────────────────────────────────────────────
 * P2WPKH uses HASH160 (20 bytes) of a public key. P2WSH uses plain SHA-256 (32
 * bytes) of the script. The extra length matters: a script is attacker-
 * influenceable in multi-party settings, and 20 bytes offers only ~80-bit
 * collision resistance — enough for someone to construct two scripts with the
 * same hash, one of which they control. 32 bytes puts that at 128 bits.
 *
 * ─── BIP-67: keys are SORTED ───────────────────────────────────────────────
 * Public keys are ordered lexicographically before going into the script.
 * Without a canonical order, three parties supplying the same three keys in
 * different orders would derive three DIFFERENT addresses — and each would
 * believe the others had the wrong one. Sorting makes the address a pure
 * function of the key set.
 *
 * ─── The OP_CHECKMULTISIG dummy element ────────────────────────────────────
 * CHECKMULTISIG pops one item more than it needs, an off-by-one in the
 * original implementation that could not be fixed without a hard fork. So
 * every witness begins with an empty element:
 *
 *     [ <empty>, sig_1, … sig_t, witnessScript ]
 *
 * Omitting it makes the script fail. It is the single most common mistake in
 * hand-written multisig code.
 */

import { PublicKey } from "../keys/publicKey.js";
import { sha256 } from "../crypto/hashes.js";
import { encodeSegwitAddress } from "./bech32.js";
import { concatBytes, bytesToHex } from "../crypto/bytes.js";
import type { Network } from "../bitcoin/networks.js";
import { DEFAULT_NETWORK } from "../bitcoin/networks.js";
import { AddressError } from "./bip84.js";

/**
 * Maximum participants.
 *
 * Consensus allows 20 in a P2WSH CHECKMULTISIG, but the witness carries every
 * public key and every signature — a 15-of-20 spend is enormous and expensive.
 * The limit is consensus's, not ours; the cost is the practical constraint.
 */
export const MAX_MULTISIG_PARTICIPANTS = 20;

/** Opcode for a small integer 1–16: OP_1 is 0x51. */
function opN(n: number): number {
  if (n < 1 || n > 16) throw new AddressError(`cannot encode ${n} as a small-integer opcode`);
  return 0x50 + n;
}

/**
 * Sort public keys lexicographically by their compressed encoding (BIP-67).
 *
 * Returns a new array; the input is untouched. Duplicate keys are rejected —
 * the same key twice would let one holder satisfy two slots of the threshold,
 * silently reducing a 2-of-3 to a 1-of-2 for that participant.
 */
export function sortPublicKeys(publicKeys: readonly PublicKey[]): PublicKey[] {
  const hexed = publicKeys.map((key) => key.toHex());
  if (new Set(hexed).size !== hexed.length) {
    throw new AddressError(
      "duplicate public key: one holder would be able to satisfy two slots of the threshold",
    );
  }
  return [...publicKeys].sort((a, b) => (a.toHex() < b.toHex() ? -1 : 1));
}

/**
 * Build the witnessScript: OP_m <pubkeys...> OP_n OP_CHECKMULTISIG.
 *
 * Keys are sorted per BIP-67 unless `preserveOrder` is set — which exists only
 * for parsing scripts created elsewhere, never for creating new ones.
 */
export function multisigWitnessScript(
  threshold: number,
  publicKeys: readonly PublicKey[],
  options: { preserveOrder?: boolean } = {},
): Uint8Array {
  const n = publicKeys.length;
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new AddressError("threshold must be at least 1");
  }
  if (threshold > n) {
    throw new AddressError(
      `threshold ${threshold} exceeds the ${n} participants, so the funds would be unspendable`,
    );
  }
  if (n > MAX_MULTISIG_PARTICIPANTS) {
    throw new AddressError(`at most ${MAX_MULTISIG_PARTICIPANTS} participants are supported`);
  }
  if (n < 2) {
    // A 1-of-1 is just a single-key wallet with extra bytes and extra fee.
    throw new AddressError("multisig requires at least 2 participants");
  }

  const keys = options.preserveOrder ? [...publicKeys] : sortPublicKeys(publicKeys);

  const parts: Uint8Array[] = [new Uint8Array([opN(threshold)])];
  for (const key of keys) {
    const bytes = key.toBytes();
    // 33 bytes is below OP_PUSHDATA1, so the length byte is the opcode.
    parts.push(new Uint8Array([bytes.length]), bytes);
  }
  parts.push(new Uint8Array([opN(n), 0xae])); // OP_n OP_CHECKMULTISIG
  return concatBytes(...parts);
}

/**
 * The on-chain scriptPubKey: OP_0 <32-byte sha256(witnessScript)>.
 *
 * SHA-256, single — not the double SHA-256 used for txids, and not HASH160.
 */
export function p2wshScriptPubKey(witnessScript: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([0x00, 0x20]), sha256(witnessScript));
}

/**
 * Encode a P2WSH address.
 *
 * Witness version 0, so **Bech32** — not Bech32m. The 32-byte program length
 * is what distinguishes P2WSH from P2WPKH's 20 bytes at the same version.
 */
export function p2wshAddress(
  witnessScript: Uint8Array,
  network: Network = DEFAULT_NETWORK,
): string {
  return encodeSegwitAddress(network.bech32Hrp, 0, sha256(witnessScript));
}

/** A configured multisig arrangement. */
export interface MultisigConfig {
  readonly threshold: number;
  readonly publicKeys: readonly PublicKey[];
  readonly network: Network;
}

export class MultisigAccount {
  readonly threshold: number;
  /** Sorted per BIP-67. Signature order must match this. */
  readonly publicKeys: readonly PublicKey[];
  readonly network: Network;
  readonly witnessScript: Uint8Array;

  constructor(config: MultisigConfig) {
    this.threshold = config.threshold;
    this.publicKeys = sortPublicKeys(config.publicKeys);
    this.network = config.network;
    this.witnessScript = multisigWitnessScript(config.threshold, this.publicKeys, {
      preserveOrder: true, // already sorted above
    });
  }

  get address(): string {
    return p2wshAddress(this.witnessScript, this.network);
  }

  get scriptPubKey(): Uint8Array {
    return p2wshScriptPubKey(this.witnessScript);
  }

  /** e.g. "2-of-3". */
  get describe(): string {
    return `${this.threshold}-of-${this.publicKeys.length}`;
  }

  /** Position of a key in the sorted set, or -1. Signatures go in this order. */
  indexOf(publicKey: PublicKey): number {
    return this.publicKeys.findIndex((key) => key.equals(publicKey));
  }

  /** Does this key participate at all? */
  includes(publicKey: PublicKey): boolean {
    return this.indexOf(publicKey) >= 0;
  }

  /**
   * Estimated witness size in vbytes, for fee calculation.
   *
   * Multisig is meaningfully more expensive than single-key, and a wallet that
   * under-estimates produces transactions that will not relay. Signatures are
   * assumed 72 bytes — the maximum — so this rounds against us.
   */
  get estimatedWitnessVsize(): number {
    const signatureBytes = this.threshold * 73; // 72 + length prefix
    const scriptBytes = this.witnessScript.length + 2; // + length prefix
    const dummyAndCount = 2;
    // Witness data is discounted to a quarter weight.
    return Math.ceil((signatureBytes + scriptBytes + dummyAndCount) / 4);
  }

  toJSON(): Record<string, unknown> {
    return {
      type: this.describe,
      address: this.address,
      network: this.network.name,
      // Public keys only. There is no private material here to leak.
      publicKeys: this.publicKeys.map((key) => key.toHex()),
      witnessScript: bytesToHex(this.witnessScript),
    };
  }
}
