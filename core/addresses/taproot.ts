/**
 * BIP-86 — TAPROOT (P2TR) KEY-PATH ADDRESSES
 *
 * ─── What Taproot changes ──────────────────────────────────────────────────
 * A P2WPKH output commits to HASH160 of a public key. A Taproot output commits
 * to an x-only public key directly, with no hash in between:
 *
 *     OP_1 <32-byte x-only output key>
 *
 * That output key is not the wallet's key. It is a TWEAKED key, and the tweak
 * is what makes Taproot interesting even when — as here — no script tree is
 * used.
 *
 * ─── The tweak ─────────────────────────────────────────────────────────────
 *     P = internal public key (x-only, 32 bytes)
 *     t = taggedHash("TapTweak", P)          ← no script tree, so nothing appended
 *     Q = P + t·G                             ← the output key
 *
 * Anyone can verify Q was derived from P this way. That matters because a
 * Taproot output can commit to a script tree by appending its merkle root to
 * the tweak input — and an output with no tree is indistinguishable on-chain
 * from one with a tree that was never used. Every key-path spend looks
 * identical, whether it was a single signer, a multisig, or a complex
 * contract. That is Taproot's privacy argument, and it works only because
 * BIP-86 specifies an *empty* merkle root rather than skipping the tweak.
 *
 * ─── Why the tweak cannot be skipped ───────────────────────────────────────
 * Using P directly as the output key would be a security flaw, not merely a
 * privacy one. If a wallet ever committed to a script tree with the same
 * internal key, an attacker who learned that tree could spend via the script
 * path. Tweaking with an empty root provably commits to "there is no script",
 * so no script path exists to exploit.
 *
 * ─── x-only keys ───────────────────────────────────────────────────────────
 * Taproot drops the parity byte: keys are 32 bytes, the x coordinate alone.
 * The implicit convention is that y is EVEN. A private key whose public point
 * has odd y must therefore be negated (d → n−d) before use, and that
 * negation has to happen at two separate points — before tweaking, and again
 * if the tweaked point has odd y. Getting either wrong produces a valid-looking
 * address whose signatures never verify.
 *
 * ─── Derivation path ───────────────────────────────────────────────────────
 *     m / 86' / coin_type' / account' / change / index
 *
 * Purpose 86 rather than 84, so a wallet restoring a seed knows to look for
 * Taproot addresses. Restoring a BIP-86 seed into a BIP-84-only wallet shows
 * an empty balance — the funds are fine, the wallet is looking down the wrong
 * branch.
 *
 * ─── Library boundary ──────────────────────────────────────────────────────
 * @noble/curves provides point arithmetic and the BIP-340 tagged hash.
 * Veyra is responsible for the parity handling, the empty-merkle-root
 * convention, and never using an untweaked key as an output key.
 */

import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { ExtendedKey, HARDENED_OFFSET } from "../derivation/bip32.js";
import { PrivateKey, CURVE_ORDER } from "../keys/privateKey.js";
import { PublicKey } from "../keys/publicKey.js";
import { encodeSegwitAddress } from "./bech32.js";
import { taggedHash } from "../crypto/hashes.js";
import { bytesToBigIntBE, bigIntToBytesBE, concatBytes, bytesToHex } from "../crypto/bytes.js";
import type { Network } from "../bitcoin/networks.js";
import { DEFAULT_NETWORK } from "../bitcoin/networks.js";
import { AddressError } from "./bip84.js";
import type { DerivedAddress } from "./bip84.js";

/** BIP-86's fixed purpose field. */
export const BIP86_PURPOSE = 86;

/** Taproot outputs use witness version 1. */
export const TAPROOT_WITNESS_VERSION = 1;

/**
 * The x-only form of a compressed public key: drop the parity byte.
 *
 * Taproot's convention is that the omitted y is even. A key whose y is odd
 * still yields the same 32 bytes here — the caller is responsible for
 * negating the corresponding private key, which is what `tweakPrivateKey`
 * below does.
 */
export function toXOnly(publicKey: PublicKey): Uint8Array {
  return publicKey.toBytes().slice(1);
}

/**
 * Compute the Taproot tweak for a key-path-only output.
 *
 * `taggedHash("TapTweak", internalKey)` — with NOTHING appended, which is the
 * BIP-86 convention meaning "no script tree". Appending a merkle root here is
 * what a script-path wallet would do.
 */
export function tapTweak(internalKeyXOnly: Uint8Array): Uint8Array {
  if (internalKeyXOnly.length !== 32) {
    throw new AddressError(`internal key must be 32 bytes, received ${internalKeyXOnly.length}`);
  }
  return taggedHash("TapTweak", internalKeyXOnly);
}

/**
 * Derive the tweaked OUTPUT key: Q = P + t·G.
 *
 * Returns the x-only output key plus the parity of Q's y coordinate, which the
 * signer needs in order to negate correctly.
 */
export function tweakPublicKey(internalKeyXOnly: Uint8Array): {
  outputKey: Uint8Array;
  parity: 0 | 1;
} {
  const tweak = bytesToBigIntBE(tapTweak(internalKeyXOnly));
  if (tweak === 0n || tweak >= CURVE_ORDER) {
    // Probability ~2^-128. Refuse rather than reduce: a reduced tweak would
    // produce an address nobody else derives.
    throw new AddressError("TapTweak produced an out-of-range scalar");
  }

  // lift_x reconstructs the point with EVEN y, which is Taproot's convention.
  const internalPoint = schnorr.utils.lift_x(bytesToBigIntBE(internalKeyXOnly));
  const outputPoint = secp256k1.Point.BASE.multiply(tweak).add(internalPoint);

  outputPoint.assertValidity();
  const affine = outputPoint.toAffine();

  return {
    outputKey: bigIntToBytesBE(affine.x, 32),
    parity: affine.y % 2n === 0n ? 0 : 1,
  };
}

/**
 * Derive the tweaked PRIVATE key for a key-path spend.
 *
 * Two negations, and both are required:
 *
 *   1. If the internal point P has odd y, negate d. Taproot treats the x-only
 *      key as having even y, so the scalar must match that assumption.
 *   2. Compute d + t. If the resulting point Q has odd y, negate again — for
 *      the same reason, one level up.
 *
 * Omitting either produces a key that signs, but whose signatures verify
 * against a different output key than the address encodes. The failure is
 * silent until broadcast.
 */
export function tweakPrivateKey(privateKey: PrivateKey): PrivateKey {
  const publicKey = PublicKey.fromPrivateKey(privateKey);
  const internalKeyXOnly = toXOnly(publicKey);

  // Step 1: match the even-y convention of the x-only internal key.
  const d = publicKey.y % 2n === 0n ? privateKey.toBigInt() : CURVE_ORDER - privateKey.toBigInt();

  const tweak = bytesToBigIntBE(tapTweak(internalKeyXOnly));
  let tweaked = (d + tweak) % CURVE_ORDER;
  if (tweaked === 0n) throw new AddressError("tweaked key is zero");

  // Step 2: the tweaked point must also present as even-y.
  const { parity } = tweakPublicKey(internalKeyXOnly);
  if (parity === 1) tweaked = CURVE_ORDER - tweaked;

  return PrivateKey.fromBigInt(tweaked);
}

/**
 * The on-chain scriptPubKey: OP_1 <32-byte output key>.
 *
 * 0x51 is OP_1 (witness version 1), 0x20 pushes 32 bytes.
 */
export function p2trScriptPubKey(outputKey: Uint8Array): Uint8Array {
  if (outputKey.length !== 32) {
    throw new AddressError(`output key must be 32 bytes, received ${outputKey.length}`);
  }
  return concatBytes(new Uint8Array([0x51, 0x20]), outputKey);
}

/**
 * Encode a Taproot address.
 *
 * Witness version 1 means **Bech32m**, not Bech32 — the variant is chosen by
 * version inside `encodeSegwitAddress`, never by the caller. That is the whole
 * lesson of BIP-350.
 */
export function p2trAddress(outputKey: Uint8Array, network: Network = DEFAULT_NETWORK): string {
  // Enforced HERE as well as in the caller, because generic SegWit validation
  // does not catch it: BIP-350 permits witness programs of 2–40 bytes for
  // version 1, since future upgrades may define other lengths.
  //
  // But a version-1 program that is not 32 bytes is not Taproot. Under current
  // consensus such an output is UNENCUMBERED — anyone can spend it. Encoding
  // one would produce a valid-looking address that gives the coins away.
  if (outputKey.length !== 32) {
    throw new AddressError(
      `a Taproot output key must be exactly 32 bytes, received ${outputKey.length}. ` +
        `A version-1 output of any other length is spendable by anyone.`,
    );
  }
  return encodeSegwitAddress(network.bech32Hrp, TAPROOT_WITNESS_VERSION, outputKey);
}

/** Account path: m/86'/coin'/account' */
export function taprootAccountPath(network: Network, account = 0): string {
  if (!Number.isInteger(account) || account < 0 || account >= HARDENED_OFFSET) {
    throw new AddressError("account must be a non-negative integer below 2^31");
  }
  return `m/${BIP86_PURPOSE}'/${network.coinType}'/${account}'`;
}

/**
 * A BIP-86 Taproot account.
 *
 * Deliberately separate from `Bip84Account` rather than a mode of it. The two
 * derive from different branches, produce incompatible addresses, and sign
 * with different algorithms — merging them would create a class where a single
 * wrong flag silently produces unspendable funds.
 */
export class Bip86Account {
  readonly node: ExtendedKey;
  readonly network: Network;
  readonly account: number;
  private readonly cache = new Map<string, DerivedAddress>();
  private static readonly MAX_CACHED = 4000;

  private constructor(node: ExtendedKey, network: Network, account: number) {
    this.node = node;
    this.network = network;
    this.account = account;
  }

  static fromMasterKey(
    master: ExtendedKey,
    network: Network = DEFAULT_NETWORK,
    account = 0,
  ): Bip86Account {
    return new Bip86Account(
      master.derivePath(taprootAccountPath(network, account)),
      network,
      account,
    );
  }

  deriveAddress(chain: 0 | 1, index: number): DerivedAddress {
    if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new AddressError("address index must be a non-negative integer below 2^31");
    }
    const key = `${chain}:${index}`;
    const cached = this.cache.get(key);
    if (cached) return cached;

    const child = this.node.derive(chain).derive(index);
    const internalKeyXOnly = toXOnly(child.publicKey);
    const { outputKey } = tweakPublicKey(internalKeyXOnly);

    const derived: DerivedAddress = {
      address: p2trAddress(outputKey, this.network),
      path: `${taprootAccountPath(this.network, this.account)}/${chain}/${index}`,
      index,
      chain,
      // The INTERNAL key, not the output key. The signer needs it to
      // reconstruct the tweak, and conflating the two is the most likely way
      // to produce an unspendable address.
      publicKey: bytesToHex(internalKeyXOnly),
      scriptPubKey: bytesToHex(p2trScriptPubKey(outputKey)),
      network: this.network.name,
    };

    if (this.cache.size < Bip86Account.MAX_CACHED) this.cache.set(key, derived);
    return derived;
  }

  receiveAddress(index: number): DerivedAddress {
    return this.deriveAddress(0, index);
  }

  changeAddress(index: number): DerivedAddress {
    return this.deriveAddress(1, index);
  }

  deriveAddresses(chain: 0 | 1, start: number, count: number): DerivedAddress[] {
    if (!Number.isInteger(count) || count < 0 || count > 1000) {
      throw new AddressError("count must be an integer between 0 and 1000");
    }
    return Array.from({ length: count }, (_, i) => this.deriveAddress(chain, start + i));
  }

  get path(): string {
    return taprootAccountPath(this.network, this.account);
  }
}
