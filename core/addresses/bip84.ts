/**
 * BIP-84 — NATIVE SEGWIT (P2WPKH) ADDRESSES
 *
 * ─── "A Bitcoin address is not your public key" ────────────────────────────
 * This is the misconception worth killing first. An address is a
 * human-transcribable encoding of a SCRIPT — a set of spending conditions.
 * The public key is one ingredient.
 *
 * For P2WPKH the actual on-chain output script is:
 *
 *     OP_0 <20-byte hash160(compressed pubkey)>
 *
 * and the address is that script's witness version and program, Bech32-encoded
 * with a network prefix. So:
 *
 *     public key (33 bytes)
 *        ↓  HASH160
 *     witness program (20 bytes)
 *        ↓  + witness version 0, + network HRP, + Bech32 checksum
 *     address  "tb1q..."
 *
 * The address commits to a *rule* ("whoever can produce a signature matching
 * the key with this hash may spend"), not to an identity. Other script types
 * encode entirely different rules — multisig, timelocks, arbitrary
 * conditions — using the same address machinery.
 *
 * ─── Derivation path ───────────────────────────────────────────────────────
 *
 *     m / purpose' / coin_type' / account' / change / index
 *     m /      84' /         1' /       0' /      0 /     0
 *
 *   purpose  = 84, fixed by BIP-84, meaning "native SegWit P2WPKH"
 *   coin_type= 0 mainnet, 1 all test networks (SLIP-44)
 *   account  = user-facing account separation
 *   change   = 0 receive, 1 change
 *   index    = sequential
 *
 * The first three levels are HARDENED. This is not decorative: see the attack
 * described in core/derivation/bip32.ts — leaking an account xpub plus one
 * non-hardened child private key would otherwise expose the master key and
 * every account under it. Hardening at the account level contains the blast
 * radius to a single account.
 *
 * The purpose field is what makes address types self-describing. A wallet
 * restoring a seed knows to look at m/84' for native SegWit, m/44' for legacy
 * P2PKH, m/49' for wrapped SegWit, m/86' for Taproot. Restoring a BIP-84 seed
 * into a BIP-44-only wallet shows an empty balance — the funds are fine, the
 * wallet is simply looking down the wrong branch. This is a common panic and
 * worth understanding before it happens to you.
 *
 * ─── Why P2WPKH rather than legacy or Taproot ──────────────────────────────
 * Chosen for Phase 1 because it is:
 *   - Cheaper. Witness data is discounted to 1/4 weight, so fees are lower.
 *   - Universally supported, unlike Taproot on some older services.
 *   - Free of the legacy transaction malleability issues, since signatures
 *     are moved out of the txid computation.
 *   - Simpler to sign correctly than Taproot (BIP-143 sighash vs BIP-341
 *     plus Schnorr), which matters when the goal is an implementation that
 *     can be fully explained.
 *
 * Taproot (BIP-86, Bech32m, Schnorr) is a natural later extension; the
 * Bech32m support already present in ./bech32.ts is there for that reason.
 */

import { PublicKey } from "../keys/publicKey.js";
import { ExtendedKey, HARDENED_OFFSET } from "../derivation/bip32.js";
import { encodeSegwitAddress, decodeSegwitAddress } from "./bech32.js";
import type { Network } from "../bitcoin/networks.js";
import { DEFAULT_NETWORK } from "../bitcoin/networks.js";
import { concatBytes, bytesToHex } from "../crypto/bytes.js";
import { VeyraError } from "../errors/index.js";

/** BIP-84's fixed purpose field. */
export const BIP84_PURPOSE = 84;

/** Chain: receive addresses vs change addresses. */
export const RECEIVE_CHAIN = 0;
export const CHANGE_CHAIN = 1;

export class AddressError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Address error: ${reason}`);
    this.name = "AddressError";
  }
}

/**
 * Build the BIP-84 account path: m/84'/coin'/account'
 *
 * Returned as a string so it can be logged and shown in the UI — the path is
 * not secret, and displaying it lets a user verify in another wallet exactly
 * which branch their funds are on.
 */
export function accountPath(network: Network, account = 0): string {
  if (!Number.isInteger(account) || account < 0 || account >= HARDENED_OFFSET) {
    throw new AddressError(`account must be a non-negative integer below 2^31`);
  }
  return `m/${BIP84_PURPOSE}'/${network.coinType}'/${account}'`;
}

/** Full path to a single address: m/84'/coin'/account'/change/index */
export function addressPath(
  network: Network,
  account: number,
  chain: 0 | 1,
  index: number,
): string {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
    throw new AddressError("address index must be a non-negative integer below 2^31");
  }
  return `${accountPath(network, account)}/${chain}/${index}`;
}

/**
 * The scriptPubKey actually committed to on-chain: OP_0 <20-byte hash>.
 *
 * 0x00 is OP_0 (the witness version), 0x14 is a push of 20 bytes. This is the
 * literal output script — not a representation of one. Included here so the
 * relationship between "address" and "script" is visible in code rather than
 * only described in a comment.
 */
export function p2wpkhScriptPubKey(publicKey: PublicKey): Uint8Array {
  return concatBytes(new Uint8Array([0x00, 0x14]), publicKey.hash160());
}

/** Encode a public key as a P2WPKH address for the given network. */
export function p2wpkhAddress(publicKey: PublicKey, network: Network = DEFAULT_NETWORK): string {
  return encodeSegwitAddress(network.bech32Hrp, 0, publicKey.hash160());
}

/**
 * Validate an address for a specific network.
 *
 * Returns a discriminated result rather than throwing, because this is called
 * on user input in the send flow, where a malformed address is an expected
 * condition rather than an exceptional one.
 *
 * Note that the network check is essentially free: the HRP is part of the
 * Bech32 checksum, so a mainnet address does not merely have the wrong prefix
 * when parsed as testnet — it fails the checksum outright.
 */
export function validateAddress(
  address: string,
  network: Network = DEFAULT_NETWORK,
): { valid: true; version: number; program: Uint8Array } | { valid: false; reason: string } {
  try {
    const { version, program } = decodeSegwitAddress(network.bech32Hrp, address);
    return { valid: true, version, program };
  } catch (error) {
    return { valid: false, reason: (error as Error).message };
  }
}

/**
 * A derived address together with everything needed to verify or spend it.
 *
 * Deliberately carries NO private key. An address record is displayed, logged,
 * exported to QR codes, and passed to the API — none of which should ever be
 * able to carry key material. Signing looks the key up from the path when it
 * is actually needed.
 */
export interface DerivedAddress {
  readonly address: string;
  readonly path: string;
  readonly index: number;
  readonly chain: 0 | 1;
  readonly publicKey: string;
  readonly scriptPubKey: string;
  readonly network: string;
}

/**
 * A BIP-84 account: the node at m/84'/coin'/account', from which all receive
 * and change addresses descend.
 *
 * Deriving the account node once and then deriving children from it is not
 * just an optimisation. It means the expensive hardened derivations happen a
 * single time, and it mirrors how the account xpub would be exported to a
 * watch-only service — the same node, minus the private key.
 */
export class Bip84Account {
  readonly node: ExtendedKey;
  readonly network: Network;
  readonly account: number;

  /**
   * Memoised addresses, keyed "chain:index".
   *
   * Each derivation is two EC scalar multiplications plus a HASH160. That is
   * cheap once and expensive two thousand times — a gap-limit scan against a
   * source claiming universal history derives the full bound, and on a modest
   * machine that was taking fourteen seconds.
   *
   * Caching is sound because derivation is a pure function of the account
   * node, chain, and index, none of which change over an account's lifetime.
   * The cache holds public data only: addresses, paths, and public keys. No
   * private key is derived here or retained.
   */
  private readonly cache = new Map<string, DerivedAddress>();

  /**
   * Bound on cached entries.
   *
   * Without a cap, an attacker-driven scan could grow this without limit — the
   * optimisation becoming a memory-exhaustion vector, which is the same shape
   * as the rate limiter needing eviction. 4000 covers both chains at the
   * scan bound with room to spare.
   */
  private static readonly MAX_CACHED = 4000;

  private constructor(node: ExtendedKey, network: Network, account: number) {
    this.node = node;
    this.network = network;
    this.account = account;
  }

  /**
   * Build directly from an account-level node.
   *
   * The path a watch-only wallet takes: it holds an account xpub and has no
   * master to derive from. Kept separate from `fromMasterKey` so the depth
   * expectation is explicit — a node from the wrong level derives addresses
   * nobody else will find, which is indistinguishable from lost funds.
   */
  static fromAccountNode(
    node: ExtendedKey,
    network: Network = DEFAULT_NETWORK,
    account = 0,
  ): Bip84Account {
    return new Bip84Account(node, network, account);
  }

  /** Derive the account node from a master key. */
  static fromMasterKey(
    master: ExtendedKey,
    network: Network = DEFAULT_NETWORK,
    account = 0,
  ): Bip84Account {
    const node = master.derivePath(accountPath(network, account));
    return new Bip84Account(node, network, account);
  }

  /** Derive one address on the given chain. */
  deriveAddress(chain: 0 | 1, index: number): DerivedAddress {
    if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new AddressError("address index must be a non-negative integer below 2^31");
    }

    const key = `${chain}:${index}`;
    const cached = this.cache.get(key);
    if (cached) return cached;
    // Relative derivation from the account node: chain/index, both unhardened.
    const child = this.node.derive(chain).derive(index);
    const publicKey = child.publicKey;

    const derived: DerivedAddress = {
      address: p2wpkhAddress(publicKey, this.network),
      path: addressPath(this.network, this.account, chain, index),
      index,
      chain,
      publicKey: publicKey.toHex(),
      scriptPubKey: bytesToHex(p2wpkhScriptPubKey(publicKey)),
      network: this.network.name,
    };

    if (this.cache.size < Bip84Account.MAX_CACHED) this.cache.set(key, derived);
    return derived;
  }

  receiveAddress(index: number): DerivedAddress {
    return this.deriveAddress(RECEIVE_CHAIN, index);
  }

  /**
   * A change address.
   *
   * Change goes on a separate chain (1) so that the receive-address gap-limit
   * scan is not disturbed by internal transactions, and so a watch-only
   * service can distinguish "money someone sent me" from "my own change".
   * Fresh change addresses are a privacy measure — see docs, §17 of the spec.
   */
  changeAddress(index: number): DerivedAddress {
    return this.deriveAddress(CHANGE_CHAIN, index);
  }

  /** Derive a contiguous run of addresses. */
  deriveAddresses(chain: 0 | 1, start: number, count: number): DerivedAddress[] {
    if (!Number.isInteger(count) || count < 0 || count > 1000) {
      throw new AddressError("count must be an integer between 0 and 1000");
    }
    const out: DerivedAddress[] = [];
    for (let i = 0; i < count; i++) out.push(this.deriveAddress(chain, start + i));
    return out;
  }

  /**
   * The watch-only version of this account.
   *
   * Safe to hand to a server for address generation and balance monitoring.
   * The hardening at the account level is what makes this safe: an attacker
   * with this node cannot walk UP the tree to the master key.
   */
  neutered(): Bip84Account {
    return new Bip84Account(this.node.neutered(), this.network, this.account);
  }

  get path(): string {
    return accountPath(this.network, this.account);
  }
}
