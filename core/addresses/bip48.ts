/**
 * BIP-48 — MULTISIG HD ACCOUNTS
 *
 * ─── The problem this solves ───────────────────────────────────────────────
 * `MultisigAccount` takes raw public keys, which makes it a primitive rather
 * than something a person can use. Three holders would have to agree on a
 * fixed set of keys and manually produce a new set for every address — and
 * reusing one address for everything destroys the privacy that made multisig
 * worth the extra fees.
 *
 * BIP-48 fixes this by giving each participant an HD branch. They exchange
 * **account-level xpubs once**, and from then on every participant can derive
 * the same unlimited sequence of shared addresses independently, with no
 * further communication.
 *
 * ─── The path ──────────────────────────────────────────────────────────────
 *     m / 48' / coin_type' / account' / script_type' / change / index
 *                                       └─ 2' = P2WSH (native SegWit)
 *
 * Script type is its own level because a set of keys can back several
 * arrangements: 1' for P2SH-P2WSH, 2' for native P2WSH. Separating them means
 * a co-signer cannot be induced to sign for a script type they did not expect.
 *
 * Everything down to `script_type'` is HARDENED, so the account xpub cannot be
 * walked upward to the master key — which matters more here than in a
 * single-key wallet, because a multisig xpub is shared with other people by
 * design.
 *
 * ─── What an xpub reveals, and why sharing it is still correct ─────────────
 * An account xpub exposes every address in its subtree and every balance
 * attached to them. Sharing it is unavoidable — co-signers cannot derive the
 * shared addresses without it — but it means each participant can see the
 * wallet's entire history.
 *
 * That is a property of multisig, not a flaw in this implementation, and it is
 * worth stating plainly: multisig distributes *spending authority*, not
 * *visibility*. Anyone you add as a co-signer can watch everything.
 *
 * ─── The ordering problem BIP-67 solves ────────────────────────────────────
 * At each index, every participant's key is derived and the set is sorted
 * lexicographically before entering the script. Without that, three
 * participants supplying their xpubs in three different orders would derive
 * three different addresses at index 0 — each convinced the others were wrong,
 * with funds potentially sent to an address only one of them was watching.
 */

import { ExtendedKey, HARDENED_OFFSET } from "../derivation/bip32.js";
import { PublicKey } from "../keys/publicKey.js";
import { PrivateKey } from "../keys/privateKey.js";
import { MultisigAccount } from "./multisig.js";
import type { Network } from "../bitcoin/networks.js";
import { DEFAULT_NETWORK } from "../bitcoin/networks.js";
import { AddressError } from "./bip84.js";

/** BIP-48's purpose field. */
export const BIP48_PURPOSE = 48;

/** Script-type level: 2' means native P2WSH. */
export const SCRIPT_TYPE_P2WSH = 2;

/**
 * The BIP-48 account path: m/48'/coin'/account'/2'
 *
 * This is the level at which participants exchange xpubs.
 */
export function multisigAccountPath(network: Network, account = 0): string {
  if (!Number.isInteger(account) || account < 0 || account >= HARDENED_OFFSET) {
    throw new AddressError("account must be a non-negative integer below 2^31");
  }
  return `m/${BIP48_PURPOSE}'/${network.coinType}'/${account}'/${SCRIPT_TYPE_P2WSH}'`;
}

/** A co-signer, identified by their account-level extended public key. */
export interface CoSigner {
  /** Account-level xpub. Watch-only is fine and is the normal case. */
  readonly accountKey: ExtendedKey;
  /** Optional label for display. Never used in derivation. */
  readonly label?: string;
}

/**
 * A shared multisig wallet built from several participants' account keys.
 *
 * Every participant constructs this identically from the same xpubs and
 * derives the same addresses. Only the participant holding a private account
 * key can sign, and each signs only with their own.
 */
export class Bip48MultisigWallet {
  readonly threshold: number;
  readonly coSigners: readonly CoSigner[];
  readonly network: Network;
  readonly account: number;

  /** Cache of derived arrangements, keyed "chain:index". */
  private readonly cache = new Map<string, MultisigAccount>();
  private static readonly MAX_CACHED = 2000;

  constructor(config: {
    threshold: number;
    coSigners: readonly CoSigner[];
    network?: Network;
    account?: number;
  }) {
    const n = config.coSigners.length;
    if (!Number.isInteger(config.threshold) || config.threshold < 1) {
      throw new AddressError("threshold must be at least 1");
    }
    if (config.threshold > n) {
      throw new AddressError(
        `threshold ${config.threshold} exceeds the ${n} co-signers, so funds would be unspendable`,
      );
    }
    if (n < 2) throw new AddressError("multisig requires at least 2 co-signers");

    // Two participants supplying the same account key would collapse the
    // threshold: one holder could satisfy two slots. Caught here rather than
    // at address derivation, where the error would be far less obvious.
    const fingerprints = config.coSigners.map((signer) => signer.accountKey.identifier);
    if (new Set(fingerprints).size !== fingerprints.length) {
      throw new AddressError(
        "two co-signers supplied the same account key — one holder would fill two slots",
      );
    }

    this.threshold = config.threshold;
    this.coSigners = [...config.coSigners];
    this.network = config.network ?? DEFAULT_NETWORK;
    this.account = config.account ?? 0;
  }

  /**
   * Build from a set of account-level extended keys, given as strings.
   *
   * The normal setup path: each participant sends their xpub, and everyone
   * constructs the identical wallet from the collected set.
   */
  static fromExtendedKeys(config: {
    threshold: number;
    accountKeys: readonly string[];
    network?: Network;
    account?: number;
  }): Bip48MultisigWallet {
    return new Bip48MultisigWallet({
      threshold: config.threshold,
      coSigners: config.accountKeys.map((key) => ({
        accountKey: ExtendedKey.fromExtendedKey(key),
      })),
      ...(config.network ? { network: config.network } : {}),
      ...(config.account !== undefined ? { account: config.account } : {}),
    });
  }

  /** This wallet's own account key, derived from a master key. */
  static deriveAccountKey(
    master: ExtendedKey,
    network: Network = DEFAULT_NETWORK,
    account = 0,
  ): ExtendedKey {
    return master.derivePath(multisigAccountPath(network, account));
  }

  get path(): string {
    return multisigAccountPath(this.network, this.account);
  }

  get describe(): string {
    return `${this.threshold}-of-${this.coSigners.length}`;
  }

  /**
   * The multisig arrangement at one index.
   *
   * Each co-signer's key is derived at chain/index, then the set is SORTED
   * (BIP-67) before entering the script — so every participant derives the
   * same address regardless of the order they listed the xpubs.
   */
  deriveAccount(chain: 0 | 1, index: number): MultisigAccount {
    if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new AddressError("index must be a non-negative integer below 2^31");
    }
    const key = `${chain}:${index}`;
    const cached = this.cache.get(key);
    if (cached) return cached;

    const publicKeys = this.coSigners.map((signer) =>
      // Non-hardened, so a watch-only account xpub suffices. That is what
      // lets a participant derive shared addresses without holding any
      // private key at all.
      signer.accountKey.derive(chain).derive(index).publicKey,
    );

    const account = new MultisigAccount({
      threshold: this.threshold,
      publicKeys, // MultisigAccount sorts per BIP-67
      network: this.network,
    });

    if (this.cache.size < Bip48MultisigWallet.MAX_CACHED) this.cache.set(key, account);
    return account;
  }

  /** The receiving address at an index. */
  receiveAddress(index: number): { address: string; path: string; account: MultisigAccount } {
    const account = this.deriveAccount(0, index);
    return {
      address: account.address,
      path: `${this.path}/0/${index}`,
      account,
    };
  }

  changeAddress(index: number): { address: string; path: string; account: MultisigAccount } {
    const account = this.deriveAccount(1, index);
    return {
      address: account.address,
      path: `${this.path}/1/${index}`,
      account,
    };
  }

  /**
   * The private key for signing at one index, from this participant's master.
   *
   * Derives only THIS participant's key. There is no method that assembles
   * several — the co-signers' keys are public, and their private counterparts
   * live on other machines by design.
   */
  signingKey(master: ExtendedKey, chain: 0 | 1, index: number): PrivateKey {
    const path = `${multisigAccountPath(this.network, this.account)}/${chain}/${index}`;
    const node = master.derivePath(path);

    // Confirm this master actually participates, before handing back a key
    // that would produce a useless signature.
    const derived = node.publicKey;
    const account = this.deriveAccount(chain, index);
    if (!account.includes(derived)) {
      throw new AddressError(
        "this master key does not participate in the multisig arrangement at that index",
      );
    }
    return node.privateKey;
  }

  /** Which co-signer position a public key occupies, or -1. */
  positionOf(publicKey: PublicKey, chain: 0 | 1, index: number): number {
    return this.deriveAccount(chain, index).indexOf(publicKey);
  }

  /**
   * The setup record participants should compare out of band.
   *
   * ⚠️ Comparing this by a channel the coordinator does not control is the
   * only defence against a substituted xpub. An attacker who replaces one
   * participant's key with their own creates a wallet where they are a
   * co-signer — the addresses look fine, funds arrive normally, and the
   * substitution is invisible until a spend needs a signature nobody can give.
   */
  descriptor(): Record<string, unknown> {
    return {
      type: this.describe,
      path: this.path,
      network: this.network.name,
      accountKeys: this.coSigners.map((signer) => ({
        fingerprint: signer.accountKey.identifier,
        label: signer.label ?? null,
        xpub: signer.accountKey.toExtendedPublicKey(
          this.network.isMainnet ? "mainnet" : "testnet",
        ),
      })),
      firstReceiveAddress: this.receiveAddress(0).address,
    };
  }
}
