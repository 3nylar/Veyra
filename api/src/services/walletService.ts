/**
 * WALLET SERVICE
 *
 * Sits between the HTTP layer and the wallet core. Its job is to expose
 * exactly the operations §20 permits, and nothing else.
 *
 * ─── What is deliberately absent ───────────────────────────────────────────
 * There is no method here that returns a private key, a seed, a mnemonic, or
 * an extended private key. Not a guarded one, not an admin-only one, not one
 * behind a feature flag. §20 forbids those endpoints, and the most reliable
 * way to guarantee an endpoint cannot leak a secret is for the code path to
 * not exist.
 *
 * A test asserts this by reflection over the class, so adding such a method
 * later fails the suite.
 *
 * ─── The prepare/confirm split ─────────────────────────────────────────────
 * §14: "The wallet must never silently alter transaction information after
 * the user confirms it." §24: "Never immediately broadcast from the first
 * input screen."
 *
 * So sending is two steps:
 *
 *   POST /transactions/prepare  → builds and signs, returns a REVIEW plus an id
 *   POST /transactions/send     → broadcasts THAT EXACT transaction, by id
 *
 * The critical property: `send` takes an id, not transaction parameters. It
 * cannot rebuild, re-select coins, or re-derive anything. It broadcasts the
 * bytes the user reviewed or it fails. There is no code path by which the
 * amount shown at review differs from the amount broadcast.
 *
 * The alternative — send accepting `{to, amount}` again — would mean the
 * transaction is built twice, and coin selection is random, so the second
 * build would differ from the reviewed one even with an honest server.
 *
 * ─── Prepared transactions expire ──────────────────────────────────────────
 * A prepared transaction holds UTXOs that may be spent elsewhere, and a fee
 * rate that ages. Expiry bounds both, and bounds memory: without it, a client
 * that prepares repeatedly and never sends grows the map forever.
 */

import { randomBytes } from "node:crypto";
import { Wallet, type PreparedTransaction } from "../../../core/wallet/wallet.js";
import type { ChainSource } from "../../../core/chain/types.js";
import type { SelectionStrategy } from "../../../core/utxo/coinSelection.js";
import { notFound, conflict, unprocessable } from "../errors.js";

/** How long a prepared transaction remains sendable. */
export const PREPARED_TTL_MS = 5 * 60 * 1000;

/** Cap on simultaneously-held prepared transactions. */
const MAX_PENDING = 50;

interface PendingTransaction {
  readonly id: string;
  readonly prepared: PreparedTransaction;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/** The client-facing view of a wallet. Contains no key material. */
export interface WalletSummary {
  readonly network: string;
  readonly derivationPath: string;
  readonly fingerprint: string;
  readonly addressType: string;
  readonly gapLimit: number;
}

/** The review shown before sending. §16: amount, fee, total, remaining. */
export interface TransactionReview {
  readonly id: string;
  readonly expiresAt: string;
  readonly recipient: string;
  readonly amount: string;
  readonly fee: string;
  readonly total: string;
  readonly change: string;
  readonly remainingBalance: string;
  readonly feeRate: number;
  readonly vsize: number;
  readonly inputCount: number;
  readonly txid: string;
}

export class WalletService {
  private pending = new Map<string, PendingTransaction>();

  constructor(
    private readonly wallet: Wallet,
    private readonly chain?: ChainSource,
  ) {}

  summary(): WalletSummary {
    return {
      network: this.wallet.network.name,
      derivationPath: this.wallet.path,
      fingerprint: this.wallet.fingerprint,
      addressType: "P2WPKH (BIP-84)",
      gapLimit: 20,
    };
  }

  /** The current receive address. Amounts and paths only — never keys. */
  receiveAddress(): { address: string; path: string; network: string } {
    const derived = this.wallet.currentReceiveAddress();
    return {
      address: derived.address,
      path: derived.path,
      network: this.wallet.network.name,
    };
  }

  nextReceiveAddress(): { address: string; path: string; network: string } {
    const derived = this.wallet.nextReceiveAddress();
    return {
      address: derived.address,
      path: derived.path,
      network: this.wallet.network.name,
    };
  }

  /** Balance, as decimal strings so no client loses precision to a double. */
  balance(): Record<string, string | number> {
    const balance = this.wallet.balance();
    return {
      total: balance.total.toString(),
      spendable: balance.spendable.toString(),
      unconfirmed: balance.unconfirmed.toString(),
      unavailable: balance.unavailable.toString(),
      utxoCount: balance.utxoCount,
    };
  }

  /**
   * UTXOs, without derivation paths.
   *
   * The path is omitted deliberately. It is not a secret in the way a key is,
   * but it describes wallet structure and would let an observer of one
   * response correlate addresses across a wallet. The client has no use for
   * it — signing happens server-side.
   */
  utxos(): Array<Record<string, string | number | boolean>> {
    return this.wallet.utxos.all.map((utxo) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      value: utxo.value.toString(),
      address: utxo.address,
      confirmations: utxo.confirmations,
      frozen: utxo.frozen ?? false,
    }));
  }

  async sync(): Promise<{ utxos: number; addressesScanned: number }> {
    if (!this.chain) {
      throw unprocessable("No chain source is configured for this wallet");
    }
    const result = await this.wallet.sync(this.chain);
    return { utxos: result.utxos, addressesScanned: result.addressesScanned };
  }

  /**
   * Build and sign a transaction, holding it for confirmation.
   *
   * Nothing is broadcast here. The wallet's own guards (§16) run first, so an
   * overspend or a bad address fails before any signature exists.
   */
  prepare(options: {
    to: string;
    amount: bigint;
    feeRate: number;
    strategy?: SelectionStrategy;
  }): TransactionReview {
    this.evictExpired();

    if (this.pending.size >= MAX_PENDING) {
      throw conflict(
        "Too many transactions awaiting confirmation; send or wait for expiry",
      );
    }

    const prepared = this.wallet.send({
      to: options.to,
      amount: options.amount,
      feeRate: options.feeRate,
      ...(options.strategy ? { strategy: options.strategy } : {}),
    });

    // 128 bits from the CSPRNG. Sequential ids would be guessable, and a
    // guessable id lets one client confirm another's transaction — an IDOR
    // with money attached.
    const id = randomBytes(16).toString("hex");
    const now = Date.now();

    this.pending.set(id, {
      id, prepared, createdAt: now, expiresAt: now + PREPARED_TTL_MS,
    });

    return {
      id,
      expiresAt: new Date(now + PREPARED_TTL_MS).toISOString(),
      recipient: prepared.recipient,
      amount: prepared.amount.toString(),
      fee: prepared.fee.toString(),
      total: prepared.total.toString(),
      change: prepared.change.toString(),
      remainingBalance: prepared.remainingBalance.toString(),
      feeRate: Number(prepared.feeRate.toFixed(2)),
      vsize: prepared.vsize,
      inputCount: prepared.inputs.length,
      txid: prepared.txid,
    };
  }

  /**
   * Broadcast a previously prepared transaction.
   *
   * Takes ONLY an id. There is no parameter by which the recipient, amount, or
   * fee could differ from what was reviewed — the bytes were fixed at prepare
   * time and are broadcast unchanged or not at all.
   */
  async send(id: string): Promise<{ txid: string; broadcast: boolean }> {
    this.evictExpired();

    const entry = this.pending.get(id);
    // The same 404 whether the id never existed, already sent, or expired.
    // Distinguishing them would let an attacker probe for valid ids.
    if (!entry) throw notFound(`no pending transaction ${id}`);

    if (!this.chain) {
      throw unprocessable("No chain source is configured for broadcasting");
    }

    // Consumed BEFORE the network call, so a retry after a timeout cannot
    // double-broadcast. The trade-off: if broadcast fails transiently the
    // client must prepare again. Preferring a failed send over a possible
    // double send is the right way round when money is involved.
    this.pending.delete(id);

    const txid = await this.wallet.broadcast(this.chain, entry.prepared);
    return { txid, broadcast: true };
  }

  /** Review a pending transaction without sending it. */
  pendingTransaction(id: string): TransactionReview {
    this.evictExpired();
    const entry = this.pending.get(id);
    if (!entry) throw notFound(`no pending transaction ${id}`);

    return {
      id: entry.id,
      expiresAt: new Date(entry.expiresAt).toISOString(),
      recipient: entry.prepared.recipient,
      amount: entry.prepared.amount.toString(),
      fee: entry.prepared.fee.toString(),
      total: entry.prepared.total.toString(),
      change: entry.prepared.change.toString(),
      remainingBalance: entry.prepared.remainingBalance.toString(),
      feeRate: Number(entry.prepared.feeRate.toFixed(2)),
      vsize: entry.prepared.vsize,
      inputCount: entry.prepared.inputs.length,
      txid: entry.prepared.txid,
    };
  }

  /** Cancel a pending transaction. Nothing was broadcast, so nothing to undo. */
  cancel(id: string): void {
    if (!this.pending.delete(id)) throw notFound(`no pending transaction ${id}`);
  }

  /**
   * Security-relevant state (§26). Verifiable facts only.
   *
   * No "security score". A number like "92% secure" is meaningless and
   * actively harmful: it implies a measurement nobody performed and invites
   * the user to stop reading.
   */
  securityStatus(): Record<string, unknown> {
    return {
      network: this.wallet.network.name,
      isMainnet: this.wallet.network.isMainnet,
      walletType: "self-custodial HD (BIP-84)",
      keysHeldBy: "this server process, in memory only",
      chainSource: this.chain?.name ?? null,
      chainSourceIsThirdParty:
        (this.chain as { isThirdParty?: boolean })?.isThirdParty ?? null,
      privacyWarning:
        (this.chain as { privacyWarning?: string | null })?.privacyWarning ?? null,
      pendingTransactions: this.pending.size,
      warnings: this.warnings(),
    };
  }

  private warnings(): string[] {
    const warnings: string[] = [];
    if (this.wallet.network.isMainnet) {
      warnings.push("This wallet is on MAINNET. Transactions are irreversible.");
    }
    if (!this.chain) {
      warnings.push("No chain source configured; balances may be stale.");
    }
    const thirdParty = (this.chain as { isThirdParty?: boolean })?.isThirdParty;
    if (thirdParty) {
      warnings.push(
        "The configured chain source is a third party and can observe every " +
          "address in this wallet.",
      );
    }
    warnings.push(
      "Private keys are held in this process's memory. Anyone who can read " +
        "this process, or its host, can extract them.",
    );
    return warnings;
  }

  private evictExpired(now = Date.now()): void {
    for (const [id, entry] of this.pending) {
      if (now >= entry.expiresAt) this.pending.delete(id);
    }
  }

  /** Test hook. Never routed. */
  get pendingCount(): number {
    return this.pending.size;
  }
}
