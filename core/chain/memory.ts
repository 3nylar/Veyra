/**
 * IN-MEMORY CHAIN SOURCE
 *
 * A fully controllable `ChainSource` for tests and offline development.
 *
 * ─── Why this exists ───────────────────────────────────────────────────────
 * Testing wallet sync against a real server is slow, non-deterministic, and
 * impossible to steer into the cases that matter — a reorg, a server that
 * lies, a gap-limit boundary that falls exactly wrong. This lets a test
 * construct any chain state directly.
 *
 * ─── Why it lives in core/ rather than tests/ ──────────────────────────────
 * Because it is also useful for offline development and demos, and because
 * hiding it in the test tree tempts people to reimplement it there. It is
 * exported and documented so its limits are explicit.
 *
 * ─── ⚠️ WHAT THIS IS NOT ───────────────────────────────────────────────────
 * It is NOT a Bitcoin node. It does not validate transactions, enforce
 * consensus rules, check signatures, prevent double-spends across
 * transactions it has not been told about, or model the mempool.
 *
 * A transaction broadcast here is simply recorded. Passing here means nothing
 * about whether a real network would accept it. Anything that depends on
 * consensus validation must be tested against regtest with a real node — that
 * is §36's "Development: regtest" requirement, and this class does not
 * satisfy it.
 *
 * This limitation is stated loudly because a fake that quietly stands in for
 * consensus validation is exactly how a wallet ships a bug that every test
 * passed.
 */

import {
  ChainSource, ChainUtxo, ChainTransaction, AddressActivity, ChainError,
} from "./types.js";

interface StoredUtxo extends ChainUtxo {
  readonly address: string;
}

export class MemoryChainSource implements ChainSource {
  readonly name = "MemoryChainSource";
  readonly network: string;

  private height: number;
  private utxosByAddress = new Map<string, StoredUtxo[]>();
  private historyAddresses = new Set<string>();
  private transactionsByAddress = new Map<string, ChainTransaction[]>();

  /** Every transaction passed to `broadcast`, in order. */
  readonly broadcastLog: string[] = [];

  /** When set, `broadcast` throws this instead of succeeding. */
  broadcastError: Error | null = null;

  /**
   * When set, `broadcast` returns this txid regardless of the transaction.
   *
   * Exists to test the caller's txid-mismatch check — a server that returns
   * the wrong txid must be treated as a failed broadcast.
   */
  broadcastTxidOverride: string | null = null;

  /** Requests served, for asserting that the gap-limit scan stops early. */
  requestCount = 0;

  constructor(network = "regtest", height = 100) {
    this.network = network;
    this.height = height;
  }

  // ── Test setup ──────────────────────────────────────────────────────────

  /** Give an address a confirmed UTXO. */
  fund(address: string, txid: string, vout: number, value: bigint, confirmations = 6): this {
    if (!/^[0-9a-f]{64}$/.test(txid)) {
      throw new ChainError("txid must be 64 lowercase hex characters");
    }
    const existing = this.utxosByAddress.get(address) ?? [];
    if (existing.some((u) => u.txid === txid && u.vout === vout)) {
      throw new ChainError("that outpoint already exists");
    }
    // Spread rather than assigning `undefined`: under
    // exactOptionalPropertyTypes an optional property must be ABSENT, not
    // present-and-undefined. The distinction matters beyond the type checker
    // — `JSON.stringify` drops undefined values, so the two forms serialise
    // identically but compare differently.
    existing.push({
      address, txid, vout, value, confirmations,
      ...(confirmations > 0 ? { blockHeight: this.height - confirmations + 1 } : {}),
    });
    this.utxosByAddress.set(address, existing);
    this.historyAddresses.add(address);
    return this;
  }

  /** Mark an address as used without giving it a balance — a spent address. */
  markUsed(address: string): this {
    this.historyAddresses.add(address);
    return this;
  }

  /** Remove a UTXO, as if it had been spent. */
  spend(address: string, txid: string, vout: number): this {
    const existing = this.utxosByAddress.get(address) ?? [];
    this.utxosByAddress.set(address, existing.filter((u) => !(u.txid === txid && u.vout === vout)));
    return this;
  }

  setTransactions(address: string, transactions: ChainTransaction[]): this {
    this.transactionsByAddress.set(address, transactions);
    this.historyAddresses.add(address);
    return this;
  }

  /** Advance the tip, ageing every UTXO by the same number of blocks. */
  mine(blocks = 1): this {
    this.height += blocks;
    for (const [address, utxos] of this.utxosByAddress) {
      this.utxosByAddress.set(
        address,
        utxos.map((u) => ({ ...u, confirmations: u.confirmations + blocks })),
      );
    }
    return this;
  }

  /**
   * Simulate a reorg: drop confirmations back to zero for everything.
   *
   * Crude compared with a real reorg, but it exercises the case that matters
   * — a wallet that treated confirmed funds as final must notice they are not.
   */
  reorg(): this {
    for (const [address, utxos] of this.utxosByAddress) {
      this.utxosByAddress.set(address, utxos.map((u) => ({ ...u, confirmations: 0 })));
    }
    return this;
  }

  reset(): this {
    this.utxosByAddress.clear();
    this.historyAddresses.clear();
    this.transactionsByAddress.clear();
    this.broadcastLog.length = 0;
    this.requestCount = 0;
    this.broadcastError = null;
    this.broadcastTxidOverride = null;
    return this;
  }

  // ── ChainSource implementation ──────────────────────────────────────────

  async getBlockHeight(): Promise<number> {
    this.requestCount++;
    return this.height;
  }

  async getUtxos(address: string): Promise<ChainUtxo[]> {
    this.requestCount++;
    return (this.utxosByAddress.get(address) ?? []).map(
      ({ address: _address, ...utxo }) => utxo,
    );
  }

  async getAddressActivity(address: string): Promise<AddressActivity> {
    this.requestCount++;
    const utxos = (this.utxosByAddress.get(address) ?? []).map(
      ({ address: _address, ...utxo }) => utxo,
    );
    return { address, hasHistory: this.historyAddresses.has(address), utxos };
  }

  async getTransactions(address: string): Promise<ChainTransaction[]> {
    this.requestCount++;
    return this.transactionsByAddress.get(address) ?? [];
  }

  async broadcast(rawTxHex: string): Promise<string> {
    this.requestCount++;
    if (this.broadcastError) throw this.broadcastError;
    if (!/^[0-9a-f]+$/i.test(rawTxHex)) {
      throw new ChainError("raw transaction must be hexadecimal");
    }
    this.broadcastLog.push(rawTxHex);

    if (this.broadcastTxidOverride) return this.broadcastTxidOverride;

    // Compute the real txid so honest-path tests behave correctly.
    const { Transaction } = await import("../transactions/transaction.js");
    return Transaction.fromHex(rawTxHex).txid();
  }
}
