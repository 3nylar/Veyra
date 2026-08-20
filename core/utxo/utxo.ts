/**
 * UTXOs — UNSPENT TRANSACTION OUTPUTS
 *
 * ─── What a wallet balance actually is ─────────────────────────────────────
 * A wallet does not have a balance. It has a *set of coins*, each of a fixed,
 * indivisible size, each locked to a specific address. The "balance" is a
 * derived number — the sum of the set — and treating it as the primary object
 * is the mistake that makes Bitcoin wallets confusing.
 *
 * Consequences that follow directly, and surprise people:
 *
 *   - You can have a balance of 1 BTC and be unable to send 0.6 BTC without
 *     paying fees on multiple inputs, if that 1 BTC is a hundred 0.01 coins.
 *   - You can have "enough" and still fail, because the fee to spend many
 *     small coins exceeds their value.
 *   - Spending always creates change; the number of coins in your wallet is
 *     constantly churning.
 *
 * ─── Confirmations ─────────────────────────────────────────────────────────
 * An unconfirmed UTXO exists but can vanish — the transaction that created it
 * may be replaced (RBF), evicted from mempools, or reorganised out. A UTXO
 * from a coinbase transaction is unspendable for 100 blocks by consensus.
 *
 * Veyra distinguishes these explicitly rather than presenting one number,
 * because "your balance is X" when part of X can disappear is a lie the user
 * will discover at the worst moment. See `Balance` below.
 *
 * ─── The dust threshold ────────────────────────────────────────────────────
 * An output whose value is less than the cost of eventually spending it is
 * "dust". Bitcoin Core's relay policy rejects transactions creating such
 * outputs, because they bloat the UTXO set every node must keep in memory
 * forever, for no economic purpose.
 *
 * For P2WPKH the threshold is 294 satoshis. The derivation: an output is dust
 * if `value < 3 × (cost to spend it at the dust fee rate)`. Veyra treats this
 * as a hard floor — creating a dust output produces a transaction that will
 * not relay, which looks to the user like a wallet that silently does nothing.
 *
 * ─── Frozen UTXOs ──────────────────────────────────────────────────────────
 * Users may wish to exclude specific coins from spending — for privacy (a
 * coin with a known association), or because it is disputed. Support for this
 * lives in the model rather than the UI, because a UI-only filter is bypassed
 * by anything calling the core directly.
 */

import { VeyraError } from "../errors/index.js";

export class UtxoError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `UTXO: ${reason}`);
    this.name = "UtxoError";
  }
}

/**
 * Dust threshold for a P2WPKH output, in satoshis.
 *
 * Bitcoin Core: an output is dust if its value is below three times the fee
 * to spend it, computed at the dust relay rate of 3000 sat/kvB. A P2WPKH
 * input costs 68 vbytes, plus the 31 vbytes of the output itself:
 *
 *     (68 + 31) vbytes × 3 sat/vB = 297  →  Core's P2WPKH figure is 294
 *
 * We use Core's published value rather than our own arithmetic, because what
 * matters is what the network will actually relay, not what we compute.
 */
export const DUST_THRESHOLD_P2WPKH = 294n;

/** Blocks a coinbase output must age before it is spendable. Consensus rule. */
export const COINBASE_MATURITY = 100;

/** An unspent output belonging to this wallet. */
export interface Utxo {
  /** Transaction that created it, display order. */
  readonly txid: string;
  /** Output index within that transaction. */
  readonly vout: number;
  /** Value in satoshis. */
  readonly value: bigint;
  /** Derivation path of the key that controls it — needed to sign. */
  readonly derivationPath: string;
  /** The address it was paid to. */
  readonly address: string;
  /** Confirmations. 0 means still in the mempool. */
  readonly confirmations: number;
  /** True if this came from a coinbase transaction (block reward). */
  readonly isCoinbase?: boolean;
  /** Excluded from automatic selection when true. */
  readonly frozen?: boolean;
}

/**
 * A balance broken into its meaningfully different parts.
 *
 * Deliberately not a single number. `spendable` is the only figure a send
 * flow may use; the others exist so the UI can explain *why* spendable is
 * lower than total, rather than leaving the user to guess.
 */
export interface Balance {
  /** Everything, regardless of state. */
  readonly total: bigint;
  /** Confirmed, mature, and unfrozen — actually usable right now. */
  readonly spendable: bigint;
  /** Confirmed but excluded (frozen, or immature coinbase). */
  readonly unavailable: bigint;
  /** Zero-confirmation. May still disappear. */
  readonly unconfirmed: bigint;
  /** Number of UTXOs, which drives future fee costs. */
  readonly utxoCount: number;
}

/** Is this UTXO usable in a spend right now? */
export function isSpendable(utxo: Utxo, minConfirmations = 1): boolean {
  if (utxo.frozen) return false;
  if (utxo.value <= 0n) return false;
  if (utxo.isCoinbase && utxo.confirmations < COINBASE_MATURITY) return false;
  return utxo.confirmations >= minConfirmations;
}

/** Would this output be rejected as dust by relay policy? */
export function isDust(value: bigint): boolean {
  return value < DUST_THRESHOLD_P2WPKH;
}

/**
 * An immutable collection of UTXOs.
 *
 * Immutable because a UTXO set that mutates underneath a transaction being
 * built is a race condition with money attached — coin selection could pick
 * an output that another code path has already spent.
 */
export class UtxoSet {
  private readonly utxos: readonly Utxo[];

  constructor(utxos: readonly Utxo[] = []) {
    // Reject duplicates: the same outpoint appearing twice would let coin
    // selection "spend" it twice, producing a transaction that is instantly
    // invalid and, worse, one whose fee arithmetic looks correct.
    const seen = new Set<string>();
    for (const utxo of utxos) {
      const key = `${utxo.txid}:${utxo.vout}`;
      if (seen.has(key)) throw new UtxoError(`duplicate outpoint at index ${utxo.vout}`);
      seen.add(key);
      if (utxo.value < 0n) throw new UtxoError("UTXO value cannot be negative");
      if (!Number.isInteger(utxo.confirmations) || utxo.confirmations < 0) {
        throw new UtxoError("confirmations must be a non-negative integer");
      }
    }
    this.utxos = Object.freeze([...utxos]);
  }

  get all(): readonly Utxo[] {
    return this.utxos;
  }

  get size(): number {
    return this.utxos.length;
  }

  /** Only the UTXOs eligible for spending. */
  spendable(minConfirmations = 1): Utxo[] {
    return this.utxos.filter((utxo) => isSpendable(utxo, minConfirmations));
  }

  balance(minConfirmations = 1): Balance {
    let total = 0n;
    let spendable = 0n;
    let unavailable = 0n;
    let unconfirmed = 0n;

    for (const utxo of this.utxos) {
      total += utxo.value;
      if (utxo.confirmations < minConfirmations) {
        unconfirmed += utxo.value;
      } else if (isSpendable(utxo, minConfirmations)) {
        spendable += utxo.value;
      } else {
        unavailable += utxo.value;
      }
    }
    return { total, spendable, unavailable, unconfirmed, utxoCount: this.utxos.length };
  }

  find(txid: string, vout: number): Utxo | undefined {
    return this.utxos.find((utxo) => utxo.txid === txid && utxo.vout === vout);
  }

  /** A new set with the given outpoints removed — used after a spend. */
  without(spent: readonly { txid: string; vout: number }[]): UtxoSet {
    const keys = new Set(spent.map((s) => `${s.txid}:${s.vout}`));
    return new UtxoSet(this.utxos.filter((u) => !keys.has(`${u.txid}:${u.vout}`)));
  }

  with(added: readonly Utxo[]): UtxoSet {
    return new UtxoSet([...this.utxos, ...added]);
  }

  /** A new set with one outpoint's frozen flag changed. */
  setFrozen(txid: string, vout: number, frozen: boolean): UtxoSet {
    return new UtxoSet(
      this.utxos.map((u) =>
        u.txid === txid && u.vout === vout ? { ...u, frozen } : u,
      ),
    );
  }
}
