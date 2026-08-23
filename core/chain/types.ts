/**
 * CHAIN SOURCE — the boundary with the untrusted network
 *
 * ─── This is the most dangerous interface in the wallet ────────────────────
 * Everything up to this point was arithmetic on data we produced ourselves.
 * From here, data arrives from a server we do not control, and the threat
 * model changes completely.
 *
 * ─── What a malicious chain source CAN do ──────────────────────────────────
 *
 *   1. LIE ABOUT BALANCES. Report UTXOs that do not exist, or hide ones that
 *      do. Result: transactions that fail to broadcast, or a user who thinks
 *      they are poorer than they are.
 *
 *   2. LIE ABOUT CONFIRMATIONS. Claim a transaction is confirmed when it is
 *      not. This is how a merchant gets robbed: deliver goods against a
 *      confirmation that never happened.
 *
 *   3. WITHHOLD BROADCAST. Accept a transaction and silently drop it.
 *
 *   4. LEARN YOUR ENTIRE WALLET. This is the one people underestimate.
 *      Querying a server for your addresses tells that server every address
 *      you own, in one session, linked to your IP. No cryptography prevents
 *      this. It is the single largest privacy leak in any light wallet, and
 *      it is inherent to the model, not a bug in this implementation. See
 *      the privacy note in esplora.ts.
 *
 * ─── What a malicious chain source CANNOT do ───────────────────────────────
 *
 *   1. STEAL FUNDS BY LYING ABOUT AMOUNTS. BIP-143 puts the input value
 *      inside the signature preimage. If the server understates a UTXO's
 *      value, the resulting signature simply does not verify and the network
 *      rejects the transaction. The classic "understate the input so the
 *      difference becomes miner fee" attack is closed by the protocol, not
 *      by us — see docs/CRYPTOGRAPHY.md §13.
 *
 *   2. FORGE A SIGNATURE. It never sees a private key.
 *
 *   3. REDIRECT A PAYMENT. The destination is chosen locally and committed
 *      to by the signature.
 *
 * So the realistic damage is denial of service, misinformation, and privacy
 * loss — not theft. That is worth stating precisely, because it determines
 * how much defensive machinery is justified here.
 *
 * ─── Defences implemented ──────────────────────────────────────────────────
 *   - Every response is parsed defensively; nothing is trusted to have the
 *     shape it claims. See `validate*` below.
 *   - UTXOs are checked against addresses the wallet actually derives; a
 *     UTXO for an unknown address is rejected outright.
 *   - Broadcast responses are checked: the returned txid must equal the txid
 *     we computed locally, or we treat the broadcast as failed.
 *   - Amounts are parsed as BigInt. A JSON number above 2^53 silently loses
 *     precision, and Bitcoin amounts reach 2.1e15 satoshis.
 */

import { VeyraError } from "../errors/index.js";

export class ChainError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Chain: ${reason}`);
    this.name = "ChainError";
  }
}

/** An unspent output as reported by a chain source, before validation. */
export interface ChainUtxo {
  readonly txid: string;
  readonly vout: number;
  readonly value: bigint;
  readonly confirmations: number;
  readonly blockHeight?: number;
}

/**
 * A transaction touching one of our addresses.
 *
 * `netValue` is the field that makes a history readable: positive means value
 * arrived, negative means it left. A list that shows only amounts, without
 * direction, tells a user nothing they could act on.
 */
export interface ChainTransaction {
  readonly txid: string;
  readonly confirmations: number;
  readonly blockHeight?: number;
  /** Unix seconds. Absent while unconfirmed. */
  readonly blockTime?: number;
  /** Net effect on the wallet, in satoshis. Negative for a spend. */
  readonly netValue?: bigint;
  /** Fee paid. Only known for transactions we sent. */
  readonly fee?: bigint;
  /** Derived from netValue, for display. */
  readonly direction?: "received" | "sent" | "internal";
}

/**
 * Fee estimates from live network conditions, in sat/vB.
 *
 * ─── Why these are not simply "the fee" ────────────────────────────────────
 * A fee estimate is a prediction about a competitive auction. It says: given
 * what is currently in the mempool, this rate has historically been enough to
 * confirm within N blocks. It is not a guarantee, and it goes stale in
 * minutes — a burst of activity can leave a "next block" estimate confirming
 * in an hour.
 *
 * Every field is optional because sources disagree about which targets they
 * can answer, and a node on a fresh chain can answer none of them. A missing
 * estimate must surface as "unavailable", never as a fabricated number.
 */
export interface FeeEstimates {
  /** Target: next block or two. */
  readonly high?: number;
  /** Target: within a few blocks. */
  readonly medium?: number;
  /** Target: within a day. */
  readonly low?: number;
  /** Where these came from, for display. */
  readonly source: string;
  /** When fetched. Estimates go stale quickly. */
  readonly fetchedAt: number;
}

/** Whether an address has ever been used — the signal the gap-limit scan follows. */
export interface AddressActivity {
  readonly address: string;
  readonly hasHistory: boolean;
  readonly utxos: readonly ChainUtxo[];
}

/**
 * The interface every backend implements.
 *
 * Kept deliberately small. A wallet needs exactly four things from a chain:
 * what is unspent, whether an address was ever used, the current height, and
 * a way to publish. Anything larger increases the surface an untrusted server
 * can attack and the amount of data it learns about the user.
 */
export interface ChainSource {
  /** Human-readable name, for display and logs. */
  readonly name: string;
  /** Which network this source serves. Checked against the wallet's network. */
  readonly network: string;

  /** Current best block height. Used to compute confirmations. */
  getBlockHeight(): Promise<number>;

  /** Unspent outputs for one address. */
  getUtxos(address: string): Promise<ChainUtxo[]>;

  /** Whether an address has any history, and its current UTXOs. */
  getAddressActivity(address: string): Promise<AddressActivity>;

  /** Publish a raw transaction. Returns the txid the server reports. */
  broadcast(rawTxHex: string): Promise<string>;

  /** Transactions touching an address. Optional: not every source can answer it. */
  getTransactions?(address: string): Promise<ChainTransaction[]>;

  /**
   * Live fee estimates. Optional.
   *
   * A source that cannot estimate must omit this method rather than returning
   * invented numbers — the wallet falls back to static defaults and says so.
   */
  getFeeEstimates?(): Promise<FeeEstimates>;
}

// ─────────────────────────────────────────────────────────────────────────
//  VALIDATION OF UNTRUSTED RESPONSES
//
//  Every function below assumes its input is hostile. They exist because
//  `response.json()` returns `any`, and `any` flowing into money arithmetic
//  is how a malformed field becomes a wrong balance.
// ─────────────────────────────────────────────────────────────────────────

/** A 64-character lowercase hex txid, or reject. */
export function validateTxid(value: unknown, context: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new ChainError(`${context}: expected a 64-character lowercase hex txid`);
  }
  return value;
}

/**
 * A satoshi amount, as BigInt.
 *
 * Accepts a JSON number or a string. Rejects non-integers, negatives, and
 * anything above the money supply.
 *
 * The `Number.isSafeInteger` check matters: JSON numbers are IEEE doubles, so
 * any integer above 2^53 is silently rounded. Bitcoin's supply is 2.1e15
 * satoshis, which is below 2^53 (9.0e15) — so a *legitimate* amount always
 * fits. An amount that does NOT fit is therefore either a bug or an attack,
 * and rejecting it is correct rather than merely cautious.
 */
export function validateAmount(value: unknown, context: string): bigint {
  let amount: bigint;
  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ChainError(
        `${context}: amount is not a safe integer — possible precision loss or tampering`,
      );
    }
    amount = BigInt(value);
  } else if (typeof value === "string" && /^\d+$/.test(value)) {
    amount = BigInt(value);
  } else {
    throw new ChainError(`${context}: amount is not a valid integer`);
  }

  if (amount < 0n) throw new ChainError(`${context}: amount is negative`);
  if (amount > 2_100_000_000_000_000n) {
    throw new ChainError(`${context}: amount exceeds the total money supply`);
  }
  return amount;
}

/** A non-negative integer index or count. */
export function validateIndex(value: unknown, context: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new ChainError(`${context}: expected a non-negative 32-bit integer`);
  }
  return value;
}

/** A block height. */
export function validateHeight(value: unknown, context: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 100_000_000) {
    throw new ChainError(`${context}: implausible block height`);
  }
  return value;
}

/**
 * Confirmations, clamped to zero.
 *
 * A negative confirmation count is meaningless. Rather than throwing — some
 * servers report -1 for "in mempool" — we clamp, because treating a
 * mempool transaction as zero-confirmation is exactly right and refusing to
 * sync over a formatting quirk would be unhelpful.
 */
export function normalizeConfirmations(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.floor(value));
}
