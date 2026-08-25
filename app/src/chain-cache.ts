/**
 * CHAIN SOURCE CACHE — fewer requests, never a staler answer
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  THE PROBLEM
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * One Sync click on a wallet with three used addresses costs roughly:
 *
 *   sync()      40 × GET /address/X            (the gap-limit scan)
 *              + 3 × GET /address/X/utxo
 *              + 3 × GET /blocks/tip/height
 *   history()   40 × GET /address/X/txs
 *              + 40 × GET /blocks/tip/height   (one per address, inside
 *                                               getTransactions)
 *   ────────────────────────────────────────────────────────────────────
 *   ≈ 126 sequential requests
 *
 * At a 120 ms round trip that is fifteen seconds of spinner, repeated on every
 * sync, against a public server that rate-limits. A 429 surfaces correctly as a
 * ChainError rather than corrupting anything, but it is slow, impolite, and one
 * impatient double-click away from a ban.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  WHAT THIS EXPLOITS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A fact `core/` establishes and then discards: `sync()` asks every address
 * whether it has any history, immediately before `history()` asks every address
 * for its transactions. An address that just answered "no history" cannot have
 * transactions. That is a logical certainty, not a guess — so skipping the
 * request returns the same answer the server would have.
 *
 * ─── The rule this file obeys ──────────────────────────────────────────────
 * It eliminates requests it can PROVE are unnecessary. It never serves an old
 * answer to a question that was actually asked. A stale UTXO set is a wrong
 * balance and a stale history hides a payment, so neither is ever cached — only
 * the block height, which is one number that is the same for every address in a
 * single pass, and only for thirty seconds.
 *
 * This lives in the app layer, not `core/`. It is a policy about how politely
 * to talk to one specific public server, which is exactly the kind of decision
 * `core/` should not be making on behalf of every consumer.
 */
import type {
  ChainSource,
  ChainUtxo,
  ChainTransaction,
  AddressActivity,
  FeeEstimates,
} from "../../core/chain/types.js";

/**
 * How long a block height may be reused.
 *
 * Blocks arrive every ten minutes on average, and the height is only used to
 * compute confirmation counts. Thirty seconds is far shorter than a block and
 * long enough to cover one sync pass, which is the entire point.
 */
const TIP_TTL_MS = 30_000;

/** The extras `EsploraChainSource` exposes beyond `ChainSource`, forwarded. */
export interface CachedChainSource extends ChainSource {
  readonly isThirdParty: boolean;
  readonly privacyWarning: string | null;
  /** The source being wrapped, for anything that needs the real thing. */
  readonly inner: ChainSource;
}

interface Wrappable extends ChainSource {
  readonly isThirdParty?: boolean;
  readonly privacyWarning?: string | null;
}

/**
 * Wrap a chain source so a sync pass stops asking the same questions twice.
 *
 * ⚠️ Built as a factory returning an object literal, NOT as a class.
 * `Wallet.history()` decides what to do by testing `if (!source.getTransactions)`
 * and produces a useful message when a source cannot answer. A class method
 * always exists on the prototype, so a class wrapper around a source *without*
 * history would make that check pass and core would call a method that throws —
 * turning clear guidance into a stack trace. The conditional spread below
 * preserves the absence of an optional method, which is the thing being tested.
 */
export function cachedChainSource(inner: Wrappable): CachedChainSource {
  /**
   * Addresses we have already asked about, and whether they had history.
   *
   * `true` means "has history" — we still make the request, because we need the
   * actual transactions. `false` is the useful entry: it licenses skipping the
   * request entirely. Absent means we have not asked and must.
   */
  const hasHistory = new Map<string, boolean>();

  /**
   * The in-flight or recent tip request.
   *
   * The PROMISE is cached rather than the number, so forty callers arriving
   * while one request is in the air all await that one request instead of
   * starting forty. Caching the resolved value alone would not do this — the
   * gap is precisely where the stampede happens.
   */
  let tip: { at: number; value: Promise<number> } | null = null;

  async function getBlockHeight(): Promise<number> {
    const now = Date.now();
    if (tip && now - tip.at < TIP_TTL_MS) return tip.value;

    const request = inner.getBlockHeight();
    tip = { at: now, value: request };

    try {
      return await request;
    } catch (error) {
      // A failed request must not be cached as the answer for thirty seconds.
      // Clearing it means the next caller retries, which is what they expect.
      if (tip?.value === request) tip = null;
      throw error;
    }
  }

  async function getAddressActivity(address: string): Promise<AddressActivity> {
    // Always delegated. The activity carries the current UTXO set, and serving
    // a remembered one would mean showing a balance that is quietly wrong.
    const activity = await inner.getAddressActivity(address);
    hasHistory.set(address, activity.hasHistory);
    return activity;
  }

  async function getTransactions(address: string): Promise<ChainTransaction[]> {
    // The only skip in this file, and the only one that is provably safe: the
    // scan just asked this exact server about this exact address and was told
    // it has never been used. An unused address has no transactions.
    if (hasHistory.get(address) === false) return [];

    // Unknown (never scanned) or known-used: ask. Results are never cached —
    // a stale history hides a payment that has since arrived.
    return inner.getTransactions!(address);
  }

  async function broadcast(rawTxHex: string): Promise<string> {
    // ⚠️ The subtle bug this line exists to prevent.
    //
    // Broadcasting spends coins and pays change to a FRESH address. That change
    // address was unused a moment ago and is recorded here as `false`. Without
    // this reset, `getTransactions` would skip it and the user's own outgoing
    // transaction would be missing from their history — the wallet confidently
    // reporting that the payment it just made never happened.
    //
    // Cleared before the call, not after, so an error in the middle cannot
    // leave the map describing a chain state that has moved on.
    hasHistory.clear();
    tip = null;
    return inner.broadcast(rawTxHex);
  }

  return {
    name: inner.name,
    network: inner.network,
    inner,
    isThirdParty: inner.isThirdParty ?? true,
    privacyWarning: inner.privacyWarning ?? null,

    getBlockHeight,
    getAddressActivity,
    broadcast,
    getUtxos: (address: string): Promise<ChainUtxo[]> => inner.getUtxos(address),

    // Preserve absence, do not manufacture presence. See the note above.
    ...(inner.getTransactions ? { getTransactions } : {}),
    ...(inner.getFeeEstimates
      ? { getFeeEstimates: (): Promise<FeeEstimates> => inner.getFeeEstimates!() }
      : {}),
  };
}
