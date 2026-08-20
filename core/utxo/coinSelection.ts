/**
 * COIN SELECTION
 *
 * ─── The problem ───────────────────────────────────────────────────────────
 * Given a set of coins of fixed sizes and a target amount, choose a subset
 * covering the target plus fees. This is a variant of the subset-sum problem,
 * which is NP-complete — so every real wallet uses heuristics, and the choice
 * of heuristic has consequences beyond arithmetic.
 *
 * ─── What is actually being optimised ──────────────────────────────────────
 * Three goals, and they conflict:
 *
 *   1. COST NOW. Fewer inputs means a smaller transaction and a lower fee.
 *   2. COST LATER. Creating change adds an output you must eventually spend.
 *      A "free" change output costs 68 vbytes the next time you send.
 *   3. PRIVACY. The selection reveals information. Spending five coins
 *      together tells an observer those five addresses share an owner — the
 *      "common input ownership heuristic", the single most effective tool in
 *      blockchain analysis.
 *
 * Optimising purely for goal 1 produces a wallet that fragments into dust and
 * leaks its whole address graph.
 *
 * ─── The waste metric ──────────────────────────────────────────────────────
 * Bitcoin Core formalises goals 1 and 2 as a single number:
 *
 *     waste = Σ(input cost at current rate − input cost at long-term rate)
 *             + cost of creating change + cost of spending it later
 *             (or, if no change, the excess given away as fee)
 *
 * The insight: if fees are LOW right now relative to the long-term average,
 * spending many inputs is cheap and consolidating is good. If fees are HIGH,
 * spend as few inputs as possible and defer.
 *
 * A CHANGELESS transaction — where the inputs happen to cover the target and
 * fee almost exactly — is ideal. It avoids the change output entirely, both
 * now and in future, and it destroys the change-detection heuristic that
 * blockchain analysts rely on.
 *
 * ─── The three strategies here ─────────────────────────────────────────────
 *
 *   BRANCH AND BOUND  Searches for an exact-match, changeless solution.
 *                     Bounded depth-first search over the coin set. When it
 *                     succeeds the result is optimal. It often fails, because
 *                     an exact match may not exist.
 *
 *   SINGLE RANDOM DRAW  Fallback. Picks coins at random until the target is
 *                     covered. Random is deliberate, not lazy: deterministic
 *                     strategies (always largest-first, always oldest-first)
 *                     produce recognisable on-chain patterns that fingerprint
 *                     the wallet software and leak selection logic.
 *
 *   LARGEST FIRST     Available but NOT the default. Minimises input count,
 *                     which minimises immediate fee — at the cost of
 *                     destroying large coins and fragmenting the wallet.
 *                     Included so the trade-off is visible and testable.
 *
 * ─── The invariant that matters most ───────────────────────────────────────
 * No strategy may ever select coins summing to less than target + fee. §33 of
 * the spec: "The wallet must never allow spending more than the spendable
 * UTXO set." Every selection result is validated before it is returned, and
 * the property tests assert it across thousands of random scenarios.
 */

import { Utxo, isDust, isSpendable, DUST_THRESHOLD_P2WPKH } from "./utxo.js";
import { estimateFee, costOfInput, costOfOutput, MIN_RELAY_FEE_RATE } from "./fees.js";
import { VeyraError } from "../errors/index.js";

export class CoinSelectionError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Coin selection: ${reason}`);
    this.name = "CoinSelectionError";
  }
}

export type SelectionStrategy = "branch-and-bound" | "single-random-draw" | "largest-first";

export interface SelectionRequest {
  /** Coins available to spend. */
  readonly utxos: readonly Utxo[];
  /** Amount to send, in satoshis. */
  readonly target: bigint;
  /** Fee rate in sat/vB. */
  readonly feeRate: number;
  /** Number of recipient outputs (excluding change). Defaults to 1. */
  readonly outputCount?: number;
  /** Strategy override. Defaults to trying BnB then falling back. */
  readonly strategy?: SelectionStrategy;
}

export interface SelectionResult {
  readonly selected: readonly Utxo[];
  /** Total value of selected inputs. */
  readonly inputTotal: bigint;
  /** Fee this transaction will pay. */
  readonly fee: bigint;
  /** Change amount. Zero means a changeless transaction. */
  readonly change: bigint;
  /** True when no change output is needed. */
  readonly changeless: boolean;
  /** Which strategy produced this. */
  readonly strategy: SelectionStrategy;
  /** Estimated vsize of the resulting transaction. */
  readonly estimatedVsize: number;
}

/**
 * Fisher-Yates shuffle using the CSPRNG.
 *
 * Uses secure randomness rather than Math.random — not because selection
 * order is a secret, but because `Math.random` is banned throughout core/ by
 * the entropy guard test, and carving out an exception invites the exception
 * to spread to somewhere it matters.
 */
function shuffle<T>(items: readonly T[]): T[] {
  const out = [...items];
  const random = new Uint32Array(out.length);
  crypto.getRandomValues(random);
  for (let i = out.length - 1; i > 0; i--) {
    const j = random[i]! % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

/** Validate a candidate selection. Every strategy passes through this. */
function buildResult(
  selected: Utxo[],
  target: bigint,
  feeRate: number,
  outputCount: number,
  strategy: SelectionStrategy,
  forceChangeless: boolean,
): SelectionResult | null {
  if (selected.length === 0) return null;

  const inputTotal = selected.reduce((sum, u) => sum + u.value, 0n);

  // Try WITHOUT a change output first — changeless is strictly better.
  const feeNoChange = estimateFee(selected.length, outputCount, feeRate);
  const surplusNoChange = inputTotal - target - feeNoChange;

  if (surplusNoChange >= 0n) {
    // The surplus would become change. If it is below dust, it cannot be a
    // separate output at all — it must be given to the miner as extra fee.
    // That is not a bug: a dust change output would make the transaction
    // unrelayable, so paying it forward is the only valid option.
    const changeCost = costOfOutput(feeRate);
    const feeWithChange = feeNoChange + changeCost;
    const change = inputTotal - target - feeWithChange;

    if (forceChangeless || change < DUST_THRESHOLD_P2WPKH) {
      return {
        selected,
        inputTotal,
        fee: inputTotal - target, // the entire surplus becomes fee
        change: 0n,
        changeless: true,
        strategy,
        estimatedVsize: Math.ceil(Number(feeNoChange) / feeRate),
      };
    }
    return {
      selected,
      inputTotal,
      fee: feeWithChange,
      change,
      changeless: false,
      strategy,
      estimatedVsize: Math.ceil(Number(feeWithChange) / feeRate),
    };
  }
  return null; // insufficient
}

/**
 * BRANCH AND BOUND — search for an exact, changeless match.
 *
 * Depth-first over coins sorted descending, with two pruning rules:
 *   - if the running total exceeds target + fee + tolerance, backtrack
 *   - if the remaining coins cannot reach the target, backtrack
 *
 * The tolerance is the cost of a change output: overshooting by less than
 * that is better than creating change, since we would have paid that much to
 * make the change output anyway.
 *
 * Bounded at 100,000 explored nodes. Without a bound this is exponential and
 * a wallet with many coins would hang — a denial of service on yourself.
 */
function branchAndBound(
  utxos: readonly Utxo[],
  target: bigint,
  feeRate: number,
  outputCount: number,
): SelectionResult | null {
  const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0));
  const costPerInput = costOfInput(feeRate);
  const tolerance = costOfOutput(feeRate);

  const baseFee = estimateFee(0, outputCount, feeRate);

  // Suffix sums for the "can the rest even reach the target" prune.
  const remaining: bigint[] = new Array(sorted.length + 1).fill(0n);
  for (let i = sorted.length - 1; i >= 0; i--) {
    remaining[i] = remaining[i + 1]! + sorted[i]!.value - costPerInput;
  }

  let best: Utxo[] | null = null;
  let explored = 0;
  const MAX_EXPLORED = 100_000;

  const selection: Utxo[] = [];

  function search(index: number, effectiveTotal: bigint): void {
    if (best !== null || explored++ > MAX_EXPLORED) return;

    const need = target + baseFee;

    if (effectiveTotal > need + tolerance) return; // overshot
    if (effectiveTotal >= need) {
      best = [...selection];
      return;
    }
    if (index >= sorted.length) return;
    if (effectiveTotal + remaining[index]! < need) return; // cannot reach

    // Branch: include this coin.
    const utxo = sorted[index]!;
    const effectiveValue = utxo.value - costPerInput;
    if (effectiveValue > 0n) {
      selection.push(utxo);
      search(index + 1, effectiveTotal + effectiveValue);
      selection.pop();
    }
    // Branch: skip it.
    search(index + 1, effectiveTotal);
  }

  search(0, 0n);
  if (best === null) return null;
  return buildResult(best, target, feeRate, outputCount, "branch-and-bound", true);
}

/** SINGLE RANDOM DRAW — add random coins until the target is met. */
function singleRandomDraw(
  utxos: readonly Utxo[],
  target: bigint,
  feeRate: number,
  outputCount: number,
): SelectionResult | null {
  const shuffled = shuffle(utxos);
  const selected: Utxo[] = [];
  const costPerInput = costOfInput(feeRate);

  for (const utxo of shuffled) {
    // Skip coins that cost more to spend than they contribute. Including
    // them makes the user strictly poorer.
    if (utxo.value <= costPerInput) continue;
    selected.push(utxo);
    const result = buildResult(selected, target, feeRate, outputCount, "single-random-draw", false);
    if (result) return result;
  }
  return null;
}

/** LARGEST FIRST — minimise input count. Available, not default. */
function largestFirst(
  utxos: readonly Utxo[],
  target: bigint,
  feeRate: number,
  outputCount: number,
): SelectionResult | null {
  const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0));
  const selected: Utxo[] = [];
  const costPerInput = costOfInput(feeRate);

  for (const utxo of sorted) {
    if (utxo.value <= costPerInput) continue;
    selected.push(utxo);
    const result = buildResult(selected, target, feeRate, outputCount, "largest-first", false);
    if (result) return result;
  }
  return null;
}

/**
 * Select coins to fund a payment.
 *
 * Default behaviour: try branch-and-bound for a changeless solution, fall
 * back to single random draw.
 *
 * @throws CoinSelectionError if the target cannot be funded. The error states
 *   what was available versus what was needed — non-secret information the
 *   user needs in order to understand the refusal.
 */
export function selectCoins(request: SelectionRequest): SelectionResult {
  const { utxos, target, feeRate } = request;
  const outputCount = request.outputCount ?? 1;

  if (target <= 0n) {
    throw new CoinSelectionError("target amount must be positive");
  }
  if (isDust(target)) {
    throw new CoinSelectionError(
      `target of ${target} sat is below the dust threshold of ${DUST_THRESHOLD_P2WPKH} sat ` +
        `and would not relay`,
    );
  }
  if (!Number.isFinite(feeRate) || feeRate < MIN_RELAY_FEE_RATE) {
    throw new CoinSelectionError(
      `fee rate must be at least ${MIN_RELAY_FEE_RATE} sat/vB or the transaction will not relay`,
    );
  }

  const available = utxos.filter((utxo) => isSpendable(utxo));
  if (available.length === 0) {
    throw new CoinSelectionError("no spendable UTXOs available");
  }

  const availableTotal = available.reduce((sum, u) => sum + u.value, 0n);
  const minimumFee = estimateFee(1, outputCount, feeRate);
  if (availableTotal < target + minimumFee) {
    throw new CoinSelectionError(
      `insufficient funds: ${availableTotal} sat available, ` +
        `at least ${target + minimumFee} sat required including fees`,
    );
  }

  let result: SelectionResult | null = null;
  const strategy = request.strategy;

  if (strategy === "largest-first") {
    result = largestFirst(available, target, feeRate, outputCount);
  } else if (strategy === "single-random-draw") {
    result = singleRandomDraw(available, target, feeRate, outputCount);
  } else if (strategy === "branch-and-bound") {
    result = branchAndBound(available, target, feeRate, outputCount);
  } else {
    result = branchAndBound(available, target, feeRate, outputCount)
      ?? singleRandomDraw(available, target, feeRate, outputCount);
  }

  if (result === null) {
    throw new CoinSelectionError(
      `could not fund ${target} sat at ${feeRate} sat/vB from the available UTXOs; ` +
        `the coins may be too fragmented to cover the fee`,
    );
  }

  // ── Final invariant checks. §33: never spend more than is available. ─────
  // These are asserted here, at the single exit point, rather than trusted
  // from each strategy. A bug in one algorithm cannot bypass them.
  const total = result.selected.reduce((sum, u) => sum + u.value, 0n);
  if (total !== result.inputTotal) {
    throw new CoinSelectionError("internal error: input total mismatch");
  }
  if (result.inputTotal < target + result.fee) {
    throw new CoinSelectionError("internal error: selection does not cover target plus fee");
  }
  if (result.inputTotal !== target + result.fee + result.change) {
    throw new CoinSelectionError("internal error: value does not balance");
  }
  if (result.change > 0n && isDust(result.change)) {
    throw new CoinSelectionError("internal error: change output would be dust");
  }
  if (result.fee < 0n) {
    throw new CoinSelectionError("internal error: negative fee");
  }
  return result;
}
