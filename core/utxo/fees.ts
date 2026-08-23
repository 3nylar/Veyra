/**
 * FEE ESTIMATION
 *
 * ─── The circular problem ──────────────────────────────────────────────────
 * Fees are charged per virtual byte, so you need the transaction's size to
 * compute the fee. But the fee determines how many inputs you need, which
 * determines the size. The dependency is circular:
 *
 *     size → fee → inputs needed → size → ...
 *
 * Two ways out. Iterate to a fixed point (accurate, slower), or estimate the
 * size from the transaction's *shape* before building it (fast, and exact for
 * P2WPKH because every input and output has a known size). Veyra does the
 * latter, then verifies against the real size after signing — see
 * `assertFeeMatchesEstimate` at the bottom.
 *
 * ─── Why estimate rather than measure? ─────────────────────────────────────
 * You cannot measure a transaction you have not built, and you cannot build
 * it without knowing how many inputs the fee requires. Estimating from shape
 * breaks the loop.
 *
 * ─── The sizes ─────────────────────────────────────────────────────────────
 * Weight units: non-witness bytes count 4, witness bytes count 1. vsize is
 * weight ÷ 4. So witness data is effectively a quarter price — the direct
 * economic reason SegWit exists.
 *
 * P2WPKH INPUT — 68 vbytes
 *   non-witness: outpoint 36 + scriptSig length 1 + sequence 4  = 41 bytes
 *                → 41 × 4 = 164 weight
 *   witness:     stack count 1 + (1 + 72 sig) + (1 + 33 pubkey) = 108 bytes
 *                → 108 × 1 = 108 weight
 *   total 272 weight = 68 vbytes
 *
 * P2WPKH OUTPUT — 31 vbytes
 *   value 8 + script length 1 + script 22 = 31 bytes, all non-witness
 *
 * OVERHEAD — 10.5 vbytes
 *   version 4 + input count 1 + output count 1 + locktime 4 = 10 non-witness
 *   marker 1 + flag 1 = 2 witness bytes → 0.5 vbytes
 *
 * ─── The 72-byte signature assumption ──────────────────────────────────────
 * DER signatures are 71 or 72 bytes depending on whether r and s need a
 * leading zero byte to avoid looking negative. We assume 72 — the maximum.
 *
 * This deliberately OVER-estimates by up to 1 byte per input. Over-estimating
 * means paying a fee fractionally above target; under-estimating means the
 * transaction may fall below the intended fee rate and confirm late or not at
 * all. Given that a stuck transaction is a far worse user experience than a
 * few satoshis of overpayment, rounding against ourselves is correct.
 */

/** Virtual size of one P2WPKH input, in vbytes. */
export const P2WPKH_INPUT_VSIZE = 68;

/** Virtual size of one P2WPKH output, in vbytes. */
export const P2WPKH_OUTPUT_VSIZE = 31;

/** Fixed per-transaction overhead for a SegWit transaction, in vbytes. */
export const TX_OVERHEAD_VSIZE = 10.5;

/**
 * Minimum fee rate that will relay, in sat/vB.
 *
 * Bitcoin Core's default `minRelayTxFee` is 1000 sat/kvB = 1 sat/vB. Below
 * this a transaction is not merely slow — it is rejected by nodes outright
 * and never enters a mempool. A wallet that lets a user set 0.5 sat/vB
 * produces a transaction that vanishes with no error.
 */
export const MIN_RELAY_FEE_RATE = 1;

/**
 * Fee rate presets, in sat/vB.
 *
 * These are STATIC PLACEHOLDERS, and saying so matters. Real fee estimation
 * requires live mempool data — Bitcoin Core's `estimatesmartfee`, or a
 * public API. Veyra has no network layer yet, so these are reasonable
 * defaults for a calm mempool and will be wrong during congestion.
 *
 * They are not presented as estimates anywhere in the API; the caller must
 * pass a rate explicitly. This constant exists to be replaced by a real
 * estimator, not to be quietly trusted.
 */
export const FEE_RATE_PRESETS = Object.freeze({
  /** Next block or two. */
  high: 20,
  /** Within a few blocks. */
  medium: 8,
  /** Hours to a day. */
  low: 2,
});

/**
 * Incremental relay fee, in sat/vB.
 *
 * BIP-125 rule 4: a replacement transaction must pay for its own bandwidth on
 * top of beating the original's absolute fee. The additional fee must be at
 * least this rate times the replacement's size — otherwise a node would be
 * relaying a second copy of the transaction for free, and an attacker could
 * flood the network with endless one-satoshi bumps.
 *
 * Bitcoin Core's default `incrementalRelayFee` is 1000 sat/kvB = 1 sat/vB.
 */
export const INCREMENTAL_RELAY_FEE_RATE = 1;

export interface SizeEstimate {
  readonly vsize: number;
  readonly weight: number;
}

/**
 * Estimate the virtual size of a P2WPKH transaction from its shape.
 *
 * Exact for P2WPKH given the 72-byte signature assumption, which rounds
 * against us.
 */
export function estimateVsize(inputCount: number, outputCount: number): SizeEstimate {
  if (!Number.isInteger(inputCount) || inputCount < 0) {
    throw new Error("inputCount must be a non-negative integer");
  }
  if (!Number.isInteger(outputCount) || outputCount < 0) {
    throw new Error("outputCount must be a non-negative integer");
  }

  // Counts above 252 need a larger CompactSize prefix. Accounted for rather
  // than ignored: a 300-input transaction would otherwise be under-estimated.
  const inputCountBytes = inputCount < 253 ? 1 : inputCount < 65536 ? 3 : 5;
  const outputCountBytes = outputCount < 253 ? 1 : outputCount < 65536 ? 3 : 5;
  const overhead = 4 + 4 + inputCountBytes + outputCountBytes + 0.5;

  const vsize = Math.ceil(
    overhead + inputCount * P2WPKH_INPUT_VSIZE + outputCount * P2WPKH_OUTPUT_VSIZE,
  );
  return { vsize, weight: vsize * 4 };
}

/** Fee in satoshis for a transaction of the given shape at the given rate. */
export function estimateFee(
  inputCount: number,
  outputCount: number,
  feeRateSatPerVb: number,
): bigint {
  if (!Number.isFinite(feeRateSatPerVb) || feeRateSatPerVb < MIN_RELAY_FEE_RATE) {
    throw new Error(
      `fee rate must be at least ${MIN_RELAY_FEE_RATE} sat/vB or the transaction will not relay`,
    );
  }
  const { vsize } = estimateVsize(inputCount, outputCount);
  // Round UP. Rounding down could land fractionally below the intended rate.
  return BigInt(Math.ceil(vsize * feeRateSatPerVb));
}

/**
 * The marginal cost of adding one more input.
 *
 * Coin selection needs this constantly: an input is only worth including if
 * it contributes more value than it costs to spend. A 500-satoshi UTXO at
 * 10 sat/vB costs 680 satoshis to spend — including it makes you poorer.
 */
export function costOfInput(feeRateSatPerVb: number): bigint {
  return BigInt(Math.ceil(P2WPKH_INPUT_VSIZE * feeRateSatPerVb));
}

/** The marginal cost of adding one more output — e.g. deciding on change. */
export function costOfOutput(feeRateSatPerVb: number): bigint {
  return BigInt(Math.ceil(P2WPKH_OUTPUT_VSIZE * feeRateSatPerVb));
}

/**
 * Verify that a built transaction's actual fee rate matches what was intended.
 *
 * Called after signing, when the true vsize is known. Catches estimation drift
 * before broadcast rather than after — an over-payment discovered on-chain is
 * unrecoverable.
 *
 * The tolerance allows the estimate to be slightly high (we assumed 72-byte
 * signatures; some will be 71) but not low.
 */
export function assertFeeMatchesEstimate(
  actualVsize: number,
  actualFee: bigint,
  intendedRate: number,
  toleranceRatio = 0.25,
): void {
  const actualRate = Number(actualFee) / actualVsize;
  if (actualRate < intendedRate * (1 - toleranceRatio)) {
    throw new Error(
      `actual fee rate ${actualRate.toFixed(2)} sat/vB is below the intended ` +
        `${intendedRate} sat/vB; the transaction may not confirm`,
    );
  }
  if (actualRate > intendedRate * (1 + toleranceRatio)) {
    throw new Error(
      `actual fee rate ${actualRate.toFixed(2)} sat/vB substantially exceeds the ` +
        `intended ${intendedRate} sat/vB; check the transaction before broadcasting`,
    );
  }
}
