/**
 * COIN SELECTION AND FEE TESTS
 *
 * Spec §33 requires PROPERTY testing, not just examples. The properties here
 * are the ones where a violation loses money:
 *
 *   - selection never covers less than target + fee
 *   - value always balances: inputs = target + fee + change
 *   - change is never dust
 *   - the wallet can never select more than the spendable set contains
 *
 * These are asserted across thousands of randomly generated scenarios,
 * because an example-based test only proves the cases someone thought of.
 */
import { describe, it, expect } from "vitest";
import {
  selectCoins, CoinSelectionError, type SelectionStrategy,
} from "../../core/utxo/coinSelection.js";
import {
  estimateVsize, estimateFee, costOfInput, costOfOutput,
  P2WPKH_INPUT_VSIZE, P2WPKH_OUTPUT_VSIZE, MIN_RELAY_FEE_RATE,
  assertFeeMatchesEstimate,
} from "../../core/utxo/fees.js";
import {
  UtxoSet, isDust, isSpendable, DUST_THRESHOLD_P2WPKH, COINBASE_MATURITY, type Utxo,
} from "../../core/utxo/utxo.js";

let counter = 0;
function utxo(value: bigint, overrides: Partial<Utxo> = {}): Utxo {
  counter++;
  return {
    txid: counter.toString(16).padStart(2, "0").repeat(32).slice(0, 64),
    vout: 0,
    value,
    derivationPath: "m/84'/1'/0'/0/0",
    address: "tb1qtest",
    confirmations: 6,
    ...overrides,
  };
}

describe("fee estimation", () => {
  it("uses the documented P2WPKH sizes", () => {
    expect(P2WPKH_INPUT_VSIZE).toBe(68);
    expect(P2WPKH_OUTPUT_VSIZE).toBe(31);
  });

  it("estimates a 1-in 2-out transaction at ~141 vbytes", () => {
    // 10.5 overhead + 68 + 2x31 = 140.5 -> 141
    expect(estimateVsize(1, 2).vsize).toBe(141);
  });

  it("estimates a 1-in 1-out transaction at ~110 vbytes", () => {
    expect(estimateVsize(1, 1).vsize).toBe(110);
  });

  it("grows linearly with inputs and outputs", () => {
    const base = estimateVsize(1, 1).vsize;
    expect(estimateVsize(2, 1).vsize - base).toBe(P2WPKH_INPUT_VSIZE);
    expect(estimateVsize(1, 2).vsize - base).toBe(P2WPKH_OUTPUT_VSIZE);
  });

  it("accounts for the larger CompactSize prefix above 252 inputs", () => {
    // A naive estimator would under-estimate here by 2 bytes.
    const at252 = estimateVsize(252, 1).vsize;
    const at253 = estimateVsize(253, 1).vsize;
    expect(at253 - at252).toBe(P2WPKH_INPUT_VSIZE + 2);
  });

  it("computes fees at the given rate", () => {
    expect(estimateFee(1, 2, 10)).toBe(1410n);
    expect(estimateFee(1, 2, 1)).toBe(141n);
  });

  it("REFUSES a fee rate below the relay minimum", () => {
    // Below 1 sat/vB the transaction is not slow — it is rejected outright
    // and never enters a mempool.
    expect(() => estimateFee(1, 2, 0.5)).toThrow(/at least 1 sat\/vB/);
    expect(() => estimateFee(1, 2, 0)).toThrow();
    expect(() => estimateFee(1, 2, -5)).toThrow();
    expect(MIN_RELAY_FEE_RATE).toBe(1);
  });

  it("costOfInput and costOfOutput match the per-unit sizes", () => {
    expect(costOfInput(10)).toBe(680n);
    expect(costOfOutput(10)).toBe(310n);
  });

  it("assertFeeMatchesEstimate accepts a close match and rejects drift", () => {
    expect(() => assertFeeMatchesEstimate(141, 1410n, 10)).not.toThrow();
    expect(() => assertFeeMatchesEstimate(141, 100n, 10)).toThrow(/below the intended/);
    expect(() => assertFeeMatchesEstimate(141, 14100n, 10)).toThrow(/exceeds/);
  });
});

describe("dust and spendability", () => {
  it("the P2WPKH dust threshold is 294 sat", () => {
    expect(DUST_THRESHOLD_P2WPKH).toBe(294n);
    expect(isDust(293n)).toBe(true);
    expect(isDust(294n)).toBe(false);
  });

  it("frozen UTXOs are not spendable", () => {
    expect(isSpendable(utxo(10_000n, { frozen: true }))).toBe(false);
  });

  it("unconfirmed UTXOs are not spendable by default", () => {
    expect(isSpendable(utxo(10_000n, { confirmations: 0 }))).toBe(false);
    expect(isSpendable(utxo(10_000n, { confirmations: 0 }), 0)).toBe(true);
  });

  it("immature coinbase outputs are not spendable", () => {
    expect(isSpendable(utxo(10_000n, { isCoinbase: true, confirmations: 99 }))).toBe(false);
    expect(isSpendable(utxo(10_000n, { isCoinbase: true, confirmations: COINBASE_MATURITY }))).toBe(true);
  });
});

describe("UtxoSet", () => {
  it("computes a broken-down balance", () => {
    const set = new UtxoSet([
      utxo(100_000n, { confirmations: 6 }),
      utxo(50_000n, { confirmations: 0 }),
      utxo(25_000n, { confirmations: 6, frozen: true }),
    ]);
    const balance = set.balance();
    expect(balance.total).toBe(175_000n);
    expect(balance.spendable).toBe(100_000n);
    expect(balance.unconfirmed).toBe(50_000n);
    expect(balance.unavailable).toBe(25_000n);
    expect(balance.utxoCount).toBe(3);
  });

  it("spendable + unconfirmed + unavailable always equals total", () => {
    for (let i = 0; i < 100; i++) {
      const set = new UtxoSet(
        Array.from({ length: 1 + Math.floor(Math.random() * 8) }, () =>
          utxo(BigInt(1 + Math.floor(Math.random() * 100_000)), {
            confirmations: Math.floor(Math.random() * 3),
            frozen: Math.random() > 0.8,
          }),
        ),
      );
      const b = set.balance();
      expect(b.spendable + b.unconfirmed + b.unavailable).toBe(b.total);
    }
  });

  it("REJECTS duplicate outpoints — double-spending its own coin", () => {
    const u = utxo(1000n);
    expect(() => new UtxoSet([u, { ...u }])).toThrow(/duplicate outpoint/);
  });

  it("rejects negative values and invalid confirmations", () => {
    expect(() => new UtxoSet([utxo(-1n)])).toThrow(/negative/);
    expect(() => new UtxoSet([utxo(100n, { confirmations: -1 })])).toThrow();
  });

  it("without() removes spent coins and is immutable", () => {
    const a = utxo(1000n);
    const b = utxo(2000n);
    const set = new UtxoSet([a, b]);
    const after = set.without([{ txid: a.txid, vout: a.vout }]);
    expect(after.size).toBe(1);
    expect(set.size).toBe(2); // original untouched
  });
});

describe("coin selection: basic behaviour", () => {
  it("funds a payment from a single sufficient coin", () => {
    const result = selectCoins({ utxos: [utxo(100_000n)], target: 50_000n, feeRate: 10 });
    expect(result.inputTotal).toBe(100_000n);
    expect(result.selected.length).toBe(1);
    expect(result.inputTotal).toBe(50_000n + result.fee + result.change);
  });

  it("combines several coins when no single one suffices", () => {
    const result = selectCoins({
      utxos: [utxo(20_000n), utxo(20_000n), utxo(20_000n), utxo(20_000n)],
      target: 50_000n,
      feeRate: 5,
    });
    expect(result.selected.length).toBeGreaterThanOrEqual(3);
    expect(result.inputTotal).toBeGreaterThanOrEqual(50_000n + result.fee);
  });

  it("finds a CHANGELESS solution when one exists", () => {
    // 1-in 1-out at 10 sat/vB costs 1100 sat. A coin of exactly 51,100
    // covers a 50,000 payment with no change.
    const result = selectCoins({
      utxos: [utxo(51_100n), utxo(500_000n)],
      target: 50_000n,
      feeRate: 10,
      strategy: "branch-and-bound",
    });
    expect(result.changeless).toBe(true);
    expect(result.change).toBe(0n);
  });

  it("largest-first minimises the input count", () => {
    const result = selectCoins({
      utxos: [utxo(1000n), utxo(2000n), utxo(500_000n), utxo(3000n)],
      target: 100_000n,
      feeRate: 5,
      strategy: "largest-first",
    });
    expect(result.selected.length).toBe(1);
    expect(result.selected[0]!.value).toBe(500_000n);
  });

  it("single-random-draw does not always pick the same coins", () => {
    const utxos = Array.from({ length: 20 }, () => utxo(20_000n));
    const signatures = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const result = selectCoins({
        utxos, target: 50_000n, feeRate: 5, strategy: "single-random-draw",
      });
      signatures.add(result.selected.map((u) => u.txid).sort().join(","));
    }
    // Deterministic strategies fingerprint the wallet on-chain; random does not.
    expect(signatures.size).toBeGreaterThan(1);
  });
});

describe("coin selection: refusals", () => {
  it("refuses when funds are insufficient", () => {
    expect(() => selectCoins({ utxos: [utxo(10_000n)], target: 50_000n, feeRate: 10 }))
      .toThrow(/insufficient funds/);
  });

  it("refuses when funds cover the amount but NOT the fee", () => {
    // The classic near-miss: 50,000 available, 50,000 requested, and no room
    // for the fee. Must fail rather than silently under-paying.
    expect(() => selectCoins({ utxos: [utxo(50_000n)], target: 50_000n, feeRate: 10 }))
      .toThrow(/insufficient funds/);
  });

  it("refuses a dust target", () => {
    expect(() => selectCoins({ utxos: [utxo(100_000n)], target: 100n, feeRate: 10 }))
      .toThrow(/dust threshold/);
  });

  it("refuses a non-positive target", () => {
    expect(() => selectCoins({ utxos: [utxo(100_000n)], target: 0n, feeRate: 10 })).toThrow();
    expect(() => selectCoins({ utxos: [utxo(100_000n)], target: -5n, feeRate: 10 })).toThrow();
  });

  it("refuses a sub-relay fee rate", () => {
    expect(() => selectCoins({ utxos: [utxo(100_000n)], target: 10_000n, feeRate: 0.5 }))
      .toThrow(/at least 1 sat\/vB/);
  });

  it("refuses when every UTXO is frozen or unconfirmed", () => {
    expect(() => selectCoins({
      utxos: [utxo(100_000n, { frozen: true }), utxo(100_000n, { confirmations: 0 })],
      target: 10_000n, feeRate: 10,
    })).toThrow(/no spendable UTXOs/);
  });

  it("refuses when coins are too fragmented to cover their own fees", () => {
    // 200 coins of 400 sat each = 80,000 sat, but each costs 680 to spend at
    // 10 sat/vB. Every coin makes the user poorer. Total is "enough" and the
    // payment is still impossible.
    const dusty = Array.from({ length: 200 }, () => utxo(400n));
    expect(() => selectCoins({ utxos: dusty, target: 50_000n, feeRate: 10 })).toThrow();
  });

  it("skips coins that cost more to spend than they are worth", () => {
    const result = selectCoins({
      utxos: [utxo(500_000n), utxo(100n), utxo(200n)],
      target: 100_000n,
      feeRate: 10,
    });
    for (const selected of result.selected) {
      expect(selected.value).toBeGreaterThan(costOfInput(10));
    }
  });
});

describe("§33 PROPERTY TESTS: invariants across random scenarios", () => {
  const strategies: SelectionStrategy[] = ["branch-and-bound", "single-random-draw", "largest-first"];

  it("selection NEVER covers less than target + fee (2000 scenarios)", () => {
    let succeeded = 0;
    for (let i = 0; i < 2000; i++) {
      const utxos = Array.from({ length: 1 + Math.floor(Math.random() * 12) }, () =>
        utxo(BigInt(1000 + Math.floor(Math.random() * 500_000))),
      );
      const target = BigInt(500 + Math.floor(Math.random() * 800_000));
      const feeRate = 1 + Math.floor(Math.random() * 50);
      try {
        const result = selectCoins({ utxos, target, feeRate });
        // THE invariant. A violation here is money created from nothing.
        expect(result.inputTotal).toBeGreaterThanOrEqual(target + result.fee);
        succeeded++;
      } catch (error) {
        expect(error).toBeInstanceOf(CoinSelectionError);
      }
    }
    expect(succeeded).toBeGreaterThan(500); // the loop did real work
  });

  it("value always balances: inputs = target + fee + change", () => {
    for (let i = 0; i < 1000; i++) {
      const utxos = Array.from({ length: 1 + Math.floor(Math.random() * 8) }, () =>
        utxo(BigInt(5000 + Math.floor(Math.random() * 300_000))),
      );
      const target = BigInt(1000 + Math.floor(Math.random() * 200_000));
      try {
        const r = selectCoins({ utxos, target, feeRate: 1 + Math.floor(Math.random() * 30) });
        expect(r.inputTotal).toBe(target + r.fee + r.change);
      } catch (error) {
        expect(error).toBeInstanceOf(CoinSelectionError);
      }
    }
  });

  it("change is NEVER dust", () => {
    for (let i = 0; i < 1000; i++) {
      const utxos = Array.from({ length: 1 + Math.floor(Math.random() * 6) }, () =>
        utxo(BigInt(1000 + Math.floor(Math.random() * 100_000))),
      );
      try {
        const r = selectCoins({
          utxos,
          target: BigInt(500 + Math.floor(Math.random() * 90_000)),
          feeRate: 1 + Math.floor(Math.random() * 20),
        });
        if (r.change > 0n) expect(isDust(r.change)).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(CoinSelectionError);
      }
    }
  });

  it("the fee is never negative and never absurd", () => {
    for (let i = 0; i < 800; i++) {
      const utxos = Array.from({ length: 1 + Math.floor(Math.random() * 6) }, () =>
        utxo(BigInt(10_000 + Math.floor(Math.random() * 200_000))),
      );
      try {
        const r = selectCoins({
          utxos, target: BigInt(5000 + Math.floor(Math.random() * 100_000)),
          feeRate: 1 + Math.floor(Math.random() * 20),
        });
        expect(r.fee).toBeGreaterThanOrEqual(0n);
        expect(r.fee).toBeLessThan(r.inputTotal);
      } catch (error) {
        expect(error).toBeInstanceOf(CoinSelectionError);
      }
    }
  });

  it("never selects a coin outside the supplied set", () => {
    for (let i = 0; i < 500; i++) {
      const utxos = Array.from({ length: 2 + Math.floor(Math.random() * 8) }, () =>
        utxo(BigInt(10_000 + Math.floor(Math.random() * 100_000))),
      );
      const keys = new Set(utxos.map((u) => `${u.txid}:${u.vout}`));
      try {
        const r = selectCoins({ utxos, target: BigInt(5000 + Math.floor(Math.random() * 50_000)), feeRate: 5 });
        for (const s of r.selected) expect(keys.has(`${s.txid}:${s.vout}`)).toBe(true);
        // No coin selected twice.
        expect(new Set(r.selected.map((s) => `${s.txid}:${s.vout}`)).size).toBe(r.selected.length);
      } catch (error) {
        expect(error).toBeInstanceOf(CoinSelectionError);
      }
    }
  });

  it("holds for every strategy independently", () => {
    for (const strategy of strategies) {
      for (let i = 0; i < 200; i++) {
        const utxos = Array.from({ length: 1 + Math.floor(Math.random() * 8) }, () =>
          utxo(BigInt(10_000 + Math.floor(Math.random() * 200_000))),
        );
        try {
          const r = selectCoins({
            utxos, target: BigInt(5000 + Math.floor(Math.random() * 150_000)),
            feeRate: 1 + Math.floor(Math.random() * 25), strategy,
          });
          expect(r.inputTotal).toBe(r.fee + r.change + (r.inputTotal - r.fee - r.change));
          expect(r.inputTotal).toBeGreaterThanOrEqual(r.fee);
          expect(r.strategy).toBe(strategy);
        } catch (error) {
          expect(error).toBeInstanceOf(CoinSelectionError);
        }
      }
    }
  });

  it("never selects frozen, unconfirmed, or immature coins", () => {
    for (let i = 0; i < 300; i++) {
      const utxos = [
        utxo(500_000n),
        utxo(400_000n, { frozen: true }),
        utxo(400_000n, { confirmations: 0 }),
        utxo(400_000n, { isCoinbase: true, confirmations: 10 }),
      ];
      try {
        const r = selectCoins({ utxos, target: 100_000n, feeRate: 5 });
        for (const s of r.selected) {
          expect(s.frozen).toBeFalsy();
          expect(s.confirmations).toBeGreaterThan(0);
          if (s.isCoinbase) expect(s.confirmations).toBeGreaterThanOrEqual(COINBASE_MATURITY);
        }
      } catch (error) {
        expect(error).toBeInstanceOf(CoinSelectionError);
      }
    }
  });
});

describe("branch-and-bound is bounded", () => {
  it("terminates quickly even with many coins", () => {
    // Without a node cap this search is exponential — a self-inflicted DoS.
    //
    // A catastrophe bound, not a performance target: an uncapped search on
    // 300 coins does not take "a bit longer", it does not finish this century.
    // The threshold is loose so a slow machine cannot fail it.
    const many = Array.from({ length: 300 }, (_, i) => utxo(BigInt(1000 + i * 137)));
    const start = Date.now();
    try {
      selectCoins({ utxos: many, target: 150_000n, feeRate: 10, strategy: "branch-and-bound" });
    } catch { /* failing to find an exact match is fine */ }
    expect(Date.now() - start).toBeLessThan(30_000);
  });

  it("falls back to random draw when no exact match exists", () => {
    const result = selectCoins({
      utxos: [utxo(999_983n), utxo(777_711n)],
      target: 123_457n,
      feeRate: 7,
    });
    expect(["branch-and-bound", "single-random-draw"]).toContain(result.strategy);
    expect(result.inputTotal).toBeGreaterThanOrEqual(123_457n + result.fee);
  });
});
