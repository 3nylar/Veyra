/**
 * TRANSACTION HISTORY AND FEE ESTIMATION
 *
 * The property under test for history is **folding**. One transaction touches
 * several of our addresses at once — a spend consumes inputs from one and
 * returns change to another. Reporting those separately shows a single payment
 * twice, with amounts that describe neither what was sent nor what was kept.
 *
 * For fee estimation the property is **honesty**: the caller must always be
 * able to tell whether a number came from the network or is a static guess.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { Wallet, WalletError } from "../../core/wallet/wallet.js";
import { MemoryChainSource } from "../../core/chain/memory.js";
import { TESTNET } from "../../core/bitcoin/networks.js";
import { FEE_RATE_PRESETS } from "../../core/utxo/fees.js";
import type { ChainSource, ChainTransaction, FeeEstimates } from "../../core/chain/types.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const txid = (n: number) => n.toString(16).padStart(8, "0").repeat(8).slice(0, 64);

let wallet: Wallet;
let addresses: string[];

beforeEach(() => {
  wallet = Wallet.restore(MNEMONIC, TESTNET);
  addresses = wallet.receiveAddresses(5).map((a) => a.address);
});

/** A source returning canned history per address. */
function historySource(byAddress: Record<string, ChainTransaction[]>): ChainSource {
  return {
    name: "test",
    network: "testnet",
    getBlockHeight: async () => 200,
    getUtxos: async () => [],
    getAddressActivity: async (address) => ({ address, hasHistory: false, utxos: [] }),
    broadcast: async () => txid(1),
    getTransactions: async (address) => byAddress[address] ?? [],
  };
}

describe("history: folding across addresses", () => {
  it("returns a single entry for a transaction touching one address", async () => {
    const source = historySource({
      [addresses[0]!]: [
        { txid: txid(1), confirmations: 3, netValue: 100_000n, direction: "received" },
      ],
    });
    const history = await wallet.history(source);
    expect(history.length).toBe(1);
    expect(history[0]!.netValue).toBe(100_000n);
  });

  it("FOLDS a transaction touching several of our addresses into one entry", async () => {
    // The realistic case: a spend consumes 1.0 from address 0 and returns
    // 0.9 change to address 1. Two entries, one payment.
    const source = historySource({
      [addresses[0]!]: [
        { txid: txid(7), confirmations: 2, netValue: -100_000_000n, direction: "sent" },
      ],
      [addresses[1]!]: [
        { txid: txid(7), confirmations: 2, netValue: 90_000_000n, direction: "received" },
      ],
    });

    const history = await wallet.history(source);

    // Reporting two entries would show a 1.0 send AND a 0.9 receive — both
    // misleading about what happened.
    expect(history.length).toBe(1);
    expect(history[0]!.netValue).toBe(-10_000_000n); // the real cost
    expect(history[0]!.direction).toBe("sent");
  });

  it("the folded direction reflects the SUM, not the first entry seen", async () => {
    // Address 0 shows a large outgoing, address 1 a larger incoming. Net is a
    // receive, even though the first entry encountered was a send.
    const source = historySource({
      [addresses[0]!]: [{ txid: txid(9), confirmations: 1, netValue: -50_000n, direction: "sent" }],
      [addresses[1]!]: [{ txid: txid(9), confirmations: 1, netValue: 200_000n, direction: "received" }],
    });
    const history = await wallet.history(source);
    expect(history[0]!.netValue).toBe(150_000n);
    expect(history[0]!.direction).toBe("received");
  });

  it("marks a wallet-internal transfer as 'internal' when the net is zero", async () => {
    const source = historySource({
      [addresses[0]!]: [{ txid: txid(11), confirmations: 5, netValue: -70_000n, direction: "sent" }],
      [addresses[1]!]: [{ txid: txid(11), confirmations: 5, netValue: 70_000n, direction: "received" }],
    });
    const history = await wallet.history(source);
    expect(history[0]!.netValue).toBe(0n);
    expect(history[0]!.direction).toBe("internal");
  });

  it("keeps distinct transactions distinct", async () => {
    const source = historySource({
      [addresses[0]!]: [
        { txid: txid(1), confirmations: 5, netValue: 100_000n, direction: "received" },
        { txid: txid(2), confirmations: 3, netValue: 50_000n, direction: "received" },
      ],
      [addresses[1]!]: [
        { txid: txid(3), confirmations: 1, netValue: -20_000n, direction: "sent" },
      ],
    });
    expect((await wallet.history(source)).length).toBe(3);
  });

  it("preserves a known fee when folding", async () => {
    const source = historySource({
      [addresses[0]!]: [
        { txid: txid(5), confirmations: 2, netValue: -100_000n, direction: "sent", fee: 705n },
      ],
      [addresses[1]!]: [
        { txid: txid(5), confirmations: 2, netValue: 89_295n, direction: "received" },
      ],
    });
    expect((await wallet.history(source))[0]!.fee).toBe(705n);
  });
});

describe("history: ordering and limits", () => {
  it("puts UNCONFIRMED transactions first", async () => {
    // What has not settled is what a user most needs to see.
    const source = historySource({
      [addresses[0]!]: [
        { txid: txid(1), confirmations: 100, netValue: 1n, blockTime: 1000 },
        { txid: txid(2), confirmations: 0, netValue: 2n },
        { txid: txid(3), confirmations: 5, netValue: 3n, blockTime: 2000 },
      ],
    });
    const history = await wallet.history(source);
    expect(history[0]!.confirmations).toBe(0);
  });

  it("orders confirmed transactions newest first", async () => {
    const source = historySource({
      [addresses[0]!]: [
        { txid: txid(1), confirmations: 5, netValue: 1n, blockTime: 1000 },
        { txid: txid(2), confirmations: 5, netValue: 2n, blockTime: 3000 },
        { txid: txid(3), confirmations: 5, netValue: 3n, blockTime: 2000 },
      ],
    });
    const history = await wallet.history(source);
    expect(history.map((t) => t.blockTime)).toEqual([3000, 2000, 1000]);
  });

  it("respects a limit", async () => {
    const entries = Array.from({ length: 50 }, (_, i) => ({
      txid: txid(i + 1), confirmations: i, netValue: BigInt(i + 1),
    }));
    const source = historySource({ [addresses[0]!]: entries });
    expect((await wallet.history(source, { limit: 10 })).length).toBe(10);
  });
});

describe("history: failure handling", () => {
  it("throws when the source cannot provide history at all", async () => {
    const source = new MemoryChainSource("testnet");
    // MemoryChainSource does support it, so strip the method to simulate one
    // that does not.
    const without = { ...source, getTransactions: undefined } as unknown as ChainSource;
    await expect(wallet.history(without)).rejects.toThrow(/does not provide transaction history/);
  });

  it("SURFACES a missing watch-only wallet rather than reporting an empty history", async () => {
    // "You have no transactions" is a damaging thing to say incorrectly. An
    // unconfigured source and a genuinely empty history look identical to a
    // caller, so the configuration error must not be swallowed.
    const source: ChainSource = {
      name: "rpc", network: "testnet",
      getBlockHeight: async () => 1,
      getUtxos: async () => [],
      getAddressActivity: async (address) => ({ address, hasHistory: false, utxos: [] }),
      broadcast: async () => txid(1),
      getTransactions: async () => {
        throw new Error("watch-only wallet 'veyra-watch' does not exist — call importAddressesForHistory() before requesting history");
      },
    };
    await expect(wallet.history(source)).rejects.toThrow(WalletError);
  });

  it("one failing address does not lose the whole history", async () => {
    let calls = 0;
    const source: ChainSource = {
      name: "flaky", network: "testnet",
      getBlockHeight: async () => 1,
      getUtxos: async () => [],
      getAddressActivity: async (address) => ({ address, hasHistory: false, utxos: [] }),
      broadcast: async () => txid(1),
      getTransactions: async (address) => {
        calls++;
        if (address === addresses[1]) throw new Error("transient upstream failure");
        if (address === addresses[0]) {
          return [{ txid: txid(1), confirmations: 2, netValue: 500n, direction: "received" as const }];
        }
        return [];
      },
    };
    const history = await wallet.history(source);
    expect(history.length).toBe(1);
    expect(calls).toBeGreaterThan(2);
  });
});

describe("fee estimation", () => {
  function feeSource(estimates: Partial<FeeEstimates>): ChainSource {
    return {
      name: "estimator", network: "testnet",
      getBlockHeight: async () => 1,
      getUtxos: async () => [],
      getAddressActivity: async (address) => ({ address, hasHistory: false, utxos: [] }),
      broadcast: async () => txid(1),
      getFeeEstimates: async () => ({ source: "estimator", fetchedAt: Date.now(), ...estimates }),
    };
  }

  it("uses live estimates when available, and marks them live", async () => {
    const result = await wallet.feeEstimates(feeSource({ high: 42, medium: 15, low: 3 }));
    expect(result.high).toBe(42);
    expect(result.isLive).toBe(true);
    expect(result.source).toBe("estimator");
  });

  it("falls back to static defaults with NO source, and says so", async () => {
    const result = await wallet.feeEstimates();
    expect(result.isLive).toBe(false);
    expect(result.high).toBe(FEE_RATE_PRESETS.high);
    expect(result.source).toMatch(/not live/);
  });

  it("falls back when a source has no estimates — the regtest case", async () => {
    // A private chain has no fee market. Returning nothing is correct
    // behaviour, not a failure.
    const result = await wallet.feeEstimates(feeSource({}));
    expect(result.isLive).toBe(false);
    expect(result.source).toMatch(/no estimates yet/);
    expect(result.high).toBe(FEE_RATE_PRESETS.high);
  });

  it("fills a MISSING target from the fallback rather than leaving it blank", async () => {
    // A UI must never have to render an empty fee option.
    const result = await wallet.feeEstimates(feeSource({ high: 50 }));
    expect(result.high).toBe(50);
    expect(result.medium).toBe(FEE_RATE_PRESETS.medium);
    expect(result.low).toBe(FEE_RATE_PRESETS.low);
    expect(result.isLive).toBe(true);
  });

  it("falls back when the source throws rather than failing the whole call", async () => {
    const broken: ChainSource = {
      name: "broken", network: "testnet",
      getBlockHeight: async () => 1,
      getUtxos: async () => [],
      getAddressActivity: async (address) => ({ address, hasHistory: false, utxos: [] }),
      broadcast: async () => txid(1),
      getFeeEstimates: async () => { throw new Error("upstream down"); },
    };
    const result = await wallet.feeEstimates(broken);
    expect(result.isLive).toBe(false);
    expect(result.high).toBe(FEE_RATE_PRESETS.high);
  });

  it("a source without the method falls back cleanly", async () => {
    const result = await wallet.feeEstimates(new MemoryChainSource("testnet"));
    expect(result.isLive).toBe(false);
  });

  it("every returned rate is at or above the relay minimum", async () => {
    for (const estimates of [{}, { high: 1 }, { high: 99, medium: 2, low: 1 }]) {
      const result = await wallet.feeEstimates(feeSource(estimates));
      for (const rate of [result.high, result.medium, result.low]) {
        expect(rate).toBeGreaterThanOrEqual(1);
      }
    }
  });
});
