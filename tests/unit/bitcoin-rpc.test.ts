/**
 * BITCOIN CORE RPC CLIENT TESTS
 *
 * ⚠️ These test the CLIENT against a controlled fake, not a real node. The
 * genuine verification is tests/integration/regtest.test.ts, which requires
 * bitcoind and is skipped without it.
 *
 * The most important tests here are the amount conversions. Core reports BTC
 * as JSON numbers — IEEE doubles — and money arithmetic on floats is how
 * rounding errors become lost funds.
 */
import { describe, it, expect } from "vitest";
import { BitcoinRpcChainSource, btcToSatoshis } from "../../core/chain/bitcoinRpc.js";
import { ChainError } from "../../core/chain/types.js";

const TXID = "a".repeat(64);
const ADDRESS = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/** A fake node returning canned results keyed by RPC method. */
function fakeNode(results: Record<string, unknown>, opts: { status?: number } = {}): typeof fetch {
  return (async (_url: string, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as { method: string };
    const status = opts.status ?? 200;
    if (status !== 200) {
      return { ok: false, status, text: async () => "unauthorized" } as Response;
    }
    if (!(body.method in results)) {
      return {
        ok: true, status: 200,
        text: async () => JSON.stringify({ error: { code: -32601, message: "Method not found" } }),
      } as Response;
    }
    const value = results[body.method];
    return {
      ok: true, status: 200,
      text: async () => JSON.stringify(
        value instanceof Error
          ? { error: { code: -1, message: value.message } }
          : { result: value, error: null },
      ),
    } as Response;
  }) as unknown as typeof fetch;
}

function node(results: Record<string, unknown>, overrides = {}) {
  return new BitcoinRpcChainSource({
    url: "http://127.0.0.1:18443",
    username: "u", password: "p", network: "regtest",
    fetchImpl: fakeNode(results), ...overrides,
  });
}

describe("btcToSatoshis — exact decimal conversion", () => {
  it("converts whole and fractional BTC exactly", () => {
    expect(btcToSatoshis(1, "x")).toBe(100_000_000n);
    expect(btcToSatoshis(0.5, "x")).toBe(50_000_000n);
    expect(btcToSatoshis(0.00000001, "x")).toBe(1n);
    expect(btcToSatoshis(21_000_000, "x")).toBe(2_100_000_000_000_000n);
  });

  it("handles values where naive float multiplication FAILS", () => {
    // 0.1 * 1e8 is 10000000.000000002 in IEEE 754; 4.35 * 1e8 is
    // 434999999.99999994. Math.round would hide it here but not everywhere,
    // and "usually correct" is not a property money arithmetic may have.
    expect(btcToSatoshis(0.1, "x")).toBe(10_000_000n);
    expect(btcToSatoshis(4.35, "x")).toBe(435_000_000n);
    expect(btcToSatoshis(0.29, "x")).toBe(29_000_000n);
    expect(btcToSatoshis(1.005, "x")).toBe(100_500_000n);
  });

  it("accepts decimal strings, which avoid float representation entirely", () => {
    expect(btcToSatoshis("0.00000001", "x")).toBe(1n);
    expect(btcToSatoshis("12.34567891", "x")).toBe(1_234_567_891n);
  });

  it("rejects more than 8 decimal places — sub-satoshi amounts do not exist", () => {
    expect(() => btcToSatoshis("0.000000001", "x")).toThrow(/8 decimal places/);
  });

  it("rejects negatives, exponents, and junk", () => {
    expect(() => btcToSatoshis("-1.0", "x")).toThrow(/negative/);
    expect(() => btcToSatoshis("1e8", "x")).toThrow(/plain decimal/);
    expect(() => btcToSatoshis("abc", "x")).toThrow();
    expect(() => btcToSatoshis(null, "x")).toThrow();
    expect(() => btcToSatoshis({}, "x")).toThrow();
  });

  it("rejects amounts above the money supply", () => {
    expect(() => btcToSatoshis("21000001", "x")).toThrow(/money supply/);
  });
});

describe("connection and configuration", () => {
  it("rejects a URL without a scheme", () => {
    expect(() => new BitcoinRpcChainSource({
      url: "127.0.0.1:18443", username: "u", password: "p", network: "regtest",
    })).toThrow(/http/);
  });

  it("verifies the node is on the expected chain", async () => {
    const info = await node({ getblockchaininfo: { chain: "regtest", blocks: 150 } }).verifyConnection();
    expect(info.chain).toBe("regtest");
    expect(info.blocks).toBe(150);
  });

  it("REFUSES a node serving a different chain than configured", async () => {
    // Syncing a regtest wallet against a mainnet node would report a nonsense
    // balance built from unrelated coins.
    await expect(node({ getblockchaininfo: { chain: "main", blocks: 800000 } }).verifyConnection())
      .rejects.toThrow(/'main'.*'regtest'/);
  });

  it("reports an authentication failure clearly", async () => {
    await expect(node({}, { fetchImpl: fakeNode({}, { status: 401 }) }).getBlockHeight())
      .rejects.toThrow(/authentication failed/);
  });

  it("surfaces an RPC error with its code and message", async () => {
    await expect(node({ getblockcount: new Error("Loading block index...") }).getBlockHeight())
      .rejects.toThrow(/Loading block index/);
  });

  it("detects a non-bitcoind endpoint", async () => {
    const notANode = new BitcoinRpcChainSource({
      url: "http://127.0.0.1:8080", username: "u", password: "p", network: "regtest",
      fetchImpl: (async () => ({ ok: true, status: 200, text: async () => "<html>hello</html>" } as Response)) as unknown as typeof fetch,
    });
    await expect(notANode.getBlockHeight()).rejects.toThrow(/is this a bitcoind RPC endpoint/);
  });

  it("identifies a local node as not third-party", () => {
    expect(node({}).isThirdParty).toBe(false);
    expect(new BitcoinRpcChainSource({
      url: "http://node.example.com:8332", username: "u", password: "p", network: "mainnet",
    }).isThirdParty).toBe(true);
  });

  it("never puts credentials in the URL", () => {
    // Credentials in a URL end up in logs, referrers, and shell history.
    const source = node({});
    expect(source.name).not.toContain("u:p");
    expect(source.name).toBe("bitcoind(127.0.0.1:18443)");
  });
});

describe("getUtxos via scantxoutset", () => {
  const results = {
    getblockcount: 200,
    scantxoutset: {
      success: true,
      unspents: [
        { txid: TXID, vout: 0, amount: 0.005, height: 195 },
        { txid: "b".repeat(64), vout: 2, amount: 1.23456789, height: 200 },
      ],
    },
  };

  it("parses unspents and converts amounts to satoshis", async () => {
    const utxos = await node(results).getUtxos(ADDRESS);
    expect(utxos.length).toBe(2);
    expect(utxos[0]!.value).toBe(500_000n);
    expect(utxos[1]!.value).toBe(123_456_789n);
    expect(typeof utxos[0]!.value).toBe("bigint");
  });

  it("computes confirmations from height and tip", async () => {
    const utxos = await node(results).getUtxos(ADDRESS);
    expect(utxos[0]!.confirmations).toBe(6); // 200 - 195 + 1
    expect(utxos[1]!.confirmations).toBe(1);
  });

  it("rejects an unsuccessful scan rather than reporting zero balance", async () => {
    await expect(node({ ...results, scantxoutset: { success: false } }).getUtxos(ADDRESS))
      .rejects.toThrow(/did not complete successfully/);
  });

  it("rejects a malformed unspents array", async () => {
    await expect(node({ ...results, scantxoutset: { success: true } }).getUtxos(ADDRESS))
      .rejects.toThrow(/no unspents array/);
    await expect(node({
      ...results,
      scantxoutset: { success: true, unspents: [{ txid: "bad", vout: 0, amount: 1, height: 1 }] },
    }).getUtxos(ADDRESS)).rejects.toThrow(/hex txid/);
  });

  it("bounds the number of returned outputs", async () => {
    await expect(node({
      ...results,
      scantxoutset: {
        success: true,
        unspents: Array.from({ length: 10_001 }, () => ({ txid: TXID, vout: 0, amount: 0.001, height: 1 })),
      },
    }).getUtxos(ADDRESS)).rejects.toThrow(/implausible number/);
  });

  it("rejects implausible addresses before making a request", async () => {
    const source = node(results);
    await expect(source.getUtxos("short")).rejects.toThrow(/implausible address/);
    await expect(source.getUtxos("bcrt1q/../../etc")).rejects.toThrow(/not alphanumeric/);
  });
});

describe("broadcast", () => {
  it("returns the txid Core reports", async () => {
    expect(await node({ sendrawtransaction: TXID }).broadcast("0200000001ab")).toBe(TXID);
  });

  it("surfaces Core's rejection reason", async () => {
    // The single most valuable error in the system: Core telling us exactly
    // which consensus or policy rule our transaction broke.
    await expect(
      node({ sendrawtransaction: new Error("min relay fee not met, 100 < 141") })
        .broadcast("0200000001ab"),
    ).rejects.toThrow(/min relay fee not met/);
  });

  it("rejects malformed hex before sending", async () => {
    const source = node({ sendrawtransaction: TXID });
    await expect(source.broadcast("nothex")).rejects.toThrow(/hexadecimal/);
    await expect(source.broadcast("abc")).rejects.toThrow(/even-length/);
  });
});

describe("regtest-only helpers are gated by network", () => {
  const mainnet = () => new BitcoinRpcChainSource({
    url: "http://127.0.0.1:8332", username: "u", password: "p", network: "mainnet",
    fetchImpl: fakeNode({}),
  });

  it("refuses generateToAddress off regtest", async () => {
    await expect(mainnet().generateToAddress(101, ADDRESS)).rejects.toThrow(/only permitted on regtest/);
  });

  it("refuses fundAddress off regtest", async () => {
    await expect(mainnet().fundAddress("w", ADDRESS, 1000n)).rejects.toThrow(/only permitted on regtest/);
  });

  it("bounds the block count on regtest", async () => {
    await expect(node({}).generateToAddress(0, ADDRESS)).rejects.toThrow(/between 1 and 1000/);
    await expect(node({}).generateToAddress(5000, ADDRESS)).rejects.toThrow(/between 1 and 1000/);
  });
});

describe("transaction history", () => {
  it("REPORTS a missing watch-only wallet rather than returning an empty array", async () => {
    // Returning [] would let a caller mistake an unconfigured source for "no
    // history" — a silent wrong answer, and "you have no transactions" is a
    // damaging thing to say incorrectly.
    const source = node({
      listtransactions: new Error("Requested wallet does not exist or is not loaded"),
    });
    await expect(source.getTransactions(ADDRESS)).rejects.toThrow(/importAddressesForHistory/);
  });

  it("parses entries and computes direction from the signed amount", async () => {
    const source = node({
      listtransactions: [
        { txid: TXID, address: ADDRESS, amount: 0.005, confirmations: 6, blocktime: 1700000000 },
      ],
    });
    const history = await source.getTransactions(ADDRESS);
    expect(history.length).toBe(1);
    expect(history[0]!.netValue).toBe(500_000n);
    expect(history[0]!.direction).toBe("received");
    expect(history[0]!.confirmations).toBe(6);
  });

  it("treats a NEGATIVE amount as a send", async () => {
    // Core reports sends as negative BTC. btcToSatoshis rejects negatives, so
    // the sign must be handled before conversion, not after.
    const source = node({
      listtransactions: [
        { txid: TXID, address: ADDRESS, amount: -0.002, confirmations: 1, fee: -0.00000705 },
      ],
    });
    const history = await source.getTransactions(ADDRESS);
    expect(history[0]!.netValue).toBe(-200_000n);
    expect(history[0]!.direction).toBe("sent");
    expect(history[0]!.fee).toBe(705n);
  });

  it("FOLDS several entries for one txid by summing their amounts", async () => {
    // Core emits one entry per matching output, so a transaction paying an
    // address twice appears twice.
    const source = node({
      listtransactions: [
        { txid: TXID, address: ADDRESS, amount: 0.001, confirmations: 2 },
        { txid: TXID, address: ADDRESS, amount: 0.002, confirmations: 2 },
      ],
    });
    const history = await source.getTransactions(ADDRESS);
    expect(history.length).toBe(1);
    expect(history[0]!.netValue).toBe(300_000n);
  });

  it("ignores entries for other addresses", async () => {
    const source = node({
      listtransactions: [
        { txid: TXID, address: ADDRESS, amount: 0.001, confirmations: 2 },
        { txid: "c".repeat(64), address: "bcrt1qsomeoneelse", amount: 5, confirmations: 2 },
      ],
    });
    expect((await source.getTransactions(ADDRESS)).length).toBe(1);
  });

  it("rejects a malformed txid in the response", async () => {
    const source = node({
      listtransactions: [{ txid: "nope", address: ADDRESS, amount: 0.001, confirmations: 1 }],
    });
    await expect(source.getTransactions(ADDRESS)).rejects.toThrow(/hex txid/);
  });
});

describe("fee estimation", () => {
  it("converts BTC/kvB to sat/vB", async () => {
    // Core reports BTC per kvB. 0.00002 BTC/kvB = 2000 sat per 1000 vB = 2 sat/vB.
    const source = node({ estimatesmartfee: { feerate: 0.00002, blocks: 6 } });
    const estimates = await source.getFeeEstimates();
    expect(estimates.high).toBe(2);
    expect(estimates.medium).toBe(2);
    expect(estimates.low).toBe(2);
  });

  it("REGRESSION (VEY-011): float conversion overcharges by up to 100%", async () => {
    // `(0.00002 * 1e8) / 1000` is 2.0000000000000004 in IEEE 754, and
    // Math.ceil turns that into 3 — a fee rate 50% above what the node
    // recommended. 0.00001 is worse: 1 becomes 2, a 100% overcharge.
    //
    // These are ordinary rates, not contrived edge cases, which is what makes
    // the bug expensive. The fix converts through the decimal string.
    for (const [feerate, expected] of [
      [0.00001, 1],
      [0.00002, 2],
      [0.00003, 3],
      [0.00007, 7],
      [0.0001, 10],
      [0.00025, 25],
      [0.001, 100],
    ] as const) {
      const source = node({ estimatesmartfee: { feerate } });
      const estimates = await source.getFeeEstimates();
      expect(estimates.high, `feerate ${feerate}`).toBe(expected);
    }
  });

  it("rounds UP a fractional sat/vB, because under-paying risks a stuck transaction", async () => {
    // 0.00000253 BTC/kvB = 253 sat/kvB = 0.253 sat/vB -> 1 sat/vB.
    const source = node({ estimatesmartfee: { feerate: 0.00000253 } });
    expect((await source.getFeeEstimates()).high).toBe(1);
  });

  it("OMITS a target Core cannot estimate, rather than guessing", async () => {
    // Regtest does exactly this: no fee market, no history, errors for every
    // target. Absent is the honest answer.
    const source = node({ estimatesmartfee: { errors: ["Insufficient data"] } });
    const estimates = await source.getFeeEstimates();
    expect(estimates.high).toBeUndefined();
    expect(estimates.medium).toBeUndefined();
    expect(estimates.low).toBeUndefined();
    expect(estimates.source).toContain("bitcoind");
  });

  it("never returns a rate below the relay minimum", async () => {
    const source = node({ estimatesmartfee: { feerate: 0.000000001 } });
    const estimates = await source.getFeeEstimates();
    if (estimates.high !== undefined) expect(estimates.high).toBeGreaterThanOrEqual(1);
  });

  it("survives a failing target without failing the whole call", async () => {
    const source = node({ estimatesmartfee: new Error("Method not found") });
    const estimates = await source.getFeeEstimates();
    expect(estimates.source).toContain("bitcoind");
    expect(estimates.high).toBeUndefined();
  });
});
