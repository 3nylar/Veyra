/**
 * THE CHAIN CACHE — fewer requests, never a staler answer
 *
 * The decorator exists to stop one sync pass asking the same server the same
 * questions 126 times. The risk in any cache over wallet data is that it
 * answers a question with something that WAS true, so these tests are mostly
 * about what it must refuse to cache.
 *
 * The sharpest of them is the broadcast case. Change goes to a fresh address
 * that was unused a moment ago and is therefore remembered as having no
 * history. Without a reset, the wallet would confidently report that the
 * payment it had just made never happened.
 */
import { describe, it, expect } from "vitest";
import { cachedChainSource } from "../../app/src/chain-cache.js";
import type {
  ChainSource,
  ChainUtxo,
  ChainTransaction,
  AddressActivity,
  FeeEstimates,
} from "../../core/chain/types.js";

const TXID = "a".repeat(64);
const USED = "tb1qused";
const UNUSED = "tb1qunused";

/** A chain source that records every call it receives. */
function fake(options: { withHistory?: boolean; withFees?: boolean } = {}) {
  const calls: string[] = [];
  let height = 800_000;

  const source: ChainSource & { isThirdParty: boolean; privacyWarning: string | null } = {
    name: "Fake",
    network: "testnet",
    isThirdParty: true,
    privacyWarning: "a warning",

    async getBlockHeight() {
      calls.push("height");
      return height;
    },
    async getUtxos(address: string): Promise<ChainUtxo[]> {
      calls.push(`utxos:${address}`);
      return [];
    },
    async getAddressActivity(address: string): Promise<AddressActivity> {
      calls.push(`activity:${address}`);
      return { address, hasHistory: address === USED, utxos: [] };
    },
    async broadcast(hex: string) {
      calls.push(`broadcast:${hex.slice(0, 4)}`);
      return TXID;
    },
    ...(options.withHistory !== false
      ? {
          async getTransactions(address: string): Promise<ChainTransaction[]> {
            calls.push(`txs:${address}`);
            return [{ txid: TXID, confirmations: 3 }];
          },
        }
      : {}),
    ...(options.withFees
      ? {
          async getFeeEstimates(): Promise<FeeEstimates> {
            calls.push("fees");
            return { source: "fake", fetchedAt: 0 };
          },
        }
      : {}),
  };

  return { source, calls, setHeight: (n: number) => (height = n) };
}

describe("block height", () => {
  it("is fetched once for a whole pass, not once per address", async () => {
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    for (let i = 0; i < 40; i++) await cached.getBlockHeight();

    expect(calls.filter((c) => c === "height")).toHaveLength(1);
  });

  it("shares ONE request between concurrent callers", async () => {
    // The promise is cached, not the resolved value. Caching only the value
    // leaves a window where forty callers all start their own request — which
    // is exactly when the stampede happens.
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    const results = await Promise.all(
      Array.from({ length: 40 }, () => cached.getBlockHeight()),
    );

    expect(calls.filter((c) => c === "height")).toHaveLength(1);
    expect(new Set(results)).toEqual(new Set([800_000]));
  });

  it("does not cache a FAILURE as the answer", async () => {
    // A failed request must not lock in an error for thirty seconds; the next
    // caller expects a retry.
    let attempts = 0;
    const source = {
      ...fake().source,
      async getBlockHeight() {
        attempts += 1;
        if (attempts === 1) throw new Error("network down");
        return 800_001;
      },
    };
    const cached = cachedChainSource(source);

    await expect(cached.getBlockHeight()).rejects.toThrow("network down");
    await expect(cached.getBlockHeight()).resolves.toBe(800_001);
    expect(attempts).toBe(2);
  });
});

describe("transactions", () => {
  it("SKIPS the request for an address the scan just found unused", async () => {
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    await cached.getAddressActivity(UNUSED);
    calls.length = 0;

    await expect(cached.getTransactions!(UNUSED)).resolves.toEqual([]);
    expect(calls).toEqual([]); // no request at all
  });

  it("still asks for an address that HAS history", async () => {
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    await cached.getAddressActivity(USED);
    calls.length = 0;

    await cached.getTransactions!(USED);
    expect(calls).toEqual([`txs:${USED}`]);
  });

  it("still asks about an address it has never scanned", async () => {
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    await cached.getTransactions!("tb1qneverscanned");
    expect(calls).toEqual(["txs:tb1qneverscanned"]);
  });

  it("NEVER serves a remembered transaction list", async () => {
    // Stale history hides a payment that has since arrived. Only requests that
    // are provably unnecessary are skipped; answers are never reused.
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    await cached.getAddressActivity(USED);
    await cached.getTransactions!(USED);
    await cached.getTransactions!(USED);

    expect(calls.filter((c) => c === `txs:${USED}`)).toHaveLength(2);
  });
});

describe("activity", () => {
  it("NEVER serves a remembered UTXO set", async () => {
    // A stale UTXO set is a wrong balance, which is the worst thing a wallet
    // can display.
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    await cached.getAddressActivity(USED);
    await cached.getAddressActivity(USED);

    expect(calls.filter((c) => c === `activity:${USED}`)).toHaveLength(2);
  });
});

describe("broadcast", () => {
  it("FORGETS which addresses were unused", async () => {
    // ⚠️ The subtle one. Change is paid to a fresh address that was unused a
    // moment ago and is remembered as `false`. Without this reset the wallet's
    // own outgoing transaction would be skipped and never appear in history.
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    await cached.getAddressActivity(UNUSED);
    await cached.broadcast("0200000001abcd");
    calls.length = 0;

    await cached.getTransactions!(UNUSED);

    expect(calls).toEqual([`txs:${UNUSED}`]);
  });

  it("also forgets the block height", async () => {
    // A broadcast changes what is in the mempool, and confirmation counts are
    // computed against the tip.
    const { source, calls } = fake();
    const cached = cachedChainSource(source);

    await cached.getBlockHeight();
    await cached.broadcast("0200000001abcd");
    calls.length = 0;

    await cached.getBlockHeight();
    expect(calls).toEqual(["height"]);
  });
});

describe("optional methods", () => {
  it("PRESERVES the absence of getTransactions", async () => {
    // Wallet.history() branches on `if (!source.getTransactions)` to produce a
    // useful message. A class wrapper would always have the method on its
    // prototype, so that check would pass and core would call something that
    // throws — turning clear guidance into a stack trace. This is why the
    // decorator is an object literal with conditional spreads.
    const { source } = fake({ withHistory: false });
    const cached = cachedChainSource(source);

    expect(cached.getTransactions).toBeUndefined();
  });

  it("preserves the absence of getFeeEstimates", () => {
    const { source } = fake();
    expect(cachedChainSource(source).getFeeEstimates).toBeUndefined();
  });

  it("forwards them when they do exist", async () => {
    const { source, calls } = fake({ withFees: true });
    const cached = cachedChainSource(source);

    expect(cached.getFeeEstimates).toBeTypeOf("function");
    await cached.getFeeEstimates!();
    expect(calls).toContain("fees");
  });

  it("forwards the privacy surface the settings screen reads", () => {
    const { source } = fake();
    const cached = cachedChainSource(source);

    expect(cached.isThirdParty).toBe(true);
    expect(cached.privacyWarning).toBe("a warning");
    expect(cached.name).toBe("Fake");
    expect(cached.network).toBe("testnet");
  });
});
