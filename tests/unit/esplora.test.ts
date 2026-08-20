/**
 * ESPLORA CLIENT TESTS
 *
 * ⚠️ These test the CLIENT, not the server contract. The fake below returns
 * what the Esplora API documentation says a server returns. If the real API
 * differs, these tests pass and the client is still wrong.
 *
 * What IS verified here: defensive parsing, malformed-response handling,
 * timeouts, retry behaviour, size limits, and URL construction.
 * What is NOT verified: that a live server's responses match this shape.
 * That requires a regtest Esplora instance and is recorded as outstanding in
 * the module header and the README.
 */
import { describe, it, expect } from "vitest";
import { EsploraChainSource } from "../../core/chain/esplora.js";
import { ChainError, validateAmount, validateTxid, normalizeConfirmations } from "../../core/chain/types.js";

const TXID_A = "a".repeat(64);
const TXID_B = "b".repeat(64);
const ADDRESS = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

/** Build a fake fetch returning canned responses keyed by URL suffix. */
function fakeFetch(routes: Record<string, { body: string; status?: number }>): typeof fetch {
  return (async (url: string | URL) => {
    const path = url.toString();
    for (const [suffix, response] of Object.entries(routes)) {
      if (path.endsWith(suffix)) {
        const status = response.status ?? 200;
        return {
          ok: status >= 200 && status < 300,
          status,
          text: async () => response.body,
        } as Response;
      }
    }
    return { ok: false, status: 404, text: async () => "Not Found" } as Response;
  }) as unknown as typeof fetch;
}

function client(routes: Record<string, { body: string; status?: number }>, overrides = {}) {
  return new EsploraChainSource({
    baseUrl: "https://example.test/api",
    network: "testnet",
    fetchImpl: fakeFetch(routes),
    maxRetries: 0,
    ...overrides,
  });
}

describe("construction", () => {
  it("rejects a base URL without a scheme", () => {
    expect(() => new EsploraChainSource({ baseUrl: "example.test/api", network: "testnet" }))
      .toThrow(/http/);
  });

  it("REJECTS a trailing slash rather than normalising it", () => {
    // Silently repairing configuration hides typos that might point at an
    // unintended host.
    expect(() => new EsploraChainSource({ baseUrl: "https://example.test/api/", network: "testnet" }))
      .toThrow(/must not end with a slash/);
  });

  it("identifies third-party servers and warns about the privacy cost", () => {
    const remote = client({});
    expect(remote.isThirdParty).toBe(true);
    expect(remote.privacyWarning).toContain("every address");

    const local = new EsploraChainSource({
      baseUrl: "http://localhost:3002", network: "regtest", fetchImpl: fakeFetch({}),
    });
    expect(local.isThirdParty).toBe(false);
    expect(local.privacyWarning).toBeNull();
  });
});

describe("getBlockHeight", () => {
  it("parses a plain-text height", async () => {
    expect(await client({ "/blocks/tip/height": { body: "2500000" } }).getBlockHeight()).toBe(2_500_000);
  });

  it("rejects a non-numeric response", async () => {
    await expect(client({ "/blocks/tip/height": { body: "<html>error</html>" } }).getBlockHeight())
      .rejects.toThrow(/implausible block height/);
  });

  it("rejects an implausible height", async () => {
    await expect(client({ "/blocks/tip/height": { body: "999999999999" } }).getBlockHeight())
      .rejects.toThrow(/implausible/);
    await expect(client({ "/blocks/tip/height": { body: "-5" } }).getBlockHeight())
      .rejects.toThrow();
  });
});

describe("getUtxos", () => {
  const routes = {
    "/blocks/tip/height": { body: "200" },
    "/utxo": {
      body: JSON.stringify([
        { txid: TXID_A, vout: 0, value: 100000, status: { confirmed: true, block_height: 195 } },
        { txid: TXID_B, vout: 1, value: 50000, status: { confirmed: false } },
      ]),
    },
  };

  it("parses UTXOs and computes confirmations from the tip", async () => {
    const utxos = await client(routes).getUtxos(ADDRESS);
    expect(utxos.length).toBe(2);
    expect(utxos[0]!.value).toBe(100_000n);
    expect(utxos[0]!.confirmations).toBe(6); // 200 - 195 + 1
    expect(utxos[1]!.confirmations).toBe(0); // unconfirmed
  });

  it("returns amounts as BigInt, never number", async () => {
    const utxos = await client(routes).getUtxos(ADDRESS);
    expect(typeof utxos[0]!.value).toBe("bigint");
  });

  it("rejects a non-array response", async () => {
    await expect(client({ ...routes, "/utxo": { body: '{"error":"nope"}' } }).getUtxos(ADDRESS))
      .rejects.toThrow(/not an array/);
  });

  it("rejects HTML or junk where JSON was expected", async () => {
    await expect(client({ ...routes, "/utxo": { body: "<!DOCTYPE html><h1>502</h1>" } }).getUtxos(ADDRESS))
      .rejects.toThrow(/expected JSON/);
  });

  it("rejects a malformed txid", async () => {
    await expect(client({
      ...routes,
      "/utxo": { body: JSON.stringify([{ txid: "short", vout: 0, value: 1, status: { confirmed: false } }]) },
    }).getUtxos(ADDRESS)).rejects.toThrow(/hex txid/);
  });

  it("rejects a negative or oversized value", async () => {
    await expect(client({
      ...routes,
      "/utxo": { body: JSON.stringify([{ txid: TXID_A, vout: 0, value: -100, status: { confirmed: false } }]) },
    }).getUtxos(ADDRESS)).rejects.toThrow(/negative/);

    await expect(client({
      ...routes,
      "/utxo": { body: JSON.stringify([{ txid: TXID_A, vout: 0, value: 99e15, status: { confirmed: false } }]) },
    }).getUtxos(ADDRESS)).rejects.toThrow(/money supply|safe integer/);
  });

  it("BOUNDS the number of entries a server can return", async () => {
    // Absorbing a million entries into wallet state is a memory DoS that
    // needs no exploit, just a large response.
    const huge = JSON.stringify(
      Array.from({ length: 10_001 }, () => ({ txid: TXID_A, vout: 0, value: 1, status: { confirmed: false } })),
    );
    await expect(client({ ...routes, "/utxo": { body: huge } }).getUtxos(ADDRESS))
      .rejects.toThrow(/implausible number/);
  });

  it("rejects implausible addresses before making a request", async () => {
    const c = client(routes);
    await expect(c.getUtxos("short")).rejects.toThrow(/implausible address length/);
    await expect(c.getUtxos("tb1q../../../etc/passwd")).rejects.toThrow(/not alphanumeric/);
    await expect(c.getUtxos("a".repeat(200))).rejects.toThrow(/implausible address length/);
  });
});

describe("getAddressActivity", () => {
  it("reports history from chain and mempool stats", async () => {
    const activity = await client({
      "/blocks/tip/height": { body: "200" },
      "/utxo": { body: "[]" },
      [`/address/${ADDRESS}`]: {
        body: JSON.stringify({ chain_stats: { tx_count: 3 }, mempool_stats: { tx_count: 0 } }),
      },
    }).getAddressActivity(ADDRESS);
    expect(activity.hasHistory).toBe(true);
  });

  it("SKIPS the UTXO request for an address with no history", async () => {
    // Saves a request per unused address. Over a 20-address gap-limit scan
    // that is most of them, and every skipped request is one less query
    // revealing an address to the server.
    let utxoCalls = 0;
    const c = new EsploraChainSource({
      baseUrl: "https://example.test/api",
      network: "testnet",
      maxRetries: 0,
      fetchImpl: (async (url: string) => {
        const path = url.toString();
        if (path.endsWith("/utxo")) utxoCalls++;
        return {
          ok: true, status: 200,
          text: async () =>
            path.includes("/address/")
              ? JSON.stringify({ chain_stats: { tx_count: 0 }, mempool_stats: { tx_count: 0 } })
              : "200",
        } as Response;
      }) as unknown as typeof fetch,
    });
    const activity = await c.getAddressActivity(ADDRESS);
    expect(activity.hasHistory).toBe(false);
    expect(utxoCalls).toBe(0);
  });

  it("treats missing stats as no history rather than crashing", async () => {
    const activity = await client({ [`/address/${ADDRESS}`]: { body: "{}" } }).getAddressActivity(ADDRESS);
    expect(activity.hasHistory).toBe(false);
  });
});

describe("broadcast", () => {
  const raw = "02000000000101" + "ab".repeat(100);

  it("returns the txid the server reports", async () => {
    expect(await client({ "/tx": { body: TXID_A } }).broadcast(raw)).toBe(TXID_A);
  });

  it("trims whitespace from the response", async () => {
    expect(await client({ "/tx": { body: `  ${TXID_A}\n` } }).broadcast(raw)).toBe(TXID_A);
  });

  it("rejects a non-txid response", async () => {
    // A server returning an error string where a txid belongs must not be
    // mistaken for success.
    await expect(client({ "/tx": { body: "sendrawtransaction RPC error: fee too low" } }).broadcast(raw))
      .rejects.toThrow(/hex txid/);
  });

  it("rejects malformed raw transaction hex before sending it", async () => {
    const c = client({ "/tx": { body: TXID_A } });
    await expect(c.broadcast("not hex")).rejects.toThrow(/hexadecimal/);
    await expect(c.broadcast("abc")).rejects.toThrow(/even-length/);
    await expect(c.broadcast("ab".repeat(500_000))).rejects.toThrow(/maximum standard size/);
  });

  it("surfaces a 4xx rejection with the server's reason, truncated", async () => {
    await expect(client({ "/tx": { body: "min relay fee not met", status: 400 } }).broadcast(raw))
      .rejects.toThrow(/status 400.*min relay fee/s);
  });

  it("truncates a hostile error body rather than logging it whole", async () => {
    const huge = "X".repeat(100_000);
    await expect(client({ "/tx": { body: huge, status: 400 } }).broadcast(raw))
      .rejects.toThrow(/^(?!.*X{500}).*$/s);
  });
});

describe("retries and timeouts", () => {
  it("retries 5xx responses", async () => {
    let attempts = 0;
    const c = new EsploraChainSource({
      baseUrl: "https://example.test/api", network: "testnet", maxRetries: 2,
      fetchImpl: (async () => {
        attempts++;
        return attempts < 3
          ? ({ ok: false, status: 503, text: async () => "unavailable" } as Response)
          : ({ ok: true, status: 200, text: async () => "150" } as Response);
      }) as unknown as typeof fetch,
    });
    expect(await c.getBlockHeight()).toBe(150);
    expect(attempts).toBe(3);
  });

  it("does NOT retry a 4xx — it is a definitive answer", async () => {
    // Retrying wastes time and leaks extra requests to the server.
    let attempts = 0;
    const c = new EsploraChainSource({
      baseUrl: "https://example.test/api", network: "testnet", maxRetries: 3,
      fetchImpl: (async () => {
        attempts++;
        return { ok: false, status: 404, text: async () => "not found" } as Response;
      }) as unknown as typeof fetch,
    });
    await expect(c.getBlockHeight()).rejects.toThrow(/404/);
    expect(attempts).toBe(1);
  });

  it("gives up after exhausting retries", async () => {
    const c = new EsploraChainSource({
      baseUrl: "https://example.test/api", network: "testnet", maxRetries: 2,
      fetchImpl: (async () => ({ ok: false, status: 500, text: async () => "boom" } as Response)) as unknown as typeof fetch,
    });
    await expect(c.getBlockHeight()).rejects.toThrow(/500/);
  });

  it("times out a hanging request", async () => {
    const c = new EsploraChainSource({
      baseUrl: "https://example.test/api", network: "testnet", maxRetries: 0, timeoutMs: 50,
      fetchImpl: ((_url: string, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          });
        })) as unknown as typeof fetch,
    });
    await expect(c.getBlockHeight()).rejects.toThrow(/timed out/);
  });

  it("wraps network errors rather than leaking them raw", async () => {
    const c = new EsploraChainSource({
      baseUrl: "https://example.test/api", network: "testnet", maxRetries: 0,
      fetchImpl: (async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch,
    });
    await expect(c.getBlockHeight()).rejects.toThrow(ChainError);
  });

  it("rejects an oversized response body", async () => {
    const c = new EsploraChainSource({
      baseUrl: "https://example.test/api", network: "testnet", maxRetries: 0,
      fetchImpl: (async () => ({
        ok: true, status: 200, text: async () => "0".repeat(9 * 1024 * 1024),
      } as Response)) as unknown as typeof fetch,
    });
    await expect(c.getBlockHeight()).rejects.toThrow(/maximum permitted size/);
  });
});

describe("validation helpers", () => {
  it("validateAmount accepts numbers, strings, and BigInt", () => {
    expect(validateAmount(1000, "x")).toBe(1000n);
    expect(validateAmount("1000", "x")).toBe(1000n);
    expect(validateAmount(1000n, "x")).toBe(1000n);
  });

  it("validateAmount REJECTS unsafe integers", () => {
    // JSON numbers are IEEE doubles. Above 2^53 they round silently. The
    // whole money supply (2.1e15) fits below that, so anything larger is a
    // bug or an attack.
    expect(() => validateAmount(2 ** 53 + 1, "x")).toThrow(/safe integer/);
    expect(() => validateAmount(1.5, "x")).toThrow();
    expect(() => validateAmount(NaN, "x")).toThrow();
    expect(() => validateAmount(Infinity, "x")).toThrow();
  });

  it("validateAmount rejects wrong types and malformed strings", () => {
    expect(() => validateAmount(null, "x")).toThrow();
    expect(() => validateAmount(undefined, "x")).toThrow();
    expect(() => validateAmount({}, "x")).toThrow();
    expect(() => validateAmount("1e5", "x")).toThrow();
    expect(() => validateAmount("0x10", "x")).toThrow();
  });

  it("validateTxid demands 64 lowercase hex characters", () => {
    expect(validateTxid(TXID_A, "x")).toBe(TXID_A);
    expect(() => validateTxid(TXID_A.toUpperCase(), "x")).toThrow();
    expect(() => validateTxid(TXID_A.slice(0, 63), "x")).toThrow();
    expect(() => validateTxid(123, "x")).toThrow();
  });

  it("normalizeConfirmations clamps rather than throwing", () => {
    // Some servers report -1 for "in mempool"; treating that as zero
    // confirmations is exactly right, and refusing to sync over a formatting
    // quirk would be unhelpful.
    expect(normalizeConfirmations(-1)).toBe(0);
    expect(normalizeConfirmations(6)).toBe(6);
    expect(normalizeConfirmations("junk")).toBe(0);
    expect(normalizeConfirmations(3.7)).toBe(3);
  });
});
