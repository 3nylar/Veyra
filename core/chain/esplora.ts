/**
 * ESPLORA CHAIN SOURCE
 *
 * A client for the Esplora HTTP API (Blockstream's block explorer backend,
 * also used by mempool.space and runnable locally alongside Bitcoin Core).
 *
 * ─── ⚠️ PRIVACY: read this before using a public server ────────────────────
 * Querying a public Esplora instance for your addresses tells that server:
 *
 *   - every address in your wallet, since the gap-limit scan asks about all
 *     of them in one session
 *   - that those addresses belong to ONE wallet, which is information not
 *     otherwise available from the blockchain
 *   - your IP address, and therefore an approximate location
 *   - your balance and full transaction history
 *   - when you are online, and when you transact
 *
 * No cryptography prevents any of this. It is inherent to asking someone else
 * about your coins. The blockchain is public, but *which addresses are yours*
 * is not — and a light wallet query hands exactly that over.
 *
 * The only real mitigations:
 *   - run your own Esplora or Electrum server against your own node
 *   - use Tor, which removes the IP linkage but not the address clustering
 *   - use a protocol designed for this (compact block filters, BIP-157/158),
 *     where the client downloads filters and never reveals which addresses
 *     it cares about
 *
 * Veyra defaults to no chain source at all and requires one to be passed
 * explicitly, so a user never contacts a third party without choosing to.
 * When a public server is configured, `privacyWarning` below is surfaced.
 *
 * ─── ⚠️ VERIFICATION STATUS ────────────────────────────────────────────────
 * This client has NOT been tested against a live Esplora server. It was
 * developed in an environment without access to one, and is tested against a
 * controlled fake implementing the documented API shape.
 *
 * That means: the request paths, the defensive parsing, the error handling,
 * and the retry logic are all tested. What is NOT verified is that a real
 * server's responses match the shape documented in the Esplora API reference.
 * Before this touches real funds it must be run against a regtest Esplora
 * instance. This is recorded here rather than discovered later.
 */

import {
  ChainSource, ChainUtxo, ChainTransaction, AddressActivity, ChainError, FeeEstimates,
  validateTxid, validateAmount, validateIndex, validateHeight, normalizeConfirmations,
} from "./types.js";

/** Public Esplora instances, by network. */
export const PUBLIC_ESPLORA = Object.freeze({
  mainnet: "https://blockstream.info/api",
  testnet: "https://blockstream.info/testnet/api",
  signet: "https://mempool.space/signet/api",
});

export interface EsploraOptions {
  /** Base URL, without a trailing slash. */
  readonly baseUrl: string;
  /** Network this server serves. Checked against the wallet before syncing. */
  readonly network: string;
  /** Per-request timeout in milliseconds. */
  readonly timeoutMs?: number;
  /** Retry attempts for transient failures. */
  readonly maxRetries?: number;
  /** Injected for testing. Defaults to global fetch. */
  readonly fetchImpl?: typeof fetch;
}

/**
 * Largest response we will read, in bytes.
 *
 * Without a cap, a hostile or broken server can stream indefinitely and
 * exhaust memory — a denial of service that needs no exploit, just a slow
 * infinite response. 8 MB is far above any legitimate Esplora payload.
 */
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export class EsploraChainSource implements ChainSource {
  readonly name: string;
  readonly network: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: EsploraOptions) {
    if (!/^https?:\/\//.test(options.baseUrl)) {
      throw new ChainError("base URL must start with http:// or https://");
    }
    // Reject a trailing slash rather than normalising it: silently repairing
    // configuration hides typos that might point somewhere unintended.
    if (options.baseUrl.endsWith("/")) {
      throw new ChainError("base URL must not end with a slash");
    }
    this.baseUrl = options.baseUrl;
    this.network = options.network;
    this.name = `Esplora(${new URL(options.baseUrl).host})`;
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxRetries = options.maxRetries ?? 2;
    // `.bind(globalThis)` here is load-bearing, not defensive style.
    //
    // `globalThis.fetch` is a METHOD of the global object. Storing the bare
    // reference and later calling `this.fetchImpl(...)` invokes it with `this`
    // set to this EsploraChainSource, and the WebIDL brand check rejects the
    // foreign receiver:
    //
    //     TypeError: Failed to execute 'fetch' on 'Window': Illegal invocation
    //
    // `request()` wrapped that into `Chain: network error: ...`, which is what
    // every user of the browser wallet saw when they pressed Sync — on both
    // wallet.html and watch.html. Node's undici performs no receiver check,
    // which is why 55 green tests never noticed. See docs/ATTACKS.md VEY-020.
    //
    // Only the DEFAULT is bound. An injected `fetchImpl` is a public option and
    // is left exactly as the caller supplied it; `request()` instead reads it
    // into a local so the call has no receiver at all, which is what keeps an
    // injected `window.fetch` working too.
    const globalFetch =
      typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : undefined;

    this.fetchImpl = options.fetchImpl ?? (globalFetch as typeof fetch);

    if (typeof this.fetchImpl !== "function") {
      throw new ChainError("no fetch implementation available in this runtime");
    }
  }

  /** True when this points at a third-party server rather than localhost. */
  get isThirdParty(): boolean {
    const host = new URL(this.baseUrl).hostname;
    return host !== "localhost" && host !== "127.0.0.1" && host !== "::1";
  }

  /** A warning to surface in the UI when a third-party server is in use. */
  get privacyWarning(): string | null {
    if (!this.isThirdParty) return null;
    return (
      `Using ${this.name}. This server will learn every address in this wallet, ` +
      `your balance, your transaction history, and your IP address. Run your own ` +
      `Esplora instance to avoid this.`
    );
  }

  /**
   * One HTTP request, with a timeout, a size cap, and bounded retries.
   *
   * Only transient failures are retried — network errors and 5xx responses. A
   * 404 or 400 is a definitive answer and retrying it wastes time and leaks
   * additional requests to the server.
   */
  private async request(path: string, init?: RequestInit): Promise<string> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        // Read into a local so the call has NO receiver. Together with the
        // bound default in the constructor this holds even if a caller injects
        // a raw global method: WebIDL substitutes the relevant global when
        // `this` is undefined, and rejects only a foreign object. Calling
        // `this.fetchImpl(...)` directly is the VEY-020 defect — do not.
        const doFetch = this.fetchImpl;
        const response = await doFetch(`${this.baseUrl}${path}`, {
          ...init,
          signal: controller.signal,
          headers: { Accept: "text/plain, application/json", ...(init?.headers ?? {}) },
        });

        if (response.status >= 500) {
          lastError = new ChainError(`server returned ${response.status}`);
          continue; // transient — retry
        }
        if (!response.ok) {
          const body = await response.text();
          // Truncate: an error body is attacker-controlled and could be huge,
          // and we do not want unbounded hostile text in logs.
          throw new ChainError(
            `request failed with status ${response.status}: ${body.slice(0, 200)}`,
          );
        }

        const text = await response.text();
        if (text.length > MAX_RESPONSE_BYTES) {
          throw new ChainError("response exceeded the maximum permitted size");
        }
        return text;
      } catch (error) {
        if (error instanceof ChainError) throw error;
        if ((error as Error).name === "AbortError") {
          lastError = new ChainError(`request timed out after ${this.timeoutMs}ms`);
        } else {
          lastError = new ChainError(`network error: ${(error as Error).message}`);
        }
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastError ?? new ChainError("request failed");
  }

  /** Parse JSON defensively. A server may return HTML, an error page, or junk. */
  private async requestJson(path: string): Promise<unknown> {
    const text = await this.request(path);
    try {
      return JSON.parse(text);
    } catch {
      throw new ChainError(`expected JSON from ${path} but received something else`);
    }
  }

  async getBlockHeight(): Promise<number> {
    const text = await this.request("/blocks/tip/height");
    const height = Number(text.trim());
    return validateHeight(height, "block height");
  }

  async getUtxos(address: string): Promise<ChainUtxo[]> {
    this.assertPlausibleAddress(address);
    const data = await this.requestJson(`/address/${encodeURIComponent(address)}/utxo`);

    if (!Array.isArray(data)) {
      throw new ChainError("UTXO response was not an array");
    }
    // Bound the count: a hostile server returning a million entries would
    // otherwise be absorbed into wallet state.
    if (data.length > 10_000) {
      throw new ChainError("UTXO response contained an implausible number of entries");
    }

    const tipHeight = await this.getBlockHeight();

    return data.map((entry, i): ChainUtxo => {
      const item = entry as Record<string, unknown>;
      const status = (item.status ?? {}) as Record<string, unknown>;
      const confirmed = status.confirmed === true;
      const blockHeight = confirmed ? validateHeight(status.block_height, `utxo[${i}] height`) : undefined;

      return {
        txid: validateTxid(item.txid, `utxo[${i}]`),
        vout: validateIndex(item.vout, `utxo[${i}] vout`),
        value: validateAmount(item.value, `utxo[${i}] value`),
        confirmations: confirmed && blockHeight !== undefined
          ? normalizeConfirmations(tipHeight - blockHeight + 1)
          : 0,
        ...(blockHeight !== undefined ? { blockHeight } : {}),
      };
    });
  }

  async getAddressActivity(address: string): Promise<AddressActivity> {
    this.assertPlausibleAddress(address);
    const data = (await this.requestJson(
      `/address/${encodeURIComponent(address)}`,
    )) as Record<string, unknown>;

    const chainStats = (data.chain_stats ?? {}) as Record<string, unknown>;
    const mempoolStats = (data.mempool_stats ?? {}) as Record<string, unknown>;

    const chainTxCount = typeof chainStats.tx_count === "number" ? chainStats.tx_count : 0;
    const mempoolTxCount = typeof mempoolStats.tx_count === "number" ? mempoolStats.tx_count : 0;
    const hasHistory = chainTxCount > 0 || mempoolTxCount > 0;

    // Only fetch UTXOs when there is history — saves a request per unused
    // address during a scan, which for a 20-address gap limit is most of them.
    const utxos = hasHistory ? await this.getUtxos(address) : [];
    return { address, hasHistory, utxos };
  }

  /**
   * Transactions touching an address, with direction.
   *
   * Esplora returns full transactions including every input and output, so the
   * net effect on this address is computed here: sum the outputs paying it,
   * subtract the inputs spending from it. Positive means value arrived.
   *
   * A list without direction is close to useless — "0.5 BTC" tells a user
   * nothing about whether they gained or lost it.
   */
  async getTransactions(address: string): Promise<ChainTransaction[]> {
    this.assertPlausibleAddress(address);
    const data = await this.requestJson(`/address/${encodeURIComponent(address)}/txs`);
    if (!Array.isArray(data)) throw new ChainError("transaction list was not an array");
    if (data.length > 1000) throw new ChainError("transaction list was implausibly long");

    const tipHeight = await this.getBlockHeight();

    return data.map((entry, i): ChainTransaction => {
      const item = entry as Record<string, unknown>;
      const status = (item.status ?? {}) as Record<string, unknown>;
      const confirmed = status.confirmed === true;
      const blockHeight = confirmed ? validateHeight(status.block_height, `tx[${i}] height`) : undefined;

      let received = 0n;
      let spent = 0n;

      for (const output of (item.vout as unknown[]) ?? []) {
        const vout = output as Record<string, unknown>;
        if (vout.scriptpubkey_address === address) {
          received += validateAmount(vout.value, `tx[${i}] vout value`);
        }
      }
      for (const input of (item.vin as unknown[]) ?? []) {
        const vin = input as Record<string, unknown>;
        const prevout = (vin.prevout ?? {}) as Record<string, unknown>;
        if (prevout.scriptpubkey_address === address) {
          spent += validateAmount(prevout.value, `tx[${i}] vin value`);
        }
      }

      const netValue = received - spent;

      return {
        txid: validateTxid(item.txid, `tx[${i}]`),
        confirmations: blockHeight !== undefined
          ? normalizeConfirmations(tipHeight - blockHeight + 1)
          : 0,
        netValue,
        direction: netValue > 0n ? "received" : netValue < 0n ? "sent" : "internal",
        ...(blockHeight !== undefined ? { blockHeight } : {}),
        ...(typeof status.block_time === "number" ? { blockTime: status.block_time } : {}),
        ...(item.fee !== undefined ? { fee: validateAmount(item.fee, `tx[${i}] fee`) } : {}),
      };
    });
  }

  /**
   * Live fee estimates via `/fee-estimates`.
   *
   * Esplora returns an object keyed by confirmation target, in sat/vB already.
   * Targets are sparse — a server may answer for 1, 2, 3, 6, 10, 144 and not
   * the numbers in between — so each is looked up with fallbacks rather than
   * assumed present.
   */
  async getFeeEstimates(): Promise<FeeEstimates> {
    const data = (await this.requestJson("/fee-estimates")) as Record<string, unknown>;
    if (typeof data !== "object" || data === null) {
      throw new ChainError("fee estimates response was not an object");
    }

    /** First available target from the candidates, as a sane sat/vB value. */
    const pick = (candidates: number[]): number | undefined => {
      for (const target of candidates) {
        const value = data[String(target)];
        if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) continue;
        // Bound it: a server reporting 100000 sat/vB would otherwise become a
        // fee that empties the wallet.
        if (value > 5000) continue;
        return Math.max(1, Math.ceil(value));
      }
      return undefined;
    };

    const high = pick([1, 2, 3]);
    const medium = pick([6, 5, 4, 3]);
    const low = pick([144, 72, 48, 24]);

    return {
      ...(high !== undefined ? { high } : {}),
      ...(medium !== undefined ? { medium } : {}),
      ...(low !== undefined ? { low } : {}),
      source: this.name,
      fetchedAt: Date.now(),
    };
  }

  /**
   * Broadcast a raw transaction.
   *
   * Esplora returns the txid as plain text. We validate its shape here; the
   * CALLER must additionally check it equals the locally-computed txid — see
   * `Wallet.broadcast`. A server returning a different txid is either broken
   * or lying, and either way the transaction's fate is unknown.
   */
  async broadcast(rawTxHex: string): Promise<string> {
    if (!/^[0-9a-f]+$/i.test(rawTxHex) || rawTxHex.length % 2 !== 0) {
      throw new ChainError("raw transaction must be even-length hexadecimal");
    }
    if (rawTxHex.length > 400_000 * 2) {
      throw new ChainError("raw transaction exceeds the maximum standard size");
    }

    const text = await this.request("/tx", {
      method: "POST",
      body: rawTxHex,
      headers: { "Content-Type": "text/plain" },
    });
    return validateTxid(text.trim(), "broadcast response");
  }

  /**
   * Cheap sanity check before putting an address into a URL.
   *
   * Not a full validation — that is the address module's job. This exists to
   * stop obviously malformed input reaching the network layer, and to make
   * path injection impossible even if `encodeURIComponent` were removed.
   */
  private assertPlausibleAddress(address: string): void {
    if (typeof address !== "string" || address.length < 14 || address.length > 90) {
      throw new ChainError("implausible address length");
    }
    if (!/^[a-zA-Z0-9]+$/.test(address)) {
      throw new ChainError("address contains characters that are not alphanumeric");
    }
  }
}
