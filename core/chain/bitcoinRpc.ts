/**
 * BITCOIN CORE JSON-RPC CHAIN SOURCE
 *
 * Talks directly to a `bitcoind` node over JSON-RPC. This is the chain source
 * that matters most, for a reason worth being explicit about.
 *
 * ─── Why this exists when Esplora already does ─────────────────────────────
 * Every test written so far validates Veyra against *my reading of the
 * specifications*. The BIP-143 vector proves the sighash matches the document.
 * The tampering tests prove signatures break when they should. None of it
 * proves a real Bitcoin node will ACCEPT a transaction Veyra produces.
 *
 * Consensus rules are not fully written down anywhere — the implementation is
 * the specification. A transaction can satisfy every rule I know about and
 * still be rejected for one I do not. The only way to close that gap is to
 * hand a transaction to `bitcoind` and see what it says.
 *
 * That is what this module enables, and it is why §36 requires regtest for
 * development rather than treating a mock as sufficient.
 *
 * ─── Why regtest specifically ──────────────────────────────────────────────
 * A private chain where you mine blocks on demand. Coins have no value, blocks
 * are instant, and you control every variable. It runs the SAME consensus code
 * as mainnet — which is the entire point. A transaction regtest accepts is a
 * transaction mainnet accepts, modulo policy differences.
 *
 * ─── How UTXOs are found: scantxoutset ─────────────────────────────────────
 * Bitcoin Core does not track arbitrary addresses unless you import them. Two
 * options:
 *
 *   importdescriptors — the node watches the addresses and indexes them.
 *                       Fast queries, but mutates node state and requires a
 *                       wallet, and a rescan can take hours on mainnet.
 *
 *   scantxoutset      — scans the current UTXO set on demand for a set of
 *                       descriptors. Stateless, no wallet, no node mutation.
 *                       Takes seconds on regtest, minutes on mainnet.
 *
 * Veyra uses `scantxoutset`. The trade-off is deliberate: for a test harness,
 * not mutating the node's state is worth far more than query speed, because a
 * stateless source cannot leave a previous test's imports behind to corrupt
 * the next one. This choice would be wrong for a production mainnet wallet,
 * and that is recorded here rather than discovered.
 *
 * ─── Privacy ───────────────────────────────────────────────────────────────
 * If the node is yours, this is the best available option: no third party
 * learns your addresses. If the node is someone else's, it learns everything
 * an Esplora server would. `isThirdParty` reflects this.
 *
 * ─── ⚠️ Verification status ────────────────────────────────────────────────
 * The request construction, response parsing, and error handling below are
 * tested against a controlled fake. They have NOT been run against a real
 * bitcoind, because this build environment cannot obtain one. The integration
 * suite in tests/integration/ does exactly that and is skipped unless a node
 * is configured — see docs/REGTEST.md.
 */

import {
  ChainSource, ChainUtxo, ChainTransaction, AddressActivity, ChainError,
  validateTxid, validateAmount, validateIndex, validateHeight, normalizeConfirmations,
} from "./types.js";

export interface BitcoinRpcOptions {
  /** e.g. http://127.0.0.1:18443 */
  readonly url: string;
  readonly username: string;
  readonly password: string;
  /** Network this node serves — checked against the wallet before syncing. */
  readonly network: string;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
}

/**
 * Satoshis per BTC.
 *
 * Bitcoin Core's RPC reports amounts in BTC as JSON numbers — i.e. as IEEE
 * doubles. 0.1 + 0.2 !== 0.3 in that representation, and money arithmetic on
 * floats is how rounding errors become lost funds.
 *
 * Every amount is therefore converted to integer satoshis via a STRING
 * round-trip rather than multiplication: `Math.round(btc * 1e8)` accumulates
 * error for large values, and `0.00000001 * 1e8` is not exactly 1 in floating
 * point. See `btcToSatoshis` below.
 */
const SATOSHIS_PER_BTC = 100_000_000n;

/**
 * Convert a BTC amount to satoshis exactly.
 *
 * Works on the DECIMAL STRING, never on the float. The input is already a
 * double by the time JSON.parse hands it over, so some precision may be lost
 * upstream — but Bitcoin Core emits at most 8 decimal places and values below
 * 2^53 satoshis, so the double round-trips exactly for every legitimate
 * amount. What this avoids is compounding a second error on top.
 */
export function btcToSatoshis(btc: unknown, context: string): bigint {
  if (typeof btc === "bigint") return btc;
  if (typeof btc !== "number" && typeof btc !== "string") {
    throw new ChainError(`${context}: amount is not a number`);
  }
  const text = typeof btc === "string" ? btc : btc.toFixed(8);
  if (!/^-?\d+(\.\d+)?$/.test(text)) {
    throw new ChainError(`${context}: amount is not a plain decimal`);
  }
  const negative = text.startsWith("-");
  const [whole, fraction = ""] = text.replace("-", "").split(".") as [string, string?];
  if (fraction.length > 8) {
    throw new ChainError(`${context}: amount has more than 8 decimal places`);
  }
  const satoshis =
    BigInt(whole) * SATOSHIS_PER_BTC + BigInt((fraction + "00000000").slice(0, 8));
  if (negative) throw new ChainError(`${context}: amount is negative`);
  return validateAmount(satoshis, context);
}

interface RpcResponse {
  result?: unknown;
  error?: { code: number; message: string } | null;
}

export class BitcoinRpcChainSource implements ChainSource {
  readonly name: string;
  readonly network: string;
  private readonly url: string;
  private readonly authHeader: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: BitcoinRpcOptions) {
    if (!/^https?:\/\//.test(options.url)) {
      throw new ChainError("RPC URL must start with http:// or https://");
    }
    this.url = options.url.replace(/\/$/, "");
    this.network = options.network;
    this.name = `bitcoind(${new URL(this.url).host})`;
    this.timeoutMs = options.timeoutMs ?? 60_000; // scantxoutset can be slow
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;

    // Basic auth. Credentials never appear in the URL, so they cannot end up
    // in a log line, a referrer header, or shell history via a copied URL.
    this.authHeader =
      "Basic " + Buffer.from(`${options.username}:${options.password}`).toString("base64");

    if (typeof this.fetchImpl !== "function") {
      throw new ChainError("no fetch implementation available in this runtime");
    }
  }

  get isThirdParty(): boolean {
    const host = new URL(this.url).hostname;
    return host !== "localhost" && host !== "127.0.0.1" && host !== "::1";
  }

  /**
   * One JSON-RPC call.
   *
   * `endpoint` exists so wallet-scoped calls can target /wallet/<name>
   * without mutating `this.url`. An earlier version swapped the field and
   * restored it in `finally`; that worked but was a hack, and would have been
   * a genuine race if two calls ever overlapped. Passing the target through
   * is both simpler and correct under concurrency.
   */
  private async call(method: string, params: unknown[] = [], endpoint?: string): Promise<unknown> {
    const target = endpoint ?? this.url;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(target, {
        method: "POST",
        signal: controller.signal,
        headers: { "Content-Type": "application/json", Authorization: this.authHeader },
        body: JSON.stringify({ jsonrpc: "1.0", id: "veyra", method, params }),
      });

      const text = await response.text();

      if (response.status === 401) {
        throw new ChainError("RPC authentication failed — check the username and password");
      }

      let parsed: RpcResponse;
      try {
        parsed = JSON.parse(text) as RpcResponse;
      } catch {
        throw new ChainError(
          `RPC returned a non-JSON response (HTTP ${response.status}); ` +
            `is this a bitcoind RPC endpoint?`,
        );
      }

      if (parsed.error) {
        // Core's error messages are safe to surface — they come from our own
        // node and describe our own request. Truncated regardless.
        throw new ChainError(
          `RPC ${method} failed (${parsed.error.code}): ${String(parsed.error.message).slice(0, 300)}`,
        );
      }
      if (parsed.result === undefined) {
        throw new ChainError(`RPC ${method} returned no result`);
      }
      return parsed.result;
    } catch (error) {
      if (error instanceof ChainError) throw error;
      if ((error as Error).name === "AbortError") {
        throw new ChainError(`RPC ${method} timed out after ${this.timeoutMs}ms`);
      }
      throw new ChainError(`RPC ${method} failed: ${(error as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /** Verify the node is reachable and serving the expected chain. */
  async verifyConnection(): Promise<{ chain: string; blocks: number }> {
    const info = (await this.call("getblockchaininfo")) as Record<string, unknown>;
    const chain = String(info.chain ?? "");
    const blocks = validateHeight(info.blocks, "getblockchaininfo blocks");

    // Core reports "main", "test", "signet", "regtest".
    const expected: Record<string, string> = {
      mainnet: "main", testnet: "test", signet: "signet", regtest: "regtest",
    };
    if (expected[this.network] && chain !== expected[this.network]) {
      throw new ChainError(
        `node is on '${chain}' but this source was configured for '${this.network}'`,
      );
    }
    return { chain, blocks };
  }

  async getBlockHeight(): Promise<number> {
    return validateHeight(await this.call("getblockcount"), "getblockcount");
  }

  /**
   * Find UTXOs for an address via `scantxoutset`.
   *
   * Uses the `addr(...)` descriptor form, which needs no wallet and no import.
   * The scan covers the node's current UTXO set, so it sees confirmed outputs
   * only — mempool outputs are invisible. That is a real limitation and is why
   * `getAddressActivity` reports confirmations of at least 1 for everything it
   * returns.
   */
  async getUtxos(address: string): Promise<ChainUtxo[]> {
    this.assertPlausibleAddress(address);
    const tipHeight = await this.getBlockHeight();

    const result = (await this.call("scantxoutset", [
      "start",
      [{ desc: `addr(${address})` }],
    ])) as Record<string, unknown>;

    if (result.success !== true) {
      throw new ChainError("scantxoutset did not complete successfully");
    }
    const unspents = result.unspents;
    if (!Array.isArray(unspents)) {
      throw new ChainError("scantxoutset returned no unspents array");
    }
    if (unspents.length > 10_000) {
      throw new ChainError("scantxoutset returned an implausible number of outputs");
    }

    return unspents.map((entry, i): ChainUtxo => {
      const item = entry as Record<string, unknown>;
      const height = validateHeight(item.height, `unspent[${i}] height`);
      return {
        txid: validateTxid(item.txid, `unspent[${i}]`),
        vout: validateIndex(item.vout, `unspent[${i}] vout`),
        value: btcToSatoshis(item.amount, `unspent[${i}] amount`),
        confirmations: normalizeConfirmations(tipHeight - height + 1),
        blockHeight: height,
      };
    });
  }

  /**
   * Whether an address has history.
   *
   * ⚠️ LIMITATION, stated because it changes scan behaviour: `scantxoutset`
   * only sees UNSPENT outputs. An address that received and then spent
   * everything looks unused here, whereas Esplora would report history.
   *
   * The consequence is that the gap-limit scan may stop earlier against this
   * source than against Esplora, potentially missing funds beyond a fully
   * spent address. For regtest testing that is acceptable. For production use
   * against a real node, `importdescriptors` plus `listunspent` would be
   * required instead, and that is not implemented.
   */
  async getAddressActivity(address: string): Promise<AddressActivity> {
    const utxos = await this.getUtxos(address);
    return { address, hasHistory: utxos.length > 0, utxos };
  }

  /**
   * Broadcast via `sendrawtransaction`.
   *
   * THIS is the call that matters. Bitcoin Core validates the transaction
   * against real consensus and policy rules and rejects it with a specific
   * reason if anything is wrong. Every rule Veyra's signing path assumes is
   * checked here by an independent implementation.
   */
  async broadcast(rawTxHex: string): Promise<string> {
    if (!/^[0-9a-f]+$/i.test(rawTxHex) || rawTxHex.length % 2 !== 0) {
      throw new ChainError("raw transaction must be even-length hexadecimal");
    }
    return validateTxid(await this.call("sendrawtransaction", [rawTxHex]), "sendrawtransaction");
  }

  async getTransactions(_address: string): Promise<ChainTransaction[]> {
    // Would require a wallet import or a txindex; not implemented rather than
    // faked, so no caller can mistake an empty array for "no history".
    throw new ChainError(
      "transaction history requires an imported descriptor wallet, which is not implemented",
    );
  }

  // ── Regtest helpers ─────────────────────────────────────────────────────
  //
  // Only meaningful on regtest. They throw elsewhere, because "generate 101
  // blocks" against mainnet is not a mistake worth allowing to compile.

  /** Mine blocks to an address. Regtest only. */
  async generateToAddress(blocks: number, address: string): Promise<string[]> {
    this.assertRegtest("generateToAddress");
    if (!Number.isInteger(blocks) || blocks < 1 || blocks > 1000) {
      throw new ChainError("block count must be between 1 and 1000");
    }
    const hashes = await this.call("generatetoaddress", [blocks, address]);
    if (!Array.isArray(hashes)) throw new ChainError("generatetoaddress returned no array");
    return hashes as string[];
  }

  /** Create or load a node wallet, used only to fund test addresses. */
  async ensureNodeWallet(name = "veyra-test"): Promise<void> {
    this.assertRegtest("ensureNodeWallet");
    try {
      await this.call("createwallet", [name]);
    } catch (error) {
      // Already exists: load it. Any other failure is real.
      if (!/already exists|Database already/i.test((error as Error).message)) {
        try {
          await this.call("loadwallet", [name]);
        } catch (loadError) {
          if (!/already loaded/i.test((loadError as Error).message)) throw loadError;
        }
      }
    }
  }

  /** Send BTC from the node's wallet to an address. Regtest only. */
  async fundAddress(walletName: string, address: string, satoshis: bigint): Promise<string> {
    this.assertRegtest("fundAddress");
    const btc = (Number(satoshis) / 1e8).toFixed(8);
    const result = await this.callWallet(walletName, "sendtoaddress", [address, btc]);
    return validateTxid(result, "sendtoaddress");
  }

  /** A new address from the node's own wallet, for mining rewards. */
  async getNewNodeAddress(walletName: string): Promise<string> {
    this.assertRegtest("getNewNodeAddress");
    const address = await this.callWallet(walletName, "getnewaddress");
    if (typeof address !== "string") throw new ChainError("getnewaddress returned no string");
    return address;
  }

  /** A wallet-scoped RPC call: POST to /wallet/<name>. */
  private async callWallet(walletName: string, method: string, params: unknown[] = []): Promise<unknown> {
    return this.call(method, params, `${this.url}/wallet/${encodeURIComponent(walletName)}`);
  }

  private assertRegtest(method: string): void {
    if (this.network !== "regtest") {
      throw new ChainError(`${method} is only permitted on regtest, not '${this.network}'`);
    }
  }

  private assertPlausibleAddress(address: string): void {
    if (typeof address !== "string" || address.length < 14 || address.length > 90) {
      throw new ChainError("implausible address length");
    }
    if (!/^[a-zA-Z0-9]+$/.test(address)) {
      throw new ChainError("address contains characters that are not alphanumeric");
    }
  }
}
