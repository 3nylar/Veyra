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
  ChainSource, ChainUtxo, ChainTransaction, AddressActivity, ChainError, FeeEstimates,
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

/**
 * Satoshis to a BTC decimal string, exactly.
 *
 * The inverse of `btcToSatoshis`, and it avoids floats for the same reason:
 * `Number(satoshis) / 1e8` is inexact, and the same shape produced VEY-011,
 * where a fee estimate was overcharged by up to 100%.
 *
 * String construction has no rounding step to get wrong.
 */
export function satoshisToBtcString(satoshis: bigint): string {
  if (satoshis < 0n) throw new ChainError("amount cannot be negative");
  const whole = satoshis / SATOSHIS_PER_BTC;
  const fraction = (satoshis % SATOSHIS_PER_BTC).toString().padStart(8, "0");
  return `${whole}.${fraction}`;
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

  /**
   * Live fee estimates via `estimatesmartfee`.
   *
   * ─── Why the CONSERVATIVE mode ─────────────────────────────────────────
   * Core offers two estimation modes. `ECONOMICAL` reacts quickly to a
   * draining mempool and produces lower numbers; `CONSERVATIVE` uses a longer
   * history and is more likely to be sufficient if conditions worsen.
   *
   * For a wallet, under-estimating is the worse error: a stuck transaction is
   * a far worse experience than a few satoshis of overpayment, and RBF is the
   * only way out. We ask for CONSERVATIVE deliberately.
   *
   * ─── Regtest has no estimates ──────────────────────────────────────────
   * A private chain has no fee market and no history to estimate from, so
   * Core returns errors for every target. That is correct behaviour, not a
   * failure — the method returns a result with the fields absent and the
   * caller falls back to static defaults.
   */
  async getFeeEstimates(): Promise<FeeEstimates> {
    const targets: Array<[keyof FeeEstimates, number]> = [
      ["high", 2],
      ["medium", 6],
      ["low", 144],
    ];
    const estimates: Record<string, number> = {};

    for (const [label, blocks] of targets) {
      try {
        const result = (await this.call("estimatesmartfee", [blocks, "CONSERVATIVE"])) as
          Record<string, unknown>;

        // Core reports BTC per kvB. Convert to sat/vB with INTEGER arithmetic.
        //
        // The obvious float version is wrong, and wrong in the expensive
        // direction: `(0.00002 * 1e8) / 1000` is 2.0000000000000004, which
        // Math.ceil turns into 3 — a fee rate 50% above what the node
        // recommended. This module already warns about float money arithmetic
        // in btcToSatoshis; the same discipline applies here.
        //
        // btcToSatoshis works on the decimal string, so it yields exactly
        // 2000n sat per kvB, and 2000n / 1000n is exactly 2n.
        if (typeof result.feerate === "number" && result.feerate > 0) {
          const satPerKvb = btcToSatoshis(result.feerate, `estimatesmartfee[${blocks}]`);
          // Round UP to the next whole sat/vB: under-paying risks a stuck
          // transaction, which is worse than a satoshi of overpayment.
          const satPerVb = (satPerKvb + 999n) / 1000n;
          if (satPerVb > 0n && satPerVb < 100_000n) {
            estimates[label as string] = Math.max(1, Number(satPerVb));
          }
        }
        // `errors` in the response means Core could not estimate that target.
        // Absent is the honest answer; we do not substitute a guess.
      } catch {
        // A failing target is not a failing call. Others may still work.
      }
    }
    return { ...estimates, source: this.name, fetchedAt: Date.now() };
  }

  /**
   * Transaction history via a watch-only descriptor wallet.
   *
   * ─── Why this needs an import, unlike getUtxos ──────────────────────────
   * `scantxoutset` sees the UTXO set — what is currently unspent. History is a
   * different question: it includes outputs that have since been spent, and
   * transactions where we were the sender. The UTXO set cannot answer it,
   * because a spent output is simply gone.
   *
   * So this path does import descriptors, accepting the node-state mutation
   * that `getUtxos` deliberately avoids. The import is confined to a
   * separate, clearly-named watch-only wallet holding only `addr()`
   * descriptors — no keys, no spending ability.
   *
   * ─── Rescan cost ────────────────────────────────────────────────────────
   * `importdescriptors` with a timestamp triggers a rescan from that point. On
   * regtest that is instant. On mainnet, `timestamp: 0` would rescan the
   * entire chain and take hours, which is why `since` defaults to "now" and
   * must be set deliberately.
   */
  async importAddressesForHistory(
    addresses: readonly string[],
    options: { walletName?: string; since?: number } = {},
  ): Promise<void> {
    const walletName = options.walletName ?? "veyra-watch";
    const timestamp = options.since ?? "now";

    if (addresses.length === 0) return;
    if (addresses.length > 1000) {
      throw new ChainError("refusing to import more than 1000 addresses at once");
    }
    for (const address of addresses) this.assertPlausibleAddress(address);

    // Create the watch-only wallet if it does not exist. `disable_private_keys`
    // is the important argument: this wallet can observe, never spend.
    try {
      await this.call("createwallet", [walletName, true, true, "", false, true, true]);
    } catch (error) {
      if (!/already exists|Database already/i.test((error as Error).message)) {
        try {
          await this.call("loadwallet", [walletName]);
        } catch (loadError) {
          if (!/already loaded/i.test((loadError as Error).message)) throw loadError;
        }
      }
    }

    const descriptors = addresses.map((address) => ({
      desc: `addr(${address})`,
      timestamp,
      label: "veyra",
    }));

    const result = await this.callWallet(walletName, "importdescriptors", [descriptors]);
    if (!Array.isArray(result)) throw new ChainError("importdescriptors returned no array");

    for (const [i, entry] of result.entries()) {
      const item = entry as Record<string, unknown>;
      if (item.success !== true) {
        const detail = (item.error as { message?: string } | undefined)?.message ?? "unknown";
        throw new ChainError(`descriptor ${i} failed to import: ${String(detail).slice(0, 200)}`);
      }
    }
  }

  /**
   * Transactions touching an imported address.
   *
   * Requires `importAddressesForHistory` to have been called first. Throws a
   * clear error otherwise rather than returning an empty array — an empty
   * history and an unconfigured wallet look identical to a caller, and
   * "you have no transactions" is a damaging thing to say incorrectly.
   */
  async getTransactions(
    address: string,
    options: { walletName?: string } = {},
  ): Promise<ChainTransaction[]> {
    this.assertPlausibleAddress(address);
    const walletName = options.walletName ?? "veyra-watch";

    let raw: unknown;
    try {
      // count 500, skip 0, include_watchonly true.
      raw = await this.callWallet(walletName, "listtransactions", ["*", 500, 0, true]);
    } catch (error) {
      if (/not found|Requested wallet does not exist/i.test((error as Error).message)) {
        throw new ChainError(
          `watch-only wallet '${walletName}' does not exist — call ` +
            `importAddressesForHistory() before requesting history`,
        );
      }
      throw error;
    }
    if (!Array.isArray(raw)) throw new ChainError("listtransactions returned no array");

    // One transaction can produce several entries (one per matching output),
    // so fold them together by txid and sum the amounts.
    const byTxid = new Map<string, { net: bigint; confirmations: number; time?: number; fee?: bigint }>();

    for (const entry of raw) {
      const item = entry as Record<string, unknown>;
      if (item.address !== address) continue;

      const txid = validateTxid(item.txid, "listtransactions txid");
      const amount = typeof item.amount === "number" ? item.amount : 0;
      // `amount` is signed BTC: negative for a send. btcToSatoshis rejects
      // negatives, so take the magnitude and reapply the sign.
      const magnitude = btcToSatoshis(Math.abs(amount), "listtransactions amount");
      const net = amount < 0 ? -magnitude : magnitude;

      const existing = byTxid.get(txid);
      const confirmations = normalizeConfirmations(item.confirmations);
      const fee =
        typeof item.fee === "number" && item.fee !== 0
          ? btcToSatoshis(Math.abs(item.fee), "listtransactions fee")
          : undefined;

      byTxid.set(txid, {
        net: (existing?.net ?? 0n) + net,
        confirmations,
        ...(typeof item.blocktime === "number" ? { time: item.blocktime } : {}),
        ...(fee !== undefined ? { fee } : existing?.fee !== undefined ? { fee: existing.fee } : {}),
      });
    }

    return [...byTxid.entries()].map(([txid, data]) => ({
      txid,
      confirmations: data.confirmations,
      netValue: data.net,
      direction: data.net > 0n ? ("received" as const) : data.net < 0n ? ("sent" as const) : ("internal" as const),
      ...(data.time !== undefined ? { blockTime: data.time } : {}),
      ...(data.fee !== undefined ? { fee: data.fee } : {}),
    }));
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
    const result = await this.callWallet(walletName, "sendtoaddress", [
      address,
      satoshisToBtcString(satoshis),
    ]);
    return validateTxid(result, "sendtoaddress");
  }

  /**
   * Ask the node to decode a PSBT.
   *
   * The interoperability check that matters: if Bitcoin Core can read a PSBT
   * Veyra produced, the format is correct rather than merely self-consistent.
   * A format only Veyra understands would replace "trust one seed" with
   * "trust one codebase".
   */
  async decodePsbt(base64: string): Promise<unknown> {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
      throw new ChainError("PSBT must be base64");
    }
    return this.call("decodepsbt", [base64]);
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
