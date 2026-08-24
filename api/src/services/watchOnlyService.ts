/**
 * WATCH-ONLY API SERVICE
 *
 * The service the hosted deployment exposes. Mirrors `WalletService`'s shape
 * so the same routes work, with two deliberate differences:
 *
 *   · `prepare` returns an unsigned **PSBT** instead of a signed transaction.
 *   · `send` takes signed transaction hex instead of a prepared id.
 *
 * The second difference is where the trust boundary sits. In the signing
 * service, `send` takes only an id because the server built and signed the
 * transaction — the id is a promise that the bytes cannot have changed. Here
 * the server never signed anything, so it must accept bytes from outside.
 *
 * That is riskier by nature, and it is why `broadcastSigned` re-checks that
 * every input is a UTXO this wallet watches. Without that, the endpoint would
 * be an open relay for anyone holding the token.
 *
 * ─── What this service refuses to have ─────────────────────────────────────
 * No signing method, no key export, no mnemonic. Same reflection test as the
 * signing service: the strongest guarantee that an endpoint cannot leak a
 * secret is that no code path exists — and here there is not even a secret to
 * leak.
 */

import type { WatchOnlyWallet } from "../../../core/wallet/watchOnly.js";
import type { ChainSource } from "../../../core/chain/types.js";
import type { SelectionStrategy } from "../../../core/utxo/coinSelection.js";
import { unprocessable, badRequest } from "../errors.js";

export class WatchOnlyService {
  constructor(
    private readonly wallet: WatchOnlyWallet,
    private readonly chain?: ChainSource,
  ) {}

  summary(): Record<string, unknown> {
    return {
      network: this.wallet.network.name,
      derivationPath: this.wallet.path,
      fingerprint: this.wallet.fingerprint,
      addressType: "P2WPKH (BIP-84)",
      gapLimit: 20,
      // Stated in the summary, not buried: a client should be able to tell
      // what kind of server it is talking to before it tries to spend.
      watchOnly: true,
      canSign: false,
    };
  }

  receiveAddress(): Record<string, unknown> {
    const derived = this.wallet.currentReceiveAddress();
    return { address: derived.address, path: derived.path, network: this.wallet.network.name };
  }

  nextReceiveAddress(): Record<string, unknown> {
    const derived = this.wallet.nextReceiveAddress();
    return { address: derived.address, path: derived.path, network: this.wallet.network.name };
  }

  balance(): Record<string, string | number> {
    const balance = this.wallet.balance();
    return {
      total: balance.total.toString(),
      spendable: balance.spendable.toString(),
      unconfirmed: balance.unconfirmed.toString(),
      unavailable: balance.unavailable.toString(),
      utxoCount: balance.utxoCount,
    };
  }

  utxos(): Array<Record<string, string | number | boolean>> {
    return this.wallet.utxos.all.map((utxo) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      value: utxo.value.toString(),
      address: utxo.address,
      confirmations: utxo.confirmations,
      frozen: utxo.frozen ?? false,
    }));
  }

  async sync(): Promise<{ utxos: number; addressesScanned: number }> {
    if (!this.chain) throw unprocessable("No chain source is configured");
    const result = await this.wallet.sync(this.chain);
    return { utxos: result.utxos, addressesScanned: result.addressesScanned };
  }

  async history(limit = 50): Promise<Array<Record<string, unknown>>> {
    if (!this.chain) throw unprocessable("No chain source is configured");
    const entries = await this.wallet.history(this.chain, { limit });
    return entries.map((tx) => ({
      txid: tx.txid,
      confirmations: tx.confirmations,
      direction: tx.direction ?? null,
      netValue: tx.netValue?.toString() ?? null,
      fee: tx.fee?.toString() ?? null,
      blockHeight: tx.blockHeight ?? null,
      blockTime: tx.blockTime ?? null,
    }));
  }

  async feeEstimates(): Promise<Record<string, unknown>> {
    const estimates = await this.wallet.feeEstimates(this.chain);
    return {
      high: estimates.high,
      medium: estimates.medium,
      low: estimates.low,
      isLive: estimates.isLive,
      source: estimates.source,
      fetchedAt: new Date(estimates.fetchedAt).toISOString(),
    };
  }

  /**
   * Build an unsigned PSBT.
   *
   * Every spending guard runs here, so a bad request fails on the server
   * rather than wasting a signing round on the user's device. Nothing is
   * held: a PSBT is stateless, and the server has nothing to hold that would
   * matter.
   */
  prepare(options: {
    to: string;
    amount: bigint;
    feeRate: number;
    strategy?: SelectionStrategy;
  }): Record<string, unknown> {
    const payment = this.wallet.buildPayment({
      to: options.to,
      amount: options.amount,
      feeRate: options.feeRate,
      ...(options.strategy ? { strategy: options.strategy } : {}),
    });

    return {
      psbt: payment.psbt,
      txid: payment.txid,
      recipient: payment.recipient,
      amount: payment.amount.toString(),
      fee: payment.fee.toString(),
      total: payment.total.toString(),
      change: payment.change.toString(),
      changeAddress: payment.changeAddress,
      remainingBalance: payment.remainingBalance.toString(),
      feeRate: Number(payment.feeRate.toFixed(2)),
      vsize: payment.vsize,
      inputCount: payment.inputs.length,
      inputPaths: payment.inputPaths,
      // Told plainly, because the flow differs from the signing service and a
      // client that assumed otherwise would wait forever for a broadcast.
      nextStep: "Sign this PSBT with your own key, then POST the signed transaction hex to /transactions/broadcast",
    };
  }

  /**
   * Broadcast a transaction signed elsewhere.
   *
   * Every input is checked against the UTXOs this wallet watches. Without
   * that, a hosted endpoint would relay arbitrary transactions for anyone
   * holding the token — an open relay with an authentication step.
   */
  async broadcast(rawTxHex: string): Promise<{ txid: string; broadcast: boolean }> {
    if (!this.chain) throw unprocessable("No chain source is configured for broadcasting");
    if (!/^[0-9a-f]+$/i.test(rawTxHex) || rawTxHex.length % 2 !== 0) {
      throw badRequest("Transaction must be even-length hexadecimal");
    }
    const txid = await this.wallet.broadcastSigned(this.chain, rawTxHex);
    return { txid, broadcast: true };
  }

  /** Verifiable security state. */
  securityStatus(): Record<string, unknown> {
    const thirdParty = (this.chain as { isThirdParty?: boolean })?.isThirdParty ?? null;
    return {
      network: this.wallet.network.name,
      isMainnet: this.wallet.network.isMainnet,
      walletType: "watch-only (BIP-84)",
      keysHeldBy: "nobody — this process holds an extended PUBLIC key only",
      canSign: false,
      chainSource: this.chain?.name ?? null,
      chainSourceIsThirdParty: thirdParty,
      privacyWarning:
        (this.chain as { privacyWarning?: string | null })?.privacyWarning ?? null,
      warnings: this.warnings(),
    };
  }

  private warnings(): string[] {
    const warnings: string[] = [
      "This server cannot spend. It holds no private key, and signing happens wherever your seed lives.",
      // Being unable to steal is not the same as being harmless, and a user
      // deciding whether to trust a host should be told the actual cost.
      "This server CAN see every address, balance and transaction in the account. Being unable to spend is not the same as being private.",
    ];
    if (this.wallet.network.isMainnet) {
      warnings.push("This wallet is on MAINNET. Transactions are irreversible.");
    }
    if (!this.chain) warnings.push("No chain source configured; balances will be empty.");
    if ((this.chain as { isThirdParty?: boolean })?.isThirdParty) {
      warnings.push(
        "The configured chain source is a third party and can observe every address in this wallet.",
      );
    }
    return warnings;
  }

  // ── Endpoints that exist in the signing service and are absent here ─────
  // No prepare-and-hold, no bumpFee, no policy. All three require a private
  // key or server-held state that this deployment deliberately does not have.

  policyStatus(): Record<string, unknown> {
    return {
      unrestricted: true,
      note: "Spending policy does not apply: this server cannot spend.",
    };
  }

  replaceable(): Array<Record<string, unknown>> {
    return [];
  }
}
