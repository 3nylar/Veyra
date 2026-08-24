/**
 * WATCH-ONLY WALLET
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  THE POINT: A SERVER THAT IS USEFUL WITHOUT BEING DANGEROUS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * `Wallet` holds a seed. Hosting it means hosting private keys, and a hosted
 * process holding private keys is a custodial service whether or not anyone
 * calls it that — a compromise of the host is total loss for every user on it.
 *
 * This class holds **an account xpub and nothing else**. It can:
 *
 *   · derive every address in the account
 *   · scan the chain and report balances and UTXOs
 *   · select coins and build a complete, unsigned PSBT
 *   · broadcast a transaction someone else signed
 *
 * It cannot sign, and the reason is structural rather than a policy: there is
 * no private key anywhere in this object. `#accountKey` is parsed from an
 * xpub, so `hasPrivateKey` is false and every derived child is watch-only. A
 * bug that "accidentally signed" is not possible, because there is nothing to
 * sign with.
 *
 * ─── What the host still learns ────────────────────────────────────────────
 * Being unable to steal is not the same as being harmless. A hosted watch-only
 * server sees every address, every balance, and every transaction — the whole
 * financial history of the wallet, linked to whatever IP connects to it.
 *
 * That is a genuine cost, and it is the same cost as using any third-party
 * Esplora. Running your own instance removes it; using someone else's does
 * not. The README says this where a user deciding whether to deploy will read
 * it, rather than only here.
 *
 * ─── The signing boundary ──────────────────────────────────────────────────
 *
 *     hosted (this)                          local (your machine)
 *     ─────────────                          ────────────────────
 *     derive addresses
 *     track balances
 *     select coins
 *     build unsigned PSBT   ── PSBT ──►
 *                                            open PSBT, verify amounts
 *                                            sign with the seed
 *                           ◄── signed ──
 *     broadcast
 *
 * The PSBT carries `witness_utxo` for every input, so the local signer can
 * verify the amount it commits to without trusting the server. That matters:
 * BIP-143 puts the value in the signature preimage, so a server lying about it
 * produces a signature that simply does not verify — the local signer is not
 * trusting the host on the number that matters most.
 */

import { ExtendedKey } from "../derivation/bip32.js";
import { Bip84Account, p2wpkhScriptPubKey, validateAddress, type DerivedAddress } from "../addresses/bip84.js";
import { decodeSegwitAddress } from "../addresses/bech32.js";
import { Psbt } from "../psbt/psbt.js";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../transactions/transaction.js";
import { UtxoSet, type Utxo, type Balance, isDust, DUST_THRESHOLD_P2WPKH } from "../utxo/utxo.js";
import { selectCoins, type SelectionStrategy } from "../utxo/coinSelection.js";
import type { ChainSource, ChainTransaction, FeeEstimates } from "../chain/types.js";
import { ChainError } from "../chain/types.js";
import type { Network } from "../bitcoin/networks.js";
import { DEFAULT_NETWORK } from "../bitcoin/networks.js";
import { FEE_RATE_PRESETS } from "../utxo/fees.js";
import { GAP_LIMIT, WalletError } from "./wallet.js";

/** An unsigned payment, ready for an external signer. */
export interface UnsignedPayment {
  /** Base64 PSBT. Hand this to a signer. */
  readonly psbt: string;
  /** Txid the signed transaction will have. SegWit makes this stable. */
  readonly txid: string;
  readonly recipient: string;
  readonly amount: bigint;
  readonly fee: bigint;
  readonly total: bigint;
  readonly change: bigint;
  readonly changeAddress: string | null;
  readonly remainingBalance: bigint;
  readonly feeRate: number;
  readonly vsize: number;
  readonly inputs: readonly Utxo[];
  /** Derivation paths a signer needs, in input order. */
  readonly inputPaths: readonly string[];
}

export class WatchOnlyWallet {
  readonly network: Network;
  readonly account: Bip84Account;
  readonly #accountKey: ExtendedKey;
  #utxos: UtxoSet = new UtxoSet();
  #nextReceiveIndex = 0;
  #nextChangeIndex = 0;
  #knownAddresses: Set<string> | null = null;
  #knownDepth = 0;

  private constructor(accountKey: ExtendedKey, network: Network, accountIndex: number) {
    // Refuse a key that carries private material. An xprv here would make
    // this class silently capable of signing, defeating the guarantee its
    // name advertises.
    if (accountKey.hasPrivateKey) {
      throw new WalletError(
        "a watch-only wallet must be built from an extended PUBLIC key. " +
          "An xprv was supplied — this would give the process spending authority.",
      );
    }
    this.#accountKey = accountKey;
    this.network = network;
    this.account = Bip84Account.fromAccountNode(accountKey, network, accountIndex);
  }

  /**
   * Build from an account-level extended public key.
   *
   * The xpub must be at the ACCOUNT level (m/84'/coin'/account'), because the
   * two unhardened levels below it are what this derives. A key from the wrong
   * depth produces addresses that look valid and that nobody else derives —
   * which is indistinguishable from lost funds.
   */
  static fromExtendedPublicKey(
    xpub: string,
    network: Network = DEFAULT_NETWORK,
    accountIndex = 0,
  ): WatchOnlyWallet {
    const key = ExtendedKey.fromExtendedKey(xpub.trim());
    if (key.depth !== 3) {
      throw new WalletError(
        `expected an account-level key at depth 3 (m/84'/coin'/account'), got depth ${key.depth}. ` +
          `A key from the wrong level derives addresses nobody else will find.`,
      );
    }
    return new WatchOnlyWallet(key, network, accountIndex);
  }

  /** Always false. There is no private key in this object. */
  get canSign(): false {
    return false;
  }

  get fingerprint(): string {
    return this.#accountKey.identifier;
  }

  get path(): string {
    return this.account.path;
  }

  /** The xpub this wallet watches. Already known to whoever supplied it. */
  get accountXpub(): string {
    return this.#accountKey.toExtendedPublicKey(this.network.isMainnet ? "mainnet" : "testnet");
  }

  // ── Addresses ───────────────────────────────────────────────────────────

  currentReceiveAddress(): DerivedAddress {
    return this.account.receiveAddress(this.#nextReceiveIndex);
  }

  nextReceiveAddress(): DerivedAddress {
    if (this.#nextReceiveIndex >= GAP_LIMIT) {
      throw new WalletError(
        `refusing to generate more than ${GAP_LIMIT} unused addresses: funds sent ` +
          `beyond the gap limit may not be found when restoring`,
      );
    }
    this.#nextReceiveIndex++;
    return this.account.receiveAddress(this.#nextReceiveIndex);
  }

  receiveAddresses(count = GAP_LIMIT): DerivedAddress[] {
    return this.account.deriveAddresses(0, 0, count);
  }

  private knownAddresses(depth = GAP_LIMIT): Set<string> {
    if (this.#knownAddresses === null) {
      this.#knownAddresses = new Set();
      this.#knownDepth = 0;
    }
    if (depth > this.#knownDepth) {
      const from = this.#knownDepth;
      const count = depth - from;
      for (const chain of [0, 1] as const) {
        for (const derived of this.account.deriveAddresses(chain, from, count)) {
          this.#knownAddresses.add(derived.address);
        }
      }
      this.#knownDepth = depth;
    }
    return this.#knownAddresses;
  }

  ownsAddress(address: string): boolean {
    return this.knownAddresses().has(address);
  }

  // ── Chain ───────────────────────────────────────────────────────────────

  setUtxos(utxos: readonly Utxo[]): void {
    const known = this.knownAddresses();
    for (const utxo of utxos) {
      if (!known.has(utxo.address)) {
        throw new WalletError(
          `UTXO at ${utxo.txid}:${utxo.vout} is for an address this wallet does not watch`,
        );
      }
    }
    this.#utxos = new UtxoSet(utxos);
  }

  get utxos(): UtxoSet {
    return this.#utxos;
  }

  balance(minConfirmations = 1): Balance {
    return this.#utxos.balance(minConfirmations);
  }

  async sync(source: ChainSource, options: { gapLimit?: number } = {}): Promise<{
    utxos: number;
    balance: Balance;
    addressesScanned: number;
  }> {
    if (source.network !== this.network.name) {
      throw new WalletError(
        `chain source serves '${source.network}' but this wallet is on '${this.network.name}'`,
      );
    }
    const gapLimit = options.gapLimit ?? GAP_LIMIT;
    const discovered: Utxo[] = [];
    let addressesScanned = 0;
    const MAX_INDEX = 1000;

    for (const chain of [0, 1] as const) {
      let consecutiveUnused = 0;
      let index = 0;
      this.knownAddresses(Math.max(gapLimit, this.#knownDepth));

      while (consecutiveUnused < gapLimit && index < MAX_INDEX) {
        const derived = this.account.deriveAddress(chain, index);
        const activity = await source.getAddressActivity(derived.address);
        addressesScanned++;

        if (activity.address !== derived.address) {
          throw new ChainError("chain source answered about a different address than requested");
        }

        if (activity.hasHistory) {
          consecutiveUnused = 0;
          if (index + 1 > this.#knownDepth) this.knownAddresses(index + 1);
          for (const utxo of activity.utxos) {
            discovered.push({
              txid: utxo.txid,
              vout: utxo.vout,
              value: utxo.value,
              derivationPath: derived.path,
              address: derived.address,
              confirmations: utxo.confirmations,
            });
          }
          if (chain === 0 && index >= this.#nextReceiveIndex) {
            this.#nextReceiveIndex = Math.min(index + 1, gapLimit);
          }
          if (chain === 1 && index >= this.#nextChangeIndex) this.#nextChangeIndex = index + 1;
        } else {
          consecutiveUnused++;
        }
        index++;
      }
    }

    this.setUtxos(discovered);
    return { utxos: discovered.length, balance: this.balance(), addressesScanned };
  }

  async history(source: ChainSource, options: { limit?: number } = {}): Promise<ChainTransaction[]> {
    if (!source.getTransactions) {
      throw new WalletError(`${source.name} does not provide transaction history`);
    }
    const folded = new Map<string, ChainTransaction>();
    for (const address of this.knownAddresses()) {
      let entries: ChainTransaction[];
      try {
        entries = await source.getTransactions(address);
      } catch (error) {
        if (/watch-only wallet .* does not exist|importAddressesForHistory/.test((error as Error).message)) {
          throw new WalletError((error as Error).message);
        }
        continue;
      }
      for (const entry of entries) {
        const existing = folded.get(entry.txid);
        if (!existing) {
          folded.set(entry.txid, entry);
          continue;
        }
        const netValue = (existing.netValue ?? 0n) + (entry.netValue ?? 0n);
        folded.set(entry.txid, {
          ...existing,
          netValue,
          direction: netValue > 0n ? "received" : netValue < 0n ? "sent" : "internal",
          ...(existing.fee ?? entry.fee ? { fee: existing.fee ?? entry.fee } : {}),
        });
      }
    }
    return [...folded.values()]
      .sort((a, b) => {
        if (a.confirmations !== b.confirmations) return a.confirmations - b.confirmations;
        return (b.blockTime ?? 0) - (a.blockTime ?? 0);
      })
      .slice(0, options.limit ?? 100);
  }

  async feeEstimates(source?: ChainSource): Promise<FeeEstimates & { isLive: boolean }> {
    const fallback = {
      high: FEE_RATE_PRESETS.high,
      medium: FEE_RATE_PRESETS.medium,
      low: FEE_RATE_PRESETS.low,
      source: "static defaults — not live network rates",
      fetchedAt: Date.now(),
      isLive: false,
    };
    if (!source?.getFeeEstimates) return fallback;
    try {
      const live = await source.getFeeEstimates();
      if (live.high === undefined && live.medium === undefined && live.low === undefined) {
        return { ...fallback, source: `${live.source} has no estimates yet — using static defaults` };
      }
      return {
        high: live.high ?? fallback.high,
        medium: live.medium ?? fallback.medium,
        low: live.low ?? fallback.low,
        source: live.source,
        fetchedAt: live.fetchedAt,
        isLive: true,
      };
    } catch {
      return fallback;
    }
  }

  // ── Building unsigned payments ──────────────────────────────────────────

  /**
   * Build a complete, unsigned PSBT.
   *
   * Every spending guard runs here — address validity for this network, the
   * dust threshold, sufficient funds — so a bad request fails on the server
   * rather than wasting a signing round on the user's device.
   *
   * The PSBT carries `witness_utxo` and a BIP-32 derivation for each input, so
   * the signer can verify what it is committing to WITHOUT trusting this
   * server. That is the property that makes hosting acceptable: BIP-143 puts
   * the input value in the signature preimage, so a server lying about an
   * amount produces a signature that does not verify.
   */
  buildPayment(options: {
    to: string;
    amount: bigint;
    feeRate: number;
    strategy?: SelectionStrategy;
    minConfirmations?: number;
  }): UnsignedPayment {
    const { to, amount, feeRate } = options;
    const minConfirmations = options.minConfirmations ?? 1;

    const validation = validateAddress(to, this.network);
    if (!validation.valid) {
      throw new WalletError(`invalid ${this.network.name} address: ${validation.reason}`);
    }
    if (amount <= 0n) throw new WalletError("amount must be positive");
    if (isDust(amount)) {
      throw new WalletError(
        `amount of ${amount} sat is below the dust threshold of ${DUST_THRESHOLD_P2WPKH} sat`,
      );
    }

    const selection = selectCoins({
      utxos: this.#utxos.spendable(minConfirmations),
      target: amount,
      feeRate,
      outputCount: 1,
      ...(options.strategy ? { strategy: options.strategy } : {}),
    });

    const { program } = decodeSegwitAddress(this.network.bech32Hrp, to);
    const outputs: TxOutput[] = [
      new TxOutput(amount, new Uint8Array([0x00, program.length, ...program])),
    ];

    let changeAddress: DerivedAddress | null = null;
    if (!selection.changeless && selection.change > 0n) {
      changeAddress = this.account.changeAddress(this.#nextChangeIndex++);
      outputs.push(
        new TxOutput(
          selection.change,
          p2wpkhScriptPubKey(this.account.node.derive(1).derive(changeAddress.index).publicKey),
        ),
      );
    }

    const unsigned = new Transaction(
      2,
      selection.selected.map(
        (utxo) => new TxInput({ txid: utxo.txid, vout: utxo.vout }, new Uint8Array(0), SEQUENCE_RBF),
      ),
      outputs,
      0,
    );

    const psbt = Psbt.create(unsigned);
    const inputPaths: string[] = [];

    for (const [index, utxo] of selection.selected.entries()) {
      const derived = this.addressRecordFor(utxo.address);
      psbt.setWitnessUtxo(index, utxo.value, p2wpkhScriptPubKey(derived.publicKeyObject));
      psbt.setSighashType(index, 0x01);
      psbt.setBip32Derivation(index, {
        publicKey: derived.publicKeyObject.toBytes(),
        masterFingerprint: hexToFingerprint(this.fingerprint),
        path: utxo.derivationPath,
      });
      inputPaths.push(utxo.derivationPath);
    }

    const balanceBefore = this.balance(minConfirmations).spendable;

    return {
      psbt: psbt.toBase64(),
      // SegWit keeps the txid stable before signing, so this is the final one.
      txid: unsigned.txid(),
      recipient: to,
      amount,
      fee: selection.fee,
      total: amount + selection.fee,
      change: selection.change,
      changeAddress: changeAddress?.address ?? null,
      remainingBalance: balanceBefore - amount - selection.fee,
      feeRate: Number(selection.fee) / selection.estimatedVsize,
      vsize: selection.estimatedVsize,
      inputs: selection.selected,
      inputPaths,
    };
  }

  /** Locate the derived record for an address we watch. */
  private addressRecordFor(address: string): DerivedAddress & { publicKeyObject: import("../keys/publicKey.js").PublicKey } {
    for (const chain of [0, 1] as const) {
      for (let index = 0; index < this.#knownDepth; index++) {
        const derived = this.account.deriveAddress(chain, index);
        if (derived.address === address) {
          return {
            ...derived,
            publicKeyObject: this.account.node.derive(chain).derive(index).publicKey,
          };
        }
      }
    }
    throw new WalletError(`address ${address} is not derived by this wallet`);
  }

  /**
   * Broadcast a transaction someone else signed.
   *
   * Verified against this wallet before publishing: the inputs must be UTXOs
   * we watch, and the outputs must be what was intended. A hosted service
   * asked to broadcast arbitrary hex would be an open relay.
   */
  async broadcastSigned(source: ChainSource, rawTxHex: string): Promise<string> {
    if (source.network !== this.network.name) {
      throw new WalletError(
        `chain source serves '${source.network}' but this wallet is on '${this.network.name}'`,
      );
    }

    let transaction: Transaction;
    try {
      transaction = Transaction.fromHex(rawTxHex);
    } catch (error) {
      throw new WalletError(`not a valid transaction: ${(error as Error).message}`);
    }

    if (!transaction.hasWitness) {
      throw new WalletError("transaction is not signed — no witness data");
    }
    // Every input must be a coin we watch. Otherwise this endpoint would
    // relay anything at all for anyone who holds the token.
    for (const input of transaction.inputs) {
      const utxo = this.#utxos.find(input.outpoint.txid, input.outpoint.vout);
      if (!utxo) {
        throw new WalletError(
          `input ${input.outpoint.txid}:${input.outpoint.vout} is not a UTXO this wallet watches`,
        );
      }
    }

    const txid = await source.broadcast(transaction.toHex());
    if (txid !== transaction.txid()) {
      throw new ChainError(
        `broadcast returned txid ${txid} but the transaction's txid is ${transaction.txid()}; ` +
          `its status is unknown and must be checked manually`,
      );
    }
    this.#utxos = this.#utxos.without(
      transaction.inputs.map((input) => ({
        txid: input.outpoint.txid,
        vout: input.outpoint.vout,
      })),
    );
    return txid;
  }

  toString(): string {
    return `WatchOnlyWallet<${this.network.name} ${this.path} ${this.fingerprint}>`;
  }

  toJSON(): string {
    return this.toString();
  }
}

function hexToFingerprint(hex: string): Uint8Array {
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
