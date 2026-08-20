/**
 * WALLET
 *
 * The layer that turns cryptographic primitives into something a person can
 * use. It owns the seed, derives addresses, tracks UTXOs, and produces signed
 * transactions.
 *
 * ─── Design rule: the wallet holds secrets; nothing above it does ──────────
 * This is the boundary. Everything above the wallet — the API, the UI — deals
 * in addresses, amounts, and transaction hex. None of them can obtain key
 * material, because none of them is given a way to ask for it.
 *
 * `send()` returns a signed transaction, not a key. `getAddress()` returns a
 * string, not a key. There is no `exportPrivateKey` method. Backup is the
 * mnemonic, handed over exactly once at creation via an explicitly-named
 * method that reads as dangerous at the call site.
 *
 * ─── The gap limit ─────────────────────────────────────────────────────────
 * A wallet restored from a mnemonic does not know how many addresses it used.
 * The convention (BIP-44) is to scan forward until 20 consecutive addresses
 * show no history, then stop.
 *
 * This is why handing out addresses far ahead of use is dangerous: generate
 * address 50 without using 0-29, receive funds there, and a restore will scan
 * to 20, find nothing, and report an empty wallet. The funds are not lost —
 * they are simply beyond where the scan stopped. Veyra caps forward address
 * generation at the gap limit for this reason.
 *
 * ─── Change address rotation ───────────────────────────────────────────────
 * Every transaction sends change to a FRESH address on the internal chain.
 *
 * Reusing a change address is a privacy failure, not merely untidy. Change
 * detection is one of the two pillars of blockchain analysis: if an output
 * returns to an address that has been seen before as a change destination,
 * an analyst can link the transactions with high confidence and follow the
 * wallet across its history.
 *
 * ─── Talking to a chain ────────────────────────────────────────────────────
 * The wallet has NO chain source by default. One must be passed explicitly to
 * `sync()` or `broadcast()`, so the wallet never contacts a third party
 * without the caller choosing to — which matters because that contact reveals
 * every address in the wallet. See core/chain/esplora.ts.
 *
 * UTXOs can still be supplied directly via `setUtxos()` for offline use.
 */

import { generateMnemonic, mnemonicToSeed, validateMnemonic } from "../mnemonic/index.js";
import { ExtendedKey } from "../derivation/bip32.js";
import { Bip84Account, p2wpkhScriptPubKey, validateAddress, type DerivedAddress } from "../addresses/bip84.js";
import { decodeSegwitAddress } from "../addresses/bech32.js";
import { DEFAULT_NETWORK, type Network } from "../bitcoin/networks.js";
import { UtxoSet, type Utxo, type Balance, isDust, DUST_THRESHOLD_P2WPKH } from "../utxo/utxo.js";
import { selectCoins, type SelectionResult, type SelectionStrategy } from "../utxo/coinSelection.js";
import { assertFeeMatchesEstimate } from "../utxo/fees.js";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../transactions/transaction.js";
import { signTransaction, verifyTransaction, calculateFee } from "../signing/signer.js";
import { wipe } from "../crypto/entropy.js";
import type { ChainSource, ChainTransaction } from "../chain/types.js";
import { ChainError } from "../chain/types.js";
import { VeyraError } from "../errors/index.js";

export class WalletError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Wallet: ${reason}`);
    this.name = "WalletError";
  }
}

/** BIP-44 gap limit: consecutive unused addresses before a restore scan stops. */
export const GAP_LIMIT = 20;

/** A fully-prepared, signed transaction plus everything needed to review it. */
export interface PreparedTransaction {
  readonly transaction: Transaction;
  readonly txid: string;
  readonly hex: string;
  /** What the recipient receives. */
  readonly amount: bigint;
  /** What the miner receives. */
  readonly fee: bigint;
  /** amount + fee. */
  readonly total: bigint;
  /** Change returned to the wallet. Zero for a changeless transaction. */
  readonly change: bigint;
  readonly changeAddress: string | null;
  readonly recipient: string;
  /** Spendable balance after this transaction confirms. */
  readonly remainingBalance: bigint;
  readonly vsize: number;
  readonly feeRate: number;
  readonly inputs: readonly Utxo[];
  readonly strategy: SelectionStrategy;
}

export class Wallet {
  readonly network: Network;
  readonly account: Bip84Account;
  readonly #master: ExtendedKey;
  #utxos: UtxoSet;
  #nextReceiveIndex = 0;
  #nextChangeIndex = 0;

  /**
   * Cache of addresses this wallet controls, built lazily on first use.
   *
   * Deriving the gap-limit window costs 40 EC scalar multiplications. Without
   * this cache, `setUtxos` paid that cost on every call — which is invisible
   * in normal use but made a 200-iteration property test spend seven seconds
   * in key derivation. Caching is safe because the address set is a pure
   * function of the seed, network, and account index, none of which change
   * over a wallet's lifetime.
   */
  #knownAddresses: Set<string> | null = null;

  /** How deep the address cache currently reaches. Grows, never shrinks. */
  #knownDepth = 0;

  private constructor(master: ExtendedKey, network: Network, accountIndex: number) {
    this.#master = master;
    this.network = network;
    this.account = Bip84Account.fromMasterKey(master, network, accountIndex);
    this.#utxos = new UtxoSet();
  }

  /**
   * Create a brand-new wallet.
   *
   * Returns the wallet AND the mnemonic. The mnemonic is returned exactly
   * once, here, and never again — there is no `getMnemonic()`. If the caller
   * discards it, the funds are unrecoverable, which is the correct and honest
   * behaviour for self-custody: the wallet cannot secretly retain a copy for
   * you, because a copy it can retrieve is a copy an attacker can retrieve.
   */
  static create(
    network: Network = DEFAULT_NETWORK,
    wordCount: 12 | 24 = 24,
    accountIndex = 0,
  ): { wallet: Wallet; mnemonic: string } {
    const mnemonic = generateMnemonic(wordCount);
    const seed = mnemonicToSeed(mnemonic);
    try {
      const master = ExtendedKey.fromSeed(seed);
      return { wallet: new Wallet(master, network, accountIndex), mnemonic };
    } finally {
      wipe(seed);
    }
  }

  /**
   * Restore from a mnemonic.
   *
   * The checksum is validated BEFORE deriving anything. BIP-39 defines a seed
   * for any string, so a wallet that skips validation happily derives from a
   * typo'd phrase and shows an empty balance — leaving the user to conclude
   * their funds are gone when the phrase is simply mistyped.
   */
  static restore(
    mnemonic: string,
    network: Network = DEFAULT_NETWORK,
    passphrase = "",
    accountIndex = 0,
  ): Wallet {
    if (!validateMnemonic(mnemonic)) {
      throw new WalletError(
        "mnemonic checksum failed — check for mistyped or transposed words",
      );
    }
    const seed = mnemonicToSeed(mnemonic, passphrase);
    try {
      return new Wallet(ExtendedKey.fromSeed(seed), network, accountIndex);
    } finally {
      wipe(seed);
    }
  }

  /** The account-level derivation path, e.g. m/84'/1'/0'. Not secret. */
  get path(): string {
    return this.account.path;
  }

  /** Master key fingerprint — a public identifier, safe to log or display. */
  get fingerprint(): string {
    return this.#master.identifier;
  }

  // ── Addresses ───────────────────────────────────────────────────────────

  /** The current receive address. Stable until `nextReceiveAddress()`. */
  currentReceiveAddress(): DerivedAddress {
    return this.account.receiveAddress(this.#nextReceiveIndex);
  }

  /**
   * Advance to a fresh receive address.
   *
   * Capped at the gap limit: generating addresses far beyond what has been
   * used risks funds landing beyond where a restore scan will look.
   */
  nextReceiveAddress(): DerivedAddress {
    if (this.#nextReceiveIndex >= GAP_LIMIT) {
      throw new WalletError(
        `refusing to generate more than ${GAP_LIMIT} unused addresses: funds sent beyond ` +
          `the gap limit may not be found when restoring from the mnemonic`,
      );
    }
    this.#nextReceiveIndex++;
    return this.account.receiveAddress(this.#nextReceiveIndex);
  }

  /** A window of receive addresses, for scanning history. */
  receiveAddresses(count = GAP_LIMIT): DerivedAddress[] {
    return this.account.deriveAddresses(0, 0, count);
  }

  /** A fresh change address. Never reused — see the note at the top. */
  private freshChangeAddress(): DerivedAddress {
    return this.account.changeAddress(this.#nextChangeIndex++);
  }

  // ── UTXOs and balance ───────────────────────────────────────────────────

  /**
   * Load the UTXO set.
   *
   * Supplied by the caller, since the wallet has no network layer. Every UTXO
   * is validated as belonging to this wallet: an attacker-supplied UTXO for
   * an address we do not control would produce a transaction we cannot sign,
   * and in a more subtle attack could be used to manipulate fee arithmetic.
   */
  setUtxos(utxos: readonly Utxo[]): void {
    const known = this.knownAddresses();
    for (const utxo of utxos) {
      if (!known.has(utxo.address)) {
        throw new WalletError(
          `UTXO at ${utxo.txid}:${utxo.vout} is for an address this wallet does not control`,
        );
      }
    }
    this.#utxos = new UtxoSet(utxos);
  }

  /**
   * Addresses this wallet controls. Computed once and extended as needed.
   *
   * The `depth` parameter exists because of a real bug: `sync()` accepts a
   * custom `gapLimit`, and a scan deeper than the default discovered
   * addresses at index 20+ which `setUtxos` then rejected as "not ours". The
   * scan and the ownership check disagreed about the wallet's own addresses.
   *
   * The fix is one source of truth that grows: whatever depth has ever been
   * scanned stays known. The cache is still safe because the address set is a
   * pure function of seed, network, and account index.
   */
  private knownAddresses(depth = GAP_LIMIT): Set<string> {
    if (this.#knownAddresses === null) {
      this.#knownAddresses = new Set();
      this.#knownDepth = 0;
    }
    // Derive only the NEW range. Re-deriving the whole set on each call made
    // a deep scan quadratic — 30 discovered addresses meant ~1800 EC
    // multiplications, and the test suite went from seconds to a timeout.
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

  /** True if the given address belongs to this wallet. */
  ownsAddress(address: string): boolean {
    return this.knownAddresses().has(address);
  }

  // ── Chain synchronisation ───────────────────────────────────────────────

  /**
   * Discover this wallet's UTXOs from a chain source.
   *
   * ─── The gap-limit scan ─────────────────────────────────────────────────
   * Walks each chain (receive, then change) asking whether each address has
   * ever been used, and STOPS after `GAP_LIMIT` consecutive unused ones. This
   * mirrors what every other wallet does on restore, which is the point: if
   * Veyra scanned further than the convention it would find funds that other
   * wallets would report as missing, and vice versa.
   *
   * ─── What is verified ───────────────────────────────────────────────────
   * Every returned UTXO is checked against addresses this wallet actually
   * derives. A UTXO for an unknown address is rejected rather than absorbed:
   * we could not sign it, and accepting it would corrupt balance arithmetic.
   *
   * ─── What is NOT verified ───────────────────────────────────────────────
   * We cannot confirm the server told us about everything. A source that
   * omits a UTXO makes the wallet look poorer and produces an unexplained
   * "insufficient funds". That is a denial of service, not theft, and no
   * light client can detect it — it is the cost of not running a full node,
   * and it is recorded in docs/THREAT-MODEL.md rather than papered over.
   */
  async sync(source: ChainSource, options: { gapLimit?: number } = {}): Promise<{
    utxos: number;
    balance: Balance;
    addressesScanned: number;
  }> {
    if (source.network !== this.network.name) {
      // Syncing a mainnet wallet against a testnet server (or the reverse)
      // would report a nonsense balance built from unrelated coins.
      throw new WalletError(
        `chain source serves '${source.network}' but this wallet is on ` +
          `'${this.network.name}'`,
      );
    }
    const gapLimit = options.gapLimit ?? GAP_LIMIT;
    const discovered: Utxo[] = [];
    let addressesScanned = 0;

    for (const chain of [0, 1] as const) {
      let consecutiveUnused = 0;
      let index = 0;

      // Hard ceiling so a source that claims every address has history
      // cannot drive an unbounded scan.
      const MAX_INDEX = 1000;

      // Widen the ownership cache to match the scan depth, so addresses this
      // scan is about to derive are recognised as ours by setUtxos below.
      this.knownAddresses(Math.max(gapLimit, this.#knownDepth));

      while (consecutiveUnused < gapLimit && index < MAX_INDEX) {
        const derived = this.account.deriveAddress(chain, index);
        const activity = await source.getAddressActivity(derived.address);
        addressesScanned++;

        if (activity.address !== derived.address) {
          throw new ChainError(
            "chain source returned activity for a different address than requested",
          );
        }

        if (activity.hasHistory) {
          consecutiveUnused = 0;
          // The scan runs PAST gapLimit whenever it keeps finding history, so
          // the ownership cache must track the deepest index actually
          // reached, not the configured limit.
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
          // Keep handing out addresses past ones already used.
          if (chain === 0 && index >= this.#nextReceiveIndex) {
            this.#nextReceiveIndex = Math.min(index + 1, gapLimit);
          }
          if (chain === 1 && index >= this.#nextChangeIndex) {
            this.#nextChangeIndex = index + 1;
          }
        } else {
          consecutiveUnused++;
        }
        index++;
      }
    }

    // Goes through setUtxos so ownership validation and duplicate detection
    // apply to synced data exactly as they do to caller-supplied data.
    this.setUtxos(discovered);
    return { utxos: discovered.length, balance: this.balance(), addressesScanned };
  }

  /**
   * Broadcast a prepared transaction.
   *
   * The returned txid is compared against the one we computed locally. A
   * mismatch means the server is broken or lying, and either way the
   * transaction's fate is unknown — so we treat it as a failure rather than
   * recording a success we cannot substantiate.
   *
   * Inputs are only marked spent on a confirmed match. If broadcast fails,
   * wallet state is untouched and the transaction can be retried.
   */
  async broadcast(source: ChainSource, prepared: PreparedTransaction): Promise<string> {
    if (source.network !== this.network.name) {
      throw new WalletError(
        `chain source serves '${source.network}' but this wallet is on '${this.network.name}'`,
      );
    }

    // Re-verify immediately before an irreversible action. Cheap, and the
    // transaction may have been sitting in memory since it was prepared.
    if (!verifyTransaction(prepared.transaction, prepared.inputs.map((u) => u.value))) {
      throw new WalletError("refusing to broadcast: the transaction failed verification");
    }

    const reportedTxid = await source.broadcast(prepared.hex);
    if (reportedTxid !== prepared.txid) {
      throw new ChainError(
        `broadcast returned txid ${reportedTxid} but the transaction's txid is ` +
          `${prepared.txid}; the transaction's status is unknown and it must be ` +
          `checked manually before retrying`,
      );
    }

    this.markSpent(prepared);
    return reportedTxid;
  }

  /** Transaction history across used addresses, if the source supports it. */
  async history(source: ChainSource): Promise<ChainTransaction[]> {
    if (!source.getTransactions) {
      throw new WalletError(`${source.name} does not provide transaction history`);
    }
    const seen = new Map<string, ChainTransaction>();
    for (const address of this.knownAddresses()) {
      for (const tx of await source.getTransactions(address)) {
        // Deduplicate: one transaction can touch several of our addresses.
        seen.set(tx.txid, tx);
      }
    }
    return [...seen.values()].sort((a, b) => b.confirmations - a.confirmations);
  }

  get utxos(): UtxoSet {
    return this.#utxos;
  }

  balance(minConfirmations = 1): Balance {
    return this.#utxos.balance(minConfirmations);
  }

  // ── Spending ────────────────────────────────────────────────────────────

  /**
   * Build and sign a payment.
   *
   * The order of checks matters. Everything that can fail is checked BEFORE
   * any signature exists, so a rejected send never leaves a partially-signed
   * transaction lying around.
   *
   * §16 requires that `amount + fee > balance` be prevented and that the UI
   * show Amount / Fee / Total / Remaining. All four are returned here rather
   * than computed in the interface, so an API client gets the same guarantees
   * as the UI.
   */
  send(options: {
    to: string;
    amount: bigint;
    feeRate: number;
    strategy?: SelectionStrategy;
    minConfirmations?: number;
  }): PreparedTransaction {
    const { to, amount, feeRate } = options;
    const minConfirmations = options.minConfirmations ?? 1;

    // ── Validate the destination BEFORE anything else ─────────────────────
    const validation = validateAddress(to, this.network);
    if (!validation.valid) {
      throw new WalletError(
        `invalid ${this.network.name} address: ${validation.reason}`,
      );
    }
    if (amount <= 0n) {
      throw new WalletError("amount must be positive");
    }
    if (isDust(amount)) {
      throw new WalletError(
        `amount of ${amount} sat is below the dust threshold of ${DUST_THRESHOLD_P2WPKH} sat ` +
          `and would not be relayed by the network`,
      );
    }

    // ── Select coins ──────────────────────────────────────────────────────
    const spendable = this.#utxos.spendable(minConfirmations);
    const selection: SelectionResult = selectCoins({
      utxos: spendable,
      target: amount,
      feeRate,
      outputCount: 1,
      ...(options.strategy ? { strategy: options.strategy } : {}),
    });

    // ── Build outputs ─────────────────────────────────────────────────────
    const { program } = decodeSegwitAddress(this.network.bech32Hrp, to);
    const recipientScript = new Uint8Array([0x00, program.length, ...program]);
    const outputs: TxOutput[] = [new TxOutput(amount, recipientScript)];

    let changeAddress: DerivedAddress | null = null;
    if (!selection.changeless && selection.change > 0n) {
      changeAddress = this.freshChangeAddress();
      outputs.push(
        new TxOutput(
          selection.change,
          p2wpkhScriptPubKey(this.account.node.derive(1).derive(changeAddress.index).publicKey),
        ),
      );
    }

    // ── Build inputs ──────────────────────────────────────────────────────
    const inputs = selection.selected.map(
      (utxo) => new TxInput({ txid: utxo.txid, vout: utxo.vout }, new Uint8Array(0), SEQUENCE_RBF),
    );

    const unsigned = new Transaction(2, inputs, outputs, 0);

    // ── Sign ──────────────────────────────────────────────────────────────
    const signed = signTransaction(
      unsigned,
      selection.selected.map((utxo) => ({
        value: utxo.value,
        privateKey: this.#master.derivePath(utxo.derivationPath).privateKey,
      })),
    );

    // ── Verify what we produced, before returning it ──────────────────────
    const inputValues = selection.selected.map((u) => u.value);
    if (!verifyTransaction(signed, inputValues)) {
      throw new WalletError("internal error: the signed transaction failed verification");
    }

    const actualFee = calculateFee(signed, inputValues);
    if (actualFee !== selection.fee) {
      throw new WalletError(
        `internal error: actual fee ${actualFee} does not match planned fee ${selection.fee}`,
      );
    }
    // Catches estimation drift before broadcast, when it is still fixable.
    assertFeeMatchesEstimate(signed.vsize(), actualFee, feeRate);

    const balanceBefore = this.balance(minConfirmations).spendable;

    return {
      transaction: signed,
      txid: signed.txid(),
      hex: signed.toHex(),
      amount,
      fee: actualFee,
      total: amount + actualFee,
      change: selection.change,
      changeAddress: changeAddress?.address ?? null,
      recipient: to,
      remainingBalance: balanceBefore - amount - actualFee,
      vsize: signed.vsize(),
      feeRate: Number(actualFee) / signed.vsize(),
      inputs: selection.selected,
      strategy: selection.strategy,
    };
  }

  /**
   * Mark a prepared transaction's inputs as spent.
   *
   * Called after a successful broadcast. Separate from `send()` on purpose:
   * building a transaction must not mutate wallet state, because the user may
   * review it and decline. Only a confirmed broadcast should consume coins.
   */
  markSpent(prepared: PreparedTransaction): void {
    this.#utxos = this.#utxos.without(
      prepared.inputs.map((u) => ({ txid: u.txid, vout: u.vout })),
    );
  }

  // ── Redaction ───────────────────────────────────────────────────────────

  toString(): string {
    return `Wallet<${this.network.name} ${this.path} fingerprint=${this.fingerprint}>`;
  }

  toJSON(): string {
    return this.toString();
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}
