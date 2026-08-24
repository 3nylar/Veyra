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
import {
  assertFeeMatchesEstimate, FEE_RATE_PRESETS, INCREMENTAL_RELAY_FEE_RATE,
} from "../utxo/fees.js";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../transactions/transaction.js";
import { signTransaction, verifyTransaction, calculateFee } from "../signing/signer.js";
import { wipe } from "../crypto/entropy.js";
import type { ChainSource, ChainTransaction, FeeEstimates } from "../chain/types.js";
import {
  SpendingPolicy, NO_LIMITS,
  type PolicyDecision, type SpendRecord, type PolicyLimits,
} from "../policy/spendingPolicy.js";
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
  /** Set when this is a BIP-125 replacement: the txid it supersedes. */
  readonly replaces?: string;
  /**
   * The spending-policy decision.
   *
   * `deny` never reaches here — it throws. A `delay` DOES: the transaction is
   * built and signed, and the caller decides whether to hold it. See
   * core/policy/spendingPolicy.ts on why Veyra decides but does not hold.
   */
  readonly policy?: PolicyDecision;
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

  /**
   * Transactions this wallet has broadcast, by txid.
   *
   * Needed to replace one: a fee bump rebuilds the ORIGINAL transaction with a
   * higher fee, which requires knowing exactly which inputs it spent and what
   * it paid out.
   *
   * ⚠️ In-memory only. Restarting the process loses the ability to bump
   * anything broadcast before it — the transaction is unaffected and will
   * still confirm or not on its own, but Veyra can no longer replace it.
   * Persisting this is a wallet-database feature that does not exist yet, and
   * saying so is better than a user discovering it while a payment is stuck.
   */
  #broadcast = new Map<string, PreparedTransaction>();

  /**
   * Spending policy. Unrestricted unless one is set.
   *
   * Opt-in deliberately: a wallet that silently imposed caps nobody
   * configured would be surprising in the worst way.
   */
  #policy: SpendingPolicy = new SpendingPolicy(NO_LIMITS);

  /** Completed spends, for velocity accounting and known-recipient checks. */
  #spendHistory: SpendRecord[] = [];

  /**
   * Cache of derived signing nodes, keyed by derivation path.
   *
   * `derivePath` from the master costs ~2.6 ms — three hardened levels of
   * HMAC-SHA512 plus EC multiplication — and `send()` calls it once PER INPUT.
   * A twenty-input transaction paid that cost twenty times.
   *
   * ─── The security trade-off, stated rather than assumed ─────────────────
   * Caching derived nodes keeps private key material resident longer, which
   * looks like a regression. Materially it is not: the MASTER key is already
   * resident for the process lifetime, and anyone who can read this process's
   * memory can derive every child from it in microseconds. The cache grants an
   * attacker no capability they did not already have.
   *
   * What it WOULD change is a wallet that unloaded its master between
   * operations — which this one does not do, and which the threat model
   * (docs/THREAT-MODEL.md, A5) already places out of reach. If that ever
   * changes, this cache must be reconsidered.
   *
   * Bounded, so a caller iterating paths cannot grow it without limit.
   */
  #signingNodes = new Map<string, ExtendedKey>();

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
  /** Largest number of signing nodes to memoise. */
  static readonly MAX_CACHED_NODES = 500;

  /** A signing node for a path, memoised. See the note on #signingNodes. */
  private signingNode(path: string): ExtendedKey {
    const cached = this.#signingNodes.get(path);
    if (cached) return cached;
    const node = this.#master.derivePath(path);
    if (this.#signingNodes.size < Wallet.MAX_CACHED_NODES) {
      this.#signingNodes.set(path, node);
    }
    return node;
  }

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
    // Record it so it can be fee-bumped if it gets stuck.
    this.#broadcast.set(prepared.txid, prepared);

    // Record the completed spend. This is what makes a destination "known"
    // for the new-recipient rule — and note it happens only on a SUCCESSFUL
    // broadcast, so a blocked or failed attempt never grants that status.
    this.#spendHistory.push({
      amount: prepared.amount,
      fee: prepared.fee,
      recipient: prepared.recipient,
      at: Date.now(),
    });

    // A replacement supersedes what it replaced: the two spend the same
    // inputs, so only one can ever confirm. Dropping the original stops it
    // being offered for a second bump, which would build on a transaction the
    // network has already discarded.
    if (prepared.replaces) this.#broadcast.delete(prepared.replaces);

    return reportedTxid;
  }


  /** Install a spending policy. Replaces any existing one. */
  setPolicy(limits: PolicyLimits): void {
    this.#policy = new SpendingPolicy(limits);
  }

  /** The active policy, for display. */
  get policy(): SpendingPolicy {
    return this.#policy;
  }

  /**
   * Completed spends this session.
   *
   * ⚠️ In-memory only. A restart clears the velocity window and forgets which
   * destinations are known — so every recipient becomes "new" again. That is
   * fail-SAFE (more delays, not fewer), but it also means the velocity cap
   * resets, which is fail-open. Persisting this is a wallet-database feature
   * that does not exist yet.
   */
  get spendHistory(): readonly SpendRecord[] {
    return this.#spendHistory;
  }

  /** Transactions broadcast in this session that could still be replaced. */
  get replaceable(): Array<{ txid: string; feeRate: number; fee: bigint; amount: bigint }> {
    return [...this.#broadcast.values()].map((tx) => ({
      txid: tx.txid,
      feeRate: tx.feeRate,
      fee: tx.fee,
      amount: tx.amount,
    }));
  }

  /**
   * Replace a broadcast transaction with a higher-fee version (BIP-125).
   *
   * ─── What a fee bump actually is ────────────────────────────────────────
   * Not an edit. Bitcoin transactions are immutable once signed — a "bump" is
   * an entirely new transaction spending the SAME inputs, which makes the two
   * mutually exclusive: whichever confirms first invalidates the other. Miners
   * prefer the higher fee, so the replacement wins in practice.
   *
   * ─── Where the extra fee comes from ─────────────────────────────────────
   * The change output. The inputs are fixed, and the recipient must receive
   * exactly what they were promised — so the increase is taken from what
   * returns to us, which is the only party who should pay for our fee
   * misjudgement. If change cannot cover it, the bump is refused rather than
   * silently reducing the payment.
   *
   * ─── BIP-125 rules enforced here ────────────────────────────────────────
   *   Rule 1  The original signalled replaceability. Every Veyra transaction
   *           uses sequence 0xfffffffd, so this always holds.
   *   Rule 2  No new unconfirmed inputs. We add no inputs at all.
   *   Rule 3  Absolute fee must exceed the original's.
   *   Rule 4  The INCREASE must additionally cover the replacement's own
   *           bandwidth, or a node would relay a second copy for free and an
   *           attacker could flood the network with one-satoshi bumps.
   *
   * A replacement violating any of these is rejected by the network with a
   * confusing message, so they are checked here where the error can be clear.
   */
  bumpFee(txid: string, newFeeRate: number): PreparedTransaction {
    const original = this.#broadcast.get(txid);
    if (!original) {
      throw new WalletError(
        `no broadcast transaction ${txid} is available to replace. Fee bumping ` +
          `only works for transactions sent in this session — the record is ` +
          `not persisted across restarts.`,
      );
    }
    if (!Number.isFinite(newFeeRate) || newFeeRate <= original.feeRate) {
      throw new WalletError(
        `new fee rate must exceed the original ${original.feeRate.toFixed(2)} sat/vB`,
      );
    }

    const inputTotal = original.inputs.reduce((sum, utxo) => sum + utxo.value, 0n);
    const outputs = [...original.transaction.outputs];

    // Output 0 is the recipient and is never touched. A bump that reduced the
    // payment would be a different transaction pretending to be the same one.
    const recipientOutput = outputs[0];
    if (!recipientOutput || recipientOutput.value !== original.amount) {
      throw new WalletError("internal error: cannot identify the recipient output");
    }

    const vsize = original.vsize;
    const targetFee = BigInt(Math.ceil(vsize * newFeeRate));

    // Rule 4: the increase must cover the replacement's own bandwidth.
    const minimumFee =
      original.fee + BigInt(Math.ceil(vsize * INCREMENTAL_RELAY_FEE_RATE));
    const newFee = targetFee > minimumFee ? targetFee : minimumFee;

    const newChange = inputTotal - original.amount - newFee;
    if (newChange < 0n) {
      throw new WalletError(
        `cannot raise the fee to ${newFee} sat: the inputs only cover ` +
          `${inputTotal - original.amount} sat above the payment. Reducing the ` +
          `payment is not done automatically.`,
      );
    }

    const newOutputs: TxOutput[] = [recipientOutput];
    let changeAddress: string | null = null;

    if (newChange >= DUST_THRESHOLD_P2WPKH) {
      const originalChange = outputs[1];
      if (!originalChange) {
        throw new WalletError("internal error: expected a change output to reduce");
      }
      // Reuse the ORIGINAL change script. The two transactions are mutually
      // exclusive so only one can confirm, and a fresh address would burn a
      // gap-limit slot for an output that may never exist.
      newOutputs.push(new TxOutput(newChange, originalChange.scriptPubKey));
      changeAddress = original.changeAddress;
    }
    // Below dust the change output disappears and the remainder becomes fee —
    // the only valid option, since a dust output would not relay.

    const unsigned = new Transaction(
      original.transaction.version,
      original.inputs.map(
        (utxo) =>
          new TxInput({ txid: utxo.txid, vout: utxo.vout }, new Uint8Array(0), SEQUENCE_RBF),
      ),
      newOutputs,
      original.transaction.locktime,
    );

    const signed = signTransaction(
      unsigned,
      original.inputs.map((utxo) => ({
        value: utxo.value,
        privateKey: this.signingNode(utxo.derivationPath).privateKey,
      })),
    );

    const inputValues = original.inputs.map((utxo) => utxo.value);
    if (!verifyTransaction(signed, inputValues)) {
      throw new WalletError("internal error: the replacement failed verification");
    }

    const actualFee = calculateFee(signed, inputValues);

    // Rule 3, re-checked against what was built rather than what was planned.
    if (actualFee <= original.fee) {
      throw new WalletError(
        `internal error: replacement fee ${actualFee} does not exceed the original ${original.fee}`,
      );
    }

    return {
      transaction: signed,
      txid: signed.txid(),
      hex: signed.toHex(),
      amount: original.amount,
      fee: actualFee,
      total: original.amount + actualFee,
      change: newChange >= DUST_THRESHOLD_P2WPKH ? newChange : 0n,
      changeAddress,
      recipient: original.recipient,
      remainingBalance: original.remainingBalance + original.fee - actualFee,
      vsize: signed.vsize(),
      feeRate: Number(actualFee) / signed.vsize(),
      inputs: original.inputs,
      strategy: original.strategy,
      replaces: original.txid,
    };
  }

  /**
   * Transaction history across every address this wallet controls.
   *
   * ─── Folding across addresses ───────────────────────────────────────────
   * One transaction commonly touches several of our addresses at once — a
   * spend consumes inputs from one and returns change to another. Reporting
   * those as separate entries would show a single payment twice with
   * misleading amounts, so entries are folded by txid and their net values
   * SUMMED.
   *
   * That sum is what makes the direction meaningful. A send of 0.1 with 0.9
   * change looks like "−1.0" on the input address and "+0.9" on the change
   * address; only the sum, −0.1 plus fee, describes what actually happened to
   * the wallet.
   */
  async history(source: ChainSource, options: { limit?: number } = {}): Promise<ChainTransaction[]> {
    if (!source.getTransactions) {
      throw new WalletError(
        `${source.name} does not provide transaction history. For a Bitcoin Core ` +
          `node, call importAddressesForHistory() first.`,
      );
    }

    const folded = new Map<string, ChainTransaction>();

    for (const address of this.knownAddresses()) {
      let entries: ChainTransaction[];
      try {
        entries = await source.getTransactions(address);
      } catch (error) {
        // One address failing must not lose the whole history — but a
        // configuration error (no watch wallet) should surface, not be
        // silently swallowed into an empty list.
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
          // Prefer a known fee over an absent one; they agree when both exist.
          ...(existing.fee ?? entry.fee ? { fee: existing.fee ?? entry.fee } : {}),
        });
      }
    }

    return [...folded.values()]
      .sort((a, b) => {
        // Unconfirmed first, then newest confirmed. A user looking at history
        // cares most about what has not settled yet.
        if (a.confirmations !== b.confirmations) return a.confirmations - b.confirmations;
        return (b.blockTime ?? 0) - (a.blockTime ?? 0);
      })
      .slice(0, options.limit ?? 100);
  }

  /**
   * Live fee estimates, with an honest fallback.
   *
   * If the source cannot estimate — no chain source configured, or a regtest
   * node with no fee market to estimate from — this returns the static
   * presets with `source: "static defaults"`. The caller can therefore always
   * render something, and can always tell whether the number reflects the
   * network or is a guess.
   *
   * Fabricating an estimate and presenting it as live would be worse than
   * either: the user would set a fee believing it was informed.
   */
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
      // A source that answered but produced no usable target is no better
      // than none. Regtest does this, correctly.
      if (live.high === undefined && live.medium === undefined && live.low === undefined) {
        return {
          ...fallback,
          source: `${live.source} has no estimates yet — using static defaults`,
        };
      }
      // Fill any missing target from the fallback rather than omitting it, so
      // a UI never has to render a blank fee option.
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
    /** Current time for policy evaluation. Supplied by tests; defaults to now. */
    now?: number;
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
        privateKey: this.signingNode(utxo.derivationPath).privateKey,
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

    // ── Policy, evaluated LAST ────────────────────────────────────────────
    // After signing, because the real fee is only known once the transaction
    // exists — and a cap that ignored the fee could be evaded with a large
    // one. Nothing has been broadcast, so a denial here costs nothing.
    const decision = this.#policy.evaluate(
      { amount, fee: actualFee, recipient: to },
      options.now ?? Date.now(),
      this.#spendHistory,
    );
    if (decision.outcome === "deny") {
      throw new WalletError(`Blocked by spending policy: ${decision.reason}`);
    }

    const balanceBefore = this.balance(minConfirmations).spendable;

    return {
      policy: decision,
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
