/**
 * WALLET INTEGRATION TESTS
 *
 * End-to-end: mnemonic → addresses → UTXOs → signed transaction → verified.
 *
 * The §16 requirements are asserted here rather than left to a UI, because a
 * UI-only check is bypassed by anything calling the core or API directly.
 */
import { describe, it, expect } from "vitest";
import { Wallet, WalletError, GAP_LIMIT } from "../../core/wallet/wallet.js";
import { TESTNET, MAINNET, REGTEST } from "../../core/bitcoin/networks.js";
import { verifyTransaction } from "../../core/signing/signer.js";
import { validateMnemonic } from "../../core/mnemonic/index.js";
import { Transaction } from "../../core/transactions/transaction.js";
import { DUST_THRESHOLD_P2WPKH, type Utxo } from "../../core/utxo/utxo.js";

/** The standard BIP-39 test phrase. */
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/**
 * A recipient address, derived ONCE.
 *
 * Deriving it per call would run PBKDF2 (2048 rounds) each time. In the
 * property test below that turned a 100-iteration loop into ~7 seconds of
 * key stretching that tested nothing — the cost is real work, but not work
 * this test is about.
 */
const RECIPIENT = Wallet.restore(TEST_MNEMONIC, TESTNET, "other").currentReceiveAddress().address;

function fundedWallet(amounts: bigint[] = [100_000n]): { wallet: Wallet; utxos: Utxo[] } {
  const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
  const addresses = wallet.receiveAddresses(GAP_LIMIT);
  const utxos: Utxo[] = amounts.map((value, i) => ({
    txid: (i + 1).toString(16).padStart(2, "0").repeat(32).slice(0, 64),
    vout: 0,
    value,
    derivationPath: addresses[i]!.path,
    address: addresses[i]!.address,
    confirmations: 6,
  }));
  wallet.setUtxos(utxos);
  return { wallet, utxos };
}

describe("wallet creation and restore", () => {
  it("creates a wallet with a valid mnemonic", () => {
    const { wallet, mnemonic } = Wallet.create(TESTNET);
    expect(validateMnemonic(mnemonic)).toBe(true);
    expect(mnemonic.split(" ").length).toBe(24);
    expect(wallet.path).toBe("m/84'/1'/0'");
  });

  it("restoring the same mnemonic gives identical addresses", () => {
    const a = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const b = Wallet.restore(TEST_MNEMONIC, TESTNET);
    expect(a.currentReceiveAddress().address).toBe(b.currentReceiveAddress().address);
    expect(a.fingerprint).toBe(b.fingerprint);
  });

  it("REJECTS a mnemonic with a bad checksum rather than deriving an empty wallet", () => {
    // BIP-39 defines a seed for any string. A wallet that skips validation
    // derives happily from a typo and shows zero balance, leaving the user to
    // conclude their funds are gone.
    expect(() => Wallet.restore("abandon ".repeat(11) + "abandon", TESTNET))
      .toThrow(/checksum failed/);
    expect(() => Wallet.restore("not a real mnemonic at all", TESTNET)).toThrow();
  });

  it("a passphrase produces a completely different wallet", () => {
    const plain = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const withPass = Wallet.restore(TEST_MNEMONIC, TESTNET, "secret");
    expect(plain.currentReceiveAddress().address)
      .not.toBe(withPass.currentReceiveAddress().address);
  });

  it("different networks give different addresses and prefixes", () => {
    expect(Wallet.restore(TEST_MNEMONIC, MAINNET).currentReceiveAddress().address.startsWith("bc1q")).toBe(true);
    expect(Wallet.restore(TEST_MNEMONIC, TESTNET).currentReceiveAddress().address.startsWith("tb1q")).toBe(true);
    expect(Wallet.restore(TEST_MNEMONIC, REGTEST).currentReceiveAddress().address.startsWith("bcrt1q")).toBe(true);
  });

  it("there is NO method to retrieve the mnemonic after creation", () => {
    const { wallet } = Wallet.create(TESTNET);
    expect((wallet as unknown as Record<string, unknown>).getMnemonic).toBeUndefined();
    expect((wallet as unknown as Record<string, unknown>).exportPrivateKey).toBeUndefined();
    expect((wallet as unknown as Record<string, unknown>).seed).toBeUndefined();
  });

  it("the wallet does not leak key material when serialised", async () => {
    const { inspect } = await import("node:util");
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const master = "abandon";
    expect(String(wallet)).not.toContain(master);
    expect(JSON.stringify(wallet)).not.toContain(master);
    expect(inspect(wallet, { depth: null, showHidden: true })).not.toContain("xprv");
    expect(String(wallet)).toContain(wallet.fingerprint); // public id is fine
  });
});

describe("address management", () => {
  it("the current receive address is stable until advanced", () => {
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const first = wallet.currentReceiveAddress().address;
    expect(wallet.currentReceiveAddress().address).toBe(first);
    expect(wallet.nextReceiveAddress().address).not.toBe(first);
  });

  it("ENFORCES the gap limit", () => {
    // Funds sent beyond the gap limit are not lost, but a restore scan stops
    // at 20 consecutive unused addresses and will not find them.
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    for (let i = 0; i < GAP_LIMIT; i++) wallet.nextReceiveAddress();
    expect(() => wallet.nextReceiveAddress()).toThrow(/gap limit/);
  });

  it("all derived addresses are valid on their network", () => {
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    for (const address of wallet.receiveAddresses(20)) {
      expect(address.address.startsWith("tb1q")).toBe(true);
    }
  });
});

describe("UTXO loading", () => {
  it("REJECTS UTXOs for addresses this wallet does not control", () => {
    // An attacker-supplied UTXO would produce a transaction we cannot sign,
    // and could be used to manipulate fee arithmetic.
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    expect(() => wallet.setUtxos([{
      txid: "ab".repeat(32), vout: 0, value: 100_000n,
      derivationPath: "m/84'/1'/0'/0/0",
      address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // not ours
      confirmations: 6,
    }])).toThrow(/does not control/);
  });

  it("reports a broken-down balance", () => {
    const { wallet } = fundedWallet([100_000n, 50_000n]);
    expect(wallet.balance().spendable).toBe(150_000n);
    expect(wallet.balance().utxoCount).toBe(2);
  });
});

describe("sending: the happy path", () => {
  it("builds, signs, and self-verifies a payment", () => {
    const { wallet } = fundedWallet([100_000n]);
    const prepared = wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: 10 });

    expect(prepared.amount).toBe(50_000n);
    expect(prepared.recipient).toBe(RECIPIENT);
    expect(verifyTransaction(prepared.transaction, prepared.inputs.map((u) => u.value))).toBe(true);
    expect(prepared.transaction.txid()).toBe(prepared.txid);
  });

  it("§16: reports Amount, Fee, Total, and Remaining Balance", () => {
    const { wallet } = fundedWallet([100_000n]);
    const p = wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: 10 });

    expect(p.total).toBe(p.amount + p.fee);
    expect(p.remainingBalance).toBe(100_000n - p.amount - p.fee);
    expect(p.fee).toBeGreaterThan(0n);
    expect(p.vsize).toBeGreaterThan(0);
  });

  it("sends change to a FRESH address each time", () => {
    const { wallet } = fundedWallet([100_000n, 100_000n, 100_000n]);
    const seen = new Set<string>();
    for (let i = 0; i < 3; i++) {
      const p = wallet.send({ to: RECIPIENT, amount: 20_000n, feeRate: 5 });
      if (p.changeAddress) seen.add(p.changeAddress);
    }
    // Change-address reuse is a privacy failure: it is one of the two pillars
    // of blockchain analysis.
    expect(seen.size).toBe(3);
  });

  it("the resulting transaction parses and re-verifies from raw hex", () => {
    const { wallet } = fundedWallet([100_000n]);
    const p = wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: 10 });

    const reparsed = Transaction.fromHex(p.hex);
    expect(reparsed.txid()).toBe(p.txid);
    expect(verifyTransaction(reparsed, p.inputs.map((u) => u.value))).toBe(true);
  });

  it("the actual fee rate is close to the requested rate", () => {
    const { wallet } = fundedWallet([500_000n]);
    for (const rate of [1, 5, 10, 25, 50]) {
      const p = wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: rate });
      expect(p.feeRate).toBeGreaterThan(rate * 0.75);
      expect(p.feeRate).toBeLessThan(rate * 1.25);
    }
  });

  it("spends multiple inputs when needed", () => {
    const { wallet } = fundedWallet([30_000n, 30_000n, 30_000n, 30_000n]);
    const p = wallet.send({ to: RECIPIENT, amount: 80_000n, feeRate: 5 });
    expect(p.inputs.length).toBeGreaterThanOrEqual(3);
    expect(verifyTransaction(p.transaction, p.inputs.map((u) => u.value))).toBe(true);
  });
});

describe("§16: spending guards", () => {
  const recipient = () => RECIPIENT;

  it("REFUSES to spend more than the balance", () => {
    const { wallet } = fundedWallet([100_000n]);
    expect(() => wallet.send({ to: recipient(), amount: 200_000n, feeRate: 10 }))
      .toThrow(/insufficient funds/);
  });

  it("REFUSES when amount + fee exceeds the balance, even though amount alone does not", () => {
    // The exact §16 rule. 100,000 available, 100,000 requested: the amount
    // fits but leaves nothing for the fee.
    const { wallet } = fundedWallet([100_000n]);
    expect(() => wallet.send({ to: recipient(), amount: 100_000n, feeRate: 10 }))
      .toThrow(/insufficient funds/);
  });

  it("refuses a dust amount", () => {
    const { wallet } = fundedWallet([100_000n]);
    expect(() => wallet.send({ to: recipient(), amount: 100n, feeRate: 10 }))
      .toThrow(/dust threshold/);
    expect(() => wallet.send({ to: recipient(), amount: DUST_THRESHOLD_P2WPKH - 1n, feeRate: 10 }))
      .toThrow(/dust/);
  });

  it("refuses a zero or negative amount", () => {
    const { wallet } = fundedWallet([100_000n]);
    expect(() => wallet.send({ to: recipient(), amount: 0n, feeRate: 10 })).toThrow();
    expect(() => wallet.send({ to: recipient(), amount: -1000n, feeRate: 10 })).toThrow();
  });

  it("REFUSES a mainnet address on a testnet wallet", () => {
    const { wallet } = fundedWallet([100_000n]);
    expect(() => wallet.send({
      to: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", amount: 50_000n, feeRate: 10,
    })).toThrow(/invalid testnet address/);
  });

  it("refuses malformed and near-miss addresses", () => {
    const { wallet } = fundedWallet([100_000n]);
    const valid = recipient();
    expect(() => wallet.send({ to: "not-an-address", amount: 50_000n, feeRate: 10 })).toThrow();
    expect(() => wallet.send({ to: "", amount: 50_000n, feeRate: 10 })).toThrow();
    // Single character altered — the Bech32 checksum catches it.
    const corrupted = valid.slice(0, -1) + (valid.endsWith("q") ? "p" : "q");
    expect(() => wallet.send({ to: corrupted, amount: 50_000n, feeRate: 10 })).toThrow();
  });

  it("refuses a fee rate below the relay minimum", () => {
    const { wallet } = fundedWallet([100_000n]);
    expect(() => wallet.send({ to: recipient(), amount: 50_000n, feeRate: 0.5 })).toThrow();
  });

  it("refuses to spend frozen or unconfirmed coins", () => {
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const addresses = wallet.receiveAddresses(5);
    wallet.setUtxos([
      { txid: "01".repeat(32), vout: 0, value: 100_000n, derivationPath: addresses[0]!.path, address: addresses[0]!.address, confirmations: 6, frozen: true },
      { txid: "02".repeat(32), vout: 0, value: 100_000n, derivationPath: addresses[1]!.path, address: addresses[1]!.address, confirmations: 0 },
    ]);
    expect(() => wallet.send({ to: recipient(), amount: 50_000n, feeRate: 10 }))
      .toThrow(/no spendable UTXOs/);
  });
});

describe("state management", () => {
  it("send() does NOT mutate wallet state — the user may still decline", () => {
    const { wallet } = fundedWallet([100_000n]);
    const before = wallet.balance().spendable;
    wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: 10 });
    expect(wallet.balance().spendable).toBe(before);
  });

  it("markSpent() consumes the inputs after a broadcast", () => {
    const { wallet } = fundedWallet([100_000n, 100_000n]);
    const p = wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: 10 });
    wallet.markSpent(p);
    expect(wallet.balance().utxoCount).toBe(2 - p.inputs.length);
  });

  it("the same coin cannot be spent twice after markSpent", () => {
    const { wallet } = fundedWallet([100_000n]);
    const p = wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: 10 });
    wallet.markSpent(p);
    expect(() => wallet.send({ to: RECIPIENT, amount: 50_000n, feeRate: 10 }))
      .toThrow(/no spendable UTXOs|insufficient funds/);
  });
});

describe("value conservation across a spend", () => {
  it("outputs plus fee always equal inputs, over many random sends", () => {
    // The wallet is restored once and its UTXO set replaced per iteration,
    // so the loop measures spending logic rather than PBKDF2.
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const addresses = wallet.receiveAddresses(GAP_LIMIT);

    for (let i = 0; i < 200; i++) {
      const amounts = Array.from({ length: 1 + Math.floor(Math.random() * 4) }, () =>
        BigInt(50_000 + Math.floor(Math.random() * 200_000)),
      );
      wallet.setUtxos(amounts.map((value, n) => ({
        txid: (i * 10 + n + 1).toString(16).padStart(8, "0").repeat(8).slice(0, 64),
        vout: 0, value,
        derivationPath: addresses[n]!.path,
        address: addresses[n]!.address,
        confirmations: 6,
      })));
      const target = BigInt(1000 + Math.floor(Math.random() * 40_000));
      try {
        const p = wallet.send({ to: RECIPIENT, amount: target, feeRate: 1 + Math.floor(Math.random() * 20) });
        const inputTotal = p.inputs.reduce((sum, u) => sum + u.value, 0n);
        // Nothing created, nothing destroyed.
        expect(p.transaction.totalOutputValue() + p.fee).toBe(inputTotal);
        expect(p.amount + p.change + p.fee).toBe(inputTotal);
      } catch (error) {
        expect(error).toBeInstanceOf(WalletError);
      }
    }
  });
});
