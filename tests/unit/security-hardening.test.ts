/**
 * WATCH-ONLY WALLETS AND THE ENCRYPTED KEYSTORE
 *
 * Two independent controls:
 *
 *   · Watch-only makes a HOSTED service safe by removing the private key
 *     entirely — not by policy, but structurally.
 *   · The keystore makes a LOCAL wallet safe at rest.
 *
 * Neither addresses an attacker who can read process memory while the wallet
 * is unlocked, and the tests say so where relevant rather than implying more.
 */
import { describe, it, expect } from "vitest";
import { WatchOnlyWallet } from "../../core/wallet/watchOnly.js";
import { Wallet } from "../../core/wallet/wallet.js";
import {
  encryptMnemonic, decryptMnemonic, UnlockedKeystore, KeystoreError,
  SCRYPT_PARAMS, MIN_PASSPHRASE_LENGTH,
} from "../../core/wallet/keystore.js";
import { ExtendedKey } from "../../core/derivation/bip32.js";
import { mnemonicToSeed } from "../../core/mnemonic/index.js";
import { MemoryChainSource } from "../../core/chain/memory.js";
import { Psbt } from "../../core/psbt/psbt.js";
import { REGTEST, MAINNET } from "../../core/bitcoin/networks.js";
import { bytesToBase64, base64ToBytes } from "../../core/crypto/bytes.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const master = ExtendedKey.fromSeed(mnemonicToSeed(MNEMONIC));
const accountKey = master.derivePath("m/84'/1'/0'");
const XPUB = accountKey.toExtendedPublicKey("testnet");

const txid = (n: number) => n.toString(16).padStart(8, "0").repeat(8).slice(0, 64);

describe("watch-only: the private key is structurally absent", () => {
  it("builds from an account xpub", async () => {
    const watch = WatchOnlyWallet.fromExtendedPublicKey(XPUB, REGTEST);
    expect(watch.canSign).toBe(false);
    expect(watch.path).toBe("m/84'/1'/0'");
  });

  it("derives the SAME addresses as the full wallet", async () => {
    // The property that makes it useful: a hosted server can show you your
    // money without being able to take it.
    const full = Wallet.restore(MNEMONIC, REGTEST);
    const watch = WatchOnlyWallet.fromExtendedPublicKey(XPUB, REGTEST);
    for (let i = 0; i < 10; i++) {
      expect(watch.account.receiveAddress(i).address)
        .toBe(full.account.receiveAddress(i).address);
    }
  });

  it("REFUSES an xprv — that would give the process spending authority", async () => {
    const xprv = accountKey.toExtendedPrivateKeyUnsafe("testnet");
    expect(() => WatchOnlyWallet.fromExtendedPublicKey(xprv, REGTEST))
      .toThrow(/extended PUBLIC key/);
  });

  it("REFUSES a key from the wrong depth", async () => {
    // A key from the wrong level derives addresses nobody else finds, which
    // is indistinguishable from lost funds.
    const wrongDepth = master.derivePath("m/84'/1'").toExtendedPublicKey("testnet");
    expect(() => WatchOnlyWallet.fromExtendedPublicKey(wrongDepth, REGTEST))
      .toThrow(/depth 3/);
  });

  it("has NO method that could produce a signature", async () => {
    const watch = WatchOnlyWallet.fromExtendedPublicKey(XPUB, REGTEST);
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(watch));
    for (const method of methods) {
      expect(method.toLowerCase()).not.toMatch(/^sign|privatekey|seed|mnemonic/);
    }
  });

  it("does not leak the xpub's private counterpart anywhere", async () => {
    const { inspect } = await import("node:util");
    const watch = WatchOnlyWallet.fromExtendedPublicKey(XPUB, REGTEST);
    const secret = master.derivePath("m/84'/1'/0'/0/0").privateKey.toHexUnsafe();
    expect(inspect(watch, { depth: null, showHidden: true })).not.toContain(secret);
    expect(JSON.stringify(watch)).not.toContain(secret);
  });
});

describe("watch-only: building unsigned payments", () => {
  async function funded() {
    const watch = WatchOnlyWallet.fromExtendedPublicKey(XPUB, REGTEST);
    const chain = new MemoryChainSource("regtest", 500);
    const addresses = watch.receiveAddresses(3);
    chain.fund(addresses[0]!.address, txid(1), 0, 5_000_000n, 6);
    await watch.sync(chain);
    return { watch, chain };
  }

  const recipient = () =>
    Wallet.restore(MNEMONIC, REGTEST, "r").currentReceiveAddress().address;

  it("syncs and reports a balance", async () => {
    const { watch } = await funded();
    expect(watch.balance().spendable).toBe(5_000_000n);
  });

  it("produces a PSBT a signer can open", async () => {
    const { watch } = await funded();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });

    const psbt = Psbt.fromBase64(payment.psbt);
    expect(psbt.inputCount).toBe(payment.inputs.length);
    expect(psbt.transaction.txid()).toBe(payment.txid);
  });

  it("the PSBT carries witness_utxo, so the signer need not TRUST the server", async () => {
    // BIP-143 puts the input value in the signature preimage. A server lying
    // about it produces a signature that does not verify — the signer is not
    // trusting the host on the number that matters most.
    return funded().then(({ watch }) => {
      const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });
      const psbt = Psbt.fromBase64(payment.psbt);
      const utxo = psbt.getWitnessUtxo(0);
      expect(utxo?.value).toBe(payment.inputs[0]!.value);
    });
  });

  it("the PSBT carries a derivation path, so the signer knows which key", async () => {
    const { watch } = await funded();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });
    const [derivation] = Psbt.fromBase64(payment.psbt).getBip32Derivations(0);
    expect(derivation!.path).toBe(payment.inputPaths[0]);
    expect(derivation!.masterFingerprint.length).toBe(4);
  });

  it("§16: reports amount, fee, total and remaining balance", async () => {
    const { watch } = await funded();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });
    expect(payment.total).toBe(payment.amount + payment.fee);
    expect(payment.remainingBalance).toBe(5_000_000n - payment.total);
  });

  it("enforces every spending guard on the server", async () => {
    const { watch } = await funded();
    expect(() => watch.buildPayment({ to: recipient(), amount: 99_000_000n, feeRate: 5 }))
      .toThrow(/insufficient/i);
    expect(() => watch.buildPayment({ to: recipient(), amount: 100n, feeRate: 5 }))
      .toThrow(/dust/);
    expect(() => watch.buildPayment({
      to: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", amount: 1_000_000n, feeRate: 5,
    })).toThrow(/invalid regtest address/);
  });

  it("REFUSES to broadcast a transaction spending coins it does not watch", async () => {
    // Otherwise a hosted endpoint is an open relay for anyone with a token.
    const { watch, chain } = await funded();
    const foreign = Wallet.restore(MNEMONIC, REGTEST, "other");
    const foreignChain = new MemoryChainSource("regtest", 500);
    foreignChain.fund(foreign.receiveAddresses(1)[0]!.address, txid(9), 0, 2_000_000n, 6);
    await foreign.sync(foreignChain);
    const theirs = foreign.send({ to: recipient(), amount: 500_000n, feeRate: 5 });

    await expect(watch.broadcastSigned(chain, theirs.hex))
      .rejects.toThrow(/not a UTXO this wallet watches/);
  });

  it("refuses an unsigned transaction", async () => {
    const { watch, chain } = await funded();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });
    const unsigned = Psbt.fromBase64(payment.psbt).transaction;
    await expect(watch.broadcastSigned(chain, unsigned.toHex()))
      .rejects.toThrow(/not signed/);
  });
});

describe("keystore: encryption at rest", () => {
  const PASSPHRASE = "correct horse battery staple";

  it("round-trips a mnemonic", async () => {
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    expect(await decryptMnemonic(store, PASSPHRASE)).toBe(MNEMONIC);
  });

  it("the ciphertext contains no trace of the plaintext", async () => {
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    const serialised = JSON.stringify(store);
    expect(serialised).not.toContain("abandon");
    expect(serialised).not.toContain("about");
  });

  it("uses a FRESH salt and IV every time", async () => {
    // A reused IV under the same key is catastrophic for GCM.
    const a = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    const b = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("uses memory-hard scrypt rather than PBKDF2", async () => {
    // A GPU can parallelise PBKDF2 cheaply. scrypt needs N·r·128 bytes per
    // guess, which is expensive to replicate thousands of times.
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    expect(store.kdf).toBe("scrypt");
    expect(store.kdfParams.N).toBe(SCRYPT_PARAMS.N);
    expect(store.kdfParams.N).toBeGreaterThanOrEqual(131_072);
  });

  it("REJECTS a wrong passphrase", async () => {
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    await expect(decryptMnemonic(store, "wrong passphrase")).rejects.toThrow(/could not decrypt/);
  });

  it("gives an IDENTICAL error for a wrong passphrase and a tampered file", async () => {
    // Distinguishing them would let an attacker with a modified file test
    // passphrases — one oracle becomes two.
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    const tampered = { ...store, ciphertext: bytesToBase64(new TextEncoder().encode("garbage")) };

    let wrongPass = "";
    let tamperedMsg = "";
    try { await decryptMnemonic(store, "wrong"); } catch (e) { wrongPass = (e as Error).message; }
    try { await decryptMnemonic(tampered, PASSPHRASE); } catch (e) { tamperedMsg = (e as Error).message; }
    expect(wrongPass).toBe(tamperedMsg);
  });

  it("DETECTS tampering — GCM is authenticated", async () => {
    // With CBC an attacker could flip bits and produce garbage plaintext. A
    // corrupted mnemonic that still parses derives the wrong addresses.
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    const bytes = base64ToBytes(store.ciphertext);
    bytes[0] = bytes[0]! ^ 0xff;
    await expect(decryptMnemonic(
      { ...store, ciphertext: bytesToBase64(bytes) }, PASSPHRASE,
    )).rejects.toThrow(/could not decrypt/);
  });

  it("DETECTS a weakened KDF header — the parameters are authenticated", async () => {
    // An attacker cannot edit the file to claim a cheap N and hand it back.
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    const weakened = { ...store, kdfParams: { ...store.kdfParams, N: 16384 } };
    await expect(decryptMnemonic(weakened, PASSPHRASE)).rejects.toThrow(/could not decrypt/);
  });

  it("BOUNDS scrypt parameters read from the file", async () => {
    // A hostile keystore claiming N=2^30 would exhaust memory on any machine
    // that opened it.
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE);
    await expect(decryptMnemonic({ ...store, kdfParams: { N: 2 ** 24, r: 8, p: 1 } }, PASSPHRASE))
      .rejects.toThrow(/outside the permitted range/);
    await expect(decryptMnemonic({ ...store, kdfParams: { N: 1024, r: 8, p: 1 } }, PASSPHRASE))
      .rejects.toThrow(/outside the permitted range/);
  });

  it("REFUSES to encrypt a mnemonic that fails its checksum", async () => {
    // Otherwise the file unlocks correctly and derives an empty wallet, which
    // the user discovers only when their funds appear missing.
    await expect(encryptMnemonic("abandon ".repeat(12).trim(), PASSPHRASE))
      .rejects.toThrow(/fails its checksum/);
  });

  it("requires a minimum passphrase length", async () => {
    await expect(encryptMnemonic(MNEMONIC, "short")).rejects.toThrow(/at least 8/);
    expect(MIN_PASSPHRASE_LENGTH).toBe(8);
  });

  it("normalises the passphrase, so keyboard differences do not lock you out", async () => {
    const store = await encryptMnemonic(MNEMONIC, "caf\u00e9 passphrase");
    expect(await decryptMnemonic(store, "cafe\u0301 passphrase")).toBe(MNEMONIC);
  });

  it("stores non-secret metadata for identifying a file without unlocking it", async () => {
    const store = await encryptMnemonic(MNEMONIC, PASSPHRASE, {
      network: "regtest", fingerprint: "854f45e9",
    });
    expect(store.network).toBe("regtest");
    expect(store.fingerprint).toBe("854f45e9");
  });
});

describe("keystore: auto-lock", () => {
  const PASSPHRASE = "correct horse battery staple";

  it("starts locked", async () => {
    const keystore = new UnlockedKeystore(await encryptMnemonic(MNEMONIC, PASSPHRASE));
    expect(keystore.isLocked).toBe(true);
    expect(() => keystore.readMnemonicUnsafe()).toThrow(/locked/);
  });

  it("unlocks with the right passphrase", async () => {
    const keystore = new UnlockedKeystore(await encryptMnemonic(MNEMONIC, PASSPHRASE));
    await keystore.unlock(PASSPHRASE);
    expect(keystore.isLocked).toBe(false);
    expect(keystore.readMnemonicUnsafe()).toBe(MNEMONIC);
  });

  it("locks on demand", async () => {
    const keystore = new UnlockedKeystore(await encryptMnemonic(MNEMONIC, PASSPHRASE));
    await keystore.unlock(PASSPHRASE);
    keystore.lock();
    expect(keystore.isLocked).toBe(true);
    expect(() => keystore.readMnemonicUnsafe()).toThrow(/locked/);
  });

  it("locks automatically after the interval", async () => {
    const keystore = new UnlockedKeystore(await encryptMnemonic(MNEMONIC, PASSPHRASE), 50);
    await keystore.unlock(PASSPHRASE);
    expect(keystore.isLocked).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 90));
    expect(keystore.isLocked).toBe(true);
  });

  it("reports time remaining", async () => {
    const keystore = new UnlockedKeystore(await encryptMnemonic(MNEMONIC, PASSPHRASE), 60_000);
    expect(keystore.lockingIn).toBeNull();
    await keystore.unlock(PASSPHRASE);
    expect(keystore.lockingIn).toBeGreaterThan(50_000);
  });

  it("never serialises the mnemonic", async () => {
    const { inspect } = await import("node:util");
    const keystore = new UnlockedKeystore(await encryptMnemonic(MNEMONIC, PASSPHRASE));
    await keystore.unlock(PASSPHRASE);
    expect(String(keystore)).not.toContain("abandon");
    expect(JSON.stringify(keystore)).not.toContain("abandon");
    expect(inspect(keystore, { depth: null, showHidden: true })).not.toContain("abandon");
  });
});
