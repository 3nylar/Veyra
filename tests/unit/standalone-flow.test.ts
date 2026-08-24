/**
 * THE AIR-GAPPED ROUND TRIP
 *
 * Exercises exactly the paths the two standalone pages use:
 *
 *   veyra-watch.html   xpub → sync → build PSBT
 *        ↓ base64 across the air gap
 *   veyra-sign.html    derive → sign → finalise
 *        ↓ hex back
 *   veyra-watch.html   broadcast
 *
 * Neither page is testable directly here, but every function they call is —
 * and the failure this guards against is the flow breaking at a seam, which
 * unit tests of each half would not catch.
 */
import { describe, it, expect } from "vitest";
import { WatchOnlyWallet } from "../../core/wallet/watchOnly.js";
import { Wallet } from "../../core/wallet/wallet.js";
import { MemoryChainSource } from "../../core/chain/memory.js";
import { ExtendedKey } from "../../core/derivation/bip32.js";
import { mnemonicToSeed } from "../../core/mnemonic/index.js";
import { Psbt } from "../../core/psbt/psbt.js";
import { sighash, SighashCache, SIGHASH_ALL } from "../../core/signing/sighash.js";
import { signDigestWithSighashType, verifyWitnessSignature } from "../../core/signing/ecdsa.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { verifyTransaction } from "../../core/signing/signer.js";
import { TESTNET } from "../../core/bitcoin/networks.js";
import { bytesToHex } from "../../core/crypto/bytes.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const master = ExtendedKey.fromSeed(mnemonicToSeed(MNEMONIC));
const XPUB = master.derivePath("m/84'/1'/0'").toExtendedPublicKey("testnet");

async function watchWithFunds(amount = 3_000_000n) {
  const watch = WatchOnlyWallet.fromExtendedPublicKey(XPUB, TESTNET);
  const chain = new MemoryChainSource("testnet", 800);
  chain.fund(watch.account.receiveAddress(0).address, "aa".repeat(32), 0, amount, 6);
  await watch.sync(chain);
  return { watch, chain };
}

const recipient = () => Wallet.restore(MNEMONIC, TESTNET, "r").currentReceiveAddress().address;

/** What the signer page does, isolated from the DOM. */
function signPsbt(psbt: Psbt, seed: ExtendedKey): Psbt {
  const cache = new SighashCache(psbt.transaction);
  for (let index = 0; index < psbt.inputCount; index++) {
    const utxo = psbt.getWitnessUtxo(index);
    const [derivation] = psbt.getBip32Derivations(index);
    if (!utxo || !derivation) throw new Error(`input ${index} lacks signing data`);

    const node = seed.derivePath(derivation.path);
    const publicKey = PublicKey.fromPrivateKey(node.privateKey);
    if (bytesToHex(publicKey.toBytes()) !== bytesToHex(derivation.publicKey)) {
      throw new Error(`input ${index} expects a different key`);
    }
    const digest = sighash(
      psbt.transaction, index,
      { value: utxo.value, publicKeyHash: publicKey.hash160() },
      SIGHASH_ALL, cache,
    );
    const signature = signDigestWithSighashType(digest, node.privateKey, SIGHASH_ALL);
    if (!verifyWitnessSignature(digest, signature, publicKey)) {
      throw new Error("self-verification failed");
    }
    psbt.addPartialSignature(index, publicKey.toBytes(), signature);
  }
  return psbt;
}

describe("watch → sign → broadcast", () => {
  it("completes the full round trip", async () => {
    const { watch, chain } = await watchWithFunds();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });

    // Across the air gap as base64, exactly as a user would copy it.
    const signed = signPsbt(Psbt.fromBase64(payment.psbt), master).finalize().extract();

    expect(verifyTransaction(signed, payment.inputs.map((u) => u.value))).toBe(true);
    expect(await watch.broadcastSigned(chain, signed.toHex())).toBe(signed.txid());
  });

  it("the txid is known BEFORE signing — SegWit makes it stable", async () => {
    // So the watch page can show a final txid on a transaction it cannot sign.
    const { watch } = await watchWithFunds();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });
    const signed = signPsbt(Psbt.fromBase64(payment.psbt), master).finalize().extract();
    expect(signed.txid()).toBe(payment.txid);
  });

  it("the signer verifies the AMOUNT without trusting the watch page", async () => {
    // BIP-143 puts the input value in the preimage, so a watch page lying
    // about it produces a signature that does not verify. This is the property
    // that makes an untrusted builder acceptable.
    const { watch } = await watchWithFunds();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });

    const lying = Psbt.fromBase64(payment.psbt);
    const real = payment.inputs[0]!.value;
    // Rebuild the PSBT claiming a different input value.
    const tampered = Psbt.create(lying.transaction)
      .setWitnessUtxo(0, real + 500_000n, lying.getWitnessUtxo(0)!.scriptPubKey)
      .setBip32Derivation(0, lying.getBip32Derivations(0)[0]!);

    const signed = signPsbt(tampered, master).finalize().extract();
    // Verified against the TRUE value, the signature fails.
    expect(verifyTransaction(signed, [real])).toBe(false);
  });

  it("the signer REFUSES a PSBT for a key it does not hold", async () => {
    const { watch } = await watchWithFunds();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });
    const otherSeed = ExtendedKey.fromSeed(
      mnemonicToSeed("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
    );
    expect(() => signPsbt(Psbt.fromBase64(payment.psbt), otherSeed))
      .toThrow(/expects a different key/);
  });

  it("the watch page REFUSES to broadcast someone else's transaction", async () => {
    // Without this it would relay arbitrary bytes for anyone who could reach it.
    const { watch, chain } = await watchWithFunds();
    const foreign = Wallet.restore(MNEMONIC, TESTNET, "foreign");
    const foreignChain = new MemoryChainSource("testnet", 800);
    foreignChain.fund(foreign.receiveAddresses(1)[0]!.address, "bb".repeat(32), 0, 2_000_000n, 6);
    await foreign.sync(foreignChain);
    const theirs = foreign.send({ to: recipient(), amount: 500_000n, feeRate: 5 });

    await expect(watch.broadcastSigned(chain, theirs.hex))
      .rejects.toThrow(/not a UTXO this wallet watches/);
  });

  it("a PSBT survives a base64 round trip unchanged", async () => {
    // The air gap is a copy-paste, so this is the transfer medium itself.
    const { watch } = await watchWithFunds();
    const payment = watch.buildPayment({ to: recipient(), amount: 1_000_000n, feeRate: 5 });
    expect(Psbt.fromBase64(payment.psbt).toBase64()).toBe(payment.psbt);
  });

  it("works with several inputs", async () => {
    const watch = WatchOnlyWallet.fromExtendedPublicKey(XPUB, TESTNET);
    const chain = new MemoryChainSource("testnet", 800);
    for (let i = 0; i < 3; i++) {
      chain.fund(
        watch.account.receiveAddress(i).address,
        (i + 20).toString(16).repeat(32).slice(0, 64), 0, 800_000n, 6,
      );
    }
    await watch.sync(chain);

    const payment = watch.buildPayment({ to: recipient(), amount: 2_000_000n, feeRate: 4 });
    expect(payment.inputs.length).toBeGreaterThan(1);

    const signed = signPsbt(Psbt.fromBase64(payment.psbt), master).finalize().extract();
    expect(verifyTransaction(signed, payment.inputs.map((u) => u.value))).toBe(true);
    expect(await watch.broadcastSigned(chain, signed.toHex())).toBe(signed.txid());
  });
});
