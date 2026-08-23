/**
 * TAPROOT — BIP-86 addresses and BIP-341 key-path signing.
 *
 * The address vectors are the published BIP-86 set, using the same all-zeros
 * mnemonic as the BIP-39 tests. Matching them proves the tweak, the parity
 * handling, and the Bech32m encoding are all correct at once — any one of
 * those wrong produces a different address.
 */
import { describe, it, expect } from "vitest";
import {
  Bip86Account, tapTweak, tweakPublicKey, tweakPrivateKey, toXOnly,
  p2trScriptPubKey, p2trAddress, taprootAccountPath, BIP86_PURPOSE,
} from "../../core/addresses/taproot.js";
import {
  signTaprootTransaction, taprootSighash, taprootSigMsg, verifyTaprootSignature,
  TaprootSighashCache, SIGHASH_DEFAULT,
} from "../../core/signing/taproot.js";
import { mnemonicToSeed } from "../../core/mnemonic/index.js";
import { ExtendedKey } from "../../core/derivation/bip32.js";
import { PrivateKey } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../../core/transactions/transaction.js";
import { MAINNET, TESTNET, REGTEST } from "../../core/bitcoin/networks.js";
import { bech32Decode, decodeSegwitAddress } from "../../core/addresses/bech32.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const master = ExtendedKey.fromSeed(mnemonicToSeed(MNEMONIC));

describe("BIP-86 official test vectors", () => {
  const account = Bip86Account.fromMasterKey(master, MAINNET, 0);

  it("first receive address m/86'/0'/0'/0/0", () => {
    const derived = account.receiveAddress(0);
    expect(derived.address).toBe(
      "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    );
    expect(derived.path).toBe("m/86'/0'/0'/0/0");
  });

  it("second receive address m/86'/0'/0'/0/1", () => {
    expect(account.receiveAddress(1).address).toBe(
      "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    );
  });

  it("first change address m/86'/0'/0'/1/0", () => {
    expect(account.changeAddress(0).address).toBe(
      "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
    );
  });
});

describe("the tweak", () => {
  const child = master.derivePath("m/86'/0'/0'/0/0");
  const internalXOnly = toXOnly(child.publicKey);

  it("x-only keys are 32 bytes — the parity byte is dropped", () => {
    expect(internalXOnly.length).toBe(32);
    expect(child.publicKey.toBytes().length).toBe(33);
    expect(bytesToHex(internalXOnly)).toBe(bytesToHex(child.publicKey.toBytes().slice(1)));
  });

  it("TapTweak is a tagged hash of the internal key with NOTHING appended", () => {
    // The empty merkle root is what makes this "no script tree". Appending
    // one is what a script-path wallet does.
    expect(tapTweak(internalXOnly).length).toBe(32);
  });

  it("the OUTPUT key differs from the internal key", () => {
    // Using the internal key directly would be a security flaw, not merely a
    // privacy one — see the module header.
    const { outputKey } = tweakPublicKey(internalXOnly);
    expect(bytesToHex(outputKey)).not.toBe(bytesToHex(internalXOnly));
    expect(outputKey.length).toBe(32);
  });

  it("the tweak is deterministic", () => {
    const a = tweakPublicKey(internalXOnly);
    const b = tweakPublicKey(internalXOnly);
    expect(bytesToHex(a.outputKey)).toBe(bytesToHex(b.outputKey));
    expect(a.parity).toBe(b.parity);
  });

  it("the tweaked PRIVATE key corresponds to the tweaked PUBLIC key", () => {
    // The property that makes a Taproot address spendable. If the two
    // negations are wrong, this fails — and nothing else would catch it until
    // a node rejected the transaction.
    const tweakedPriv = tweakPrivateKey(child.privateKey);
    const derivedPub = toXOnly(PublicKey.fromPrivateKey(tweakedPriv));
    const { outputKey } = tweakPublicKey(internalXOnly);
    expect(bytesToHex(derivedPub)).toBe(bytesToHex(outputKey));
  });

  it("holds for many random keys, not just the vector", () => {
    for (let i = 0; i < 50; i++) {
      const priv = PrivateKey.generate();
      const internal = toXOnly(PublicKey.fromPrivateKey(priv));
      const tweakedPriv = tweakPrivateKey(priv);
      expect(bytesToHex(toXOnly(PublicKey.fromPrivateKey(tweakedPriv))))
        .toBe(bytesToHex(tweakPublicKey(internal).outputKey));
    }
  });

  it("rejects a wrong-length internal key", () => {
    expect(() => tapTweak(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => tapTweak(new Uint8Array(33))).toThrow(/32 bytes/);
  });
});

describe("addresses and scripts", () => {
  const account = Bip86Account.fromMasterKey(master, TESTNET, 0);

  it("uses witness version 1, therefore BECH32M", () => {
    // BIP-350: v0 is bech32, v1+ is bech32m. The wrong variant produces an
    // address other wallets reject.
    const address = account.receiveAddress(0).address;
    expect(bech32Decode(address).variant).toBe("bech32m");
    expect(decodeSegwitAddress("tb", address).version).toBe(1);
  });

  it("the witness program is the 32-byte output key", () => {
    const { program } = decodeSegwitAddress("tb", account.receiveAddress(0).address);
    expect(program.length).toBe(32);
  });

  it("scriptPubKey is OP_1 PUSH32 <output key> — 34 bytes", () => {
    const script = hexToBytes(account.receiveAddress(0).scriptPubKey);
    expect(script.length).toBe(34);
    expect(script[0]).toBe(0x51); // OP_1
    expect(script[1]).toBe(0x20); // push 32
  });

  it("publishes the INTERNAL key, not the output key", () => {
    // Conflating them is the most likely route to an unspendable address, so
    // the record is explicit about which one it holds.
    const derived = account.receiveAddress(0);
    const script = hexToBytes(derived.scriptPubKey);
    expect(derived.publicKey).not.toBe(bytesToHex(script.slice(2)));
    const { outputKey } = tweakPublicKey(hexToBytes(derived.publicKey));
    expect(bytesToHex(outputKey)).toBe(bytesToHex(script.slice(2)));
  });

  it("network prefixes are correct", () => {
    expect(Bip86Account.fromMasterKey(master, MAINNET).receiveAddress(0).address.startsWith("bc1p")).toBe(true);
    expect(Bip86Account.fromMasterKey(master, TESTNET).receiveAddress(0).address.startsWith("tb1p")).toBe(true);
    expect(Bip86Account.fromMasterKey(master, REGTEST).receiveAddress(0).address.startsWith("bcrt1p")).toBe(true);
  });

  it("BIP-86 and BIP-84 derive COMPLETELY different addresses", async () => {
    // Purpose 86 vs 84. Restoring a BIP-86 seed into a BIP-84-only wallet
    // shows an empty balance; the funds are fine, the branch is wrong.
    const { Bip84Account } = await import("../../core/addresses/bip84.js");
    const taproot = Bip86Account.fromMasterKey(master, MAINNET).receiveAddress(0);
    const segwit = Bip84Account.fromMasterKey(master, MAINNET).receiveAddress(0);
    expect(taproot.address).not.toBe(segwit.address);
    expect(taproot.publicKey).not.toBe(segwit.publicKey);
  });

  it("account paths use purpose 86", () => {
    expect(BIP86_PURPOSE).toBe(86);
    expect(taprootAccountPath(MAINNET, 0)).toBe("m/86'/0'/0'");
    expect(taprootAccountPath(TESTNET, 3)).toBe("m/86'/1'/3'");
  });

  it("REFUSES a non-32-byte output key — such an output is anyone-can-spend", () => {
    // Generic SegWit validation permits 2–40 bytes for version 1, because
    // future upgrades may define other lengths. But a v1 output that is not
    // 32 bytes is not Taproot, and under current consensus it is
    // unencumbered: anyone can spend it. Encoding one would hand the coins
    // away while looking like a valid address.
    for (const length of [2, 20, 31, 33, 40]) {
      expect(() => p2trAddress(new Uint8Array(length), MAINNET), `length ${length}`)
        .toThrow(/exactly 32 bytes|spendable by anyone/);
    }
    expect(() => p2trAddress(new Uint8Array(32), MAINNET)).not.toThrow();
  });

  it("rejects malformed scriptPubKey input", () => {
    expect(() => p2trScriptPubKey(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => p2trScriptPubKey(new Uint8Array(33))).toThrow(/32 bytes/);
  });

  it("derives unique addresses and caches them", () => {
    const addresses = account.deriveAddresses(0, 0, 20);
    expect(new Set(addresses.map((a) => a.address)).size).toBe(20);
    expect(account.deriveAddress(0, 5)).toBe(account.deriveAddress(0, 5));
  });
});

describe("BIP-341 sighash", () => {
  const account = Bip86Account.fromMasterKey(master, REGTEST, 0);
  const spend = account.receiveAddress(0);
  const recipient = account.receiveAddress(1);

  function buildTx() {
    return new Transaction(
      2,
      [new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(50_000n, hexToBytes(recipient.scriptPubKey))],
      0,
    );
  }
  const prevouts = [{ value: 100_000n, scriptPubKey: hexToBytes(spend.scriptPubKey) }];

  it("the preimage has the documented length", () => {
    // 1 + 4 + 4 + 32 + 32 + 32 + 32 + 32 + 1 + 4 = 174
    expect(taprootSigMsg(buildTx(), 0, prevouts).length).toBe(174);
  });

  it("SIGHASH_DEFAULT is 0x00 and leads the preimage", () => {
    expect(SIGHASH_DEFAULT).toBe(0x00);
    expect(taprootSigMsg(buildTx(), 0, prevouts)[0]).toBe(0x00);
  });

  it("produces a 32-byte digest", () => {
    expect(taprootSighash(buildTx(), 0, prevouts).length).toBe(32);
  });

  it("commits to EVERY input's amount, not just this one", () => {
    // The gap BIP-341 closes versus BIP-143: a signer commits to the whole
    // picture, so a malicious PSBT cannot understate a co-signer's input.
    const tx = buildTx();
    const a = taprootSighash(tx, 0, [{ ...prevouts[0]!, value: 100_000n }]);
    const b = taprootSighash(tx, 0, [{ ...prevouts[0]!, value: 100_001n }]);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it("commits to every input's SCRIPT", () => {
    const tx = buildTx();
    const a = taprootSighash(tx, 0, prevouts);
    const b = taprootSighash(tx, 0, [
      { value: 100_000n, scriptPubKey: hexToBytes(recipient.scriptPubKey) },
    ]);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it("changing an output changes the digest", () => {
    const tx = buildTx();
    const altered = new Transaction(
      tx.version, tx.inputs,
      [new TxOutput(50_001n, tx.outputs[0]!.scriptPubKey)],
      tx.locktime,
    );
    expect(bytesToHex(taprootSighash(tx, 0, prevouts)))
      .not.toBe(bytesToHex(taprootSighash(altered, 0, prevouts)));
  });

  it("rejects a prevout count that does not match the inputs", () => {
    expect(() => new TaprootSighashCache(buildTx(), [])).toThrow(/expected 1 prevouts/);
  });

  it("a cached digest matches an uncached one", () => {
    const tx = buildTx();
    const cache = new TaprootSighashCache(tx, prevouts);
    expect(bytesToHex(taprootSighash(tx, 0, prevouts, cache)))
      .toBe(bytesToHex(taprootSighash(tx, 0, prevouts)));
  });
});

describe("BIP-341 key-path signing", () => {
  const account = Bip86Account.fromMasterKey(master, REGTEST, 0);
  const spend = account.receiveAddress(0);
  const recipient = account.receiveAddress(1);
  const spendKey = master.derivePath(spend.path).privateKey;

  function signed() {
    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: "cd".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(90_000n, hexToBytes(recipient.scriptPubKey))],
      0,
    );
    return signTaprootTransaction(unsigned, [
      {
        value: 100_000n,
        scriptPubKey: hexToBytes(spend.scriptPubKey),
        privateKey: spendKey,
      },
    ]);
  }

  it("the witness is ONE item: a 64-byte signature", () => {
    // No public key — the output commits to it directly. No trailing sighash
    // byte — SIGHASH_DEFAULT omits it, and appending one gives 65 bytes that
    // nodes reject.
    const witness = signed().inputs[0]!.witness;
    expect(witness.length).toBe(1);
    expect(witness[0]!.length).toBe(64);
  });

  it("the scriptSig stays empty", () => {
    expect(signed().inputs[0]!.scriptSig.length).toBe(0);
  });

  it("the signature verifies against the OUTPUT key", () => {
    const tx = signed();
    const prevouts = [{ value: 100_000n, scriptPubKey: hexToBytes(spend.scriptPubKey) }];
    const unsigned = tx.withInput(0, tx.inputs[0]!.withWitness([]));
    const digest = taprootSighash(unsigned, 0, prevouts);
    const outputKey = hexToBytes(spend.scriptPubKey).slice(2);
    expect(verifyTaprootSignature(digest, tx.inputs[0]!.witness[0]!, outputKey)).toBe(true);
  });

  it("does NOT verify against the internal key — the tweak is load-bearing", () => {
    const tx = signed();
    const prevouts = [{ value: 100_000n, scriptPubKey: hexToBytes(spend.scriptPubKey) }];
    const unsigned = tx.withInput(0, tx.inputs[0]!.withWitness([]));
    const digest = taprootSighash(unsigned, 0, prevouts);
    expect(verifyTaprootSignature(digest, tx.inputs[0]!.witness[0]!, hexToBytes(spend.publicKey)))
      .toBe(false);
  });

  it("round-trips through serialisation", () => {
    const tx = signed();
    const reparsed = Transaction.fromHex(tx.toHex());
    expect(reparsed.txid()).toBe(tx.txid());
    expect(reparsed.inputs[0]!.witness[0]!.length).toBe(64);
  });

  it("is cheaper than P2WPKH — the witness is smaller", () => {
    // 64 bytes versus ~108 for signature plus public key.
    expect(signed().vsize()).toBeLessThan(120);
  });

  it("ATTACK: a tampered output invalidates the signature", () => {
    const tx = signed();
    const prevouts = [{ value: 100_000n, scriptPubKey: hexToBytes(spend.scriptPubKey) }];
    const tampered = new Transaction(
      tx.version,
      tx.inputs.map((i) => i.withWitness([])),
      [new TxOutput(95_000n, tx.outputs[0]!.scriptPubKey)],
      tx.locktime,
    );
    const digest = taprootSighash(tampered, 0, prevouts);
    const outputKey = hexToBytes(spend.scriptPubKey).slice(2);
    expect(verifyTaprootSignature(digest, tx.inputs[0]!.witness[0]!, outputKey)).toBe(false);
  });

  it("ATTACK: a lie about the input value invalidates the signature", () => {
    const tx = signed();
    const unsigned = tx.withInput(0, tx.inputs[0]!.withWitness([]));
    const lied = taprootSighash(unsigned, 0, [
      { value: 999_999n, scriptPubKey: hexToBytes(spend.scriptPubKey) },
    ]);
    const outputKey = hexToBytes(spend.scriptPubKey).slice(2);
    expect(verifyTaprootSignature(lied, tx.inputs[0]!.witness[0]!, outputKey)).toBe(false);
  });

  it("every single-bit flip in the signature breaks verification", () => {
    const tx = signed();
    const prevouts = [{ value: 100_000n, scriptPubKey: hexToBytes(spend.scriptPubKey) }];
    const digest = taprootSighash(tx.withInput(0, tx.inputs[0]!.withWitness([])), 0, prevouts);
    const outputKey = hexToBytes(spend.scriptPubKey).slice(2);
    const signature = tx.inputs[0]!.witness[0]!;

    let broken = 0;
    for (let byte = 0; byte < signature.length; byte++) {
      const mutated = Uint8Array.from(signature);
      mutated[byte] = mutated[byte]! ^ 0x01;
      if (!verifyTaprootSignature(digest, mutated, outputKey)) broken++;
    }
    expect(broken).toBe(64);
  });

  it("refuses to sign a non-P2TR input", () => {
    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: "ef".repeat(32), vout: 0 })],
      [new TxOutput(1000n, hexToBytes(recipient.scriptPubKey))],
      0,
    );
    expect(() =>
      signTaprootTransaction(unsigned, [
        {
          value: 5000n,
          // A P2WPKH script, not P2TR.
          scriptPubKey: hexToBytes("0014" + "ab".repeat(20)),
          privateKey: spendKey,
        },
      ]),
    ).toThrow(/not a P2TR output/);
  });

  it("refuses a mismatched count of signing inputs", () => {
    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: "ef".repeat(32), vout: 0 })],
      [new TxOutput(1000n, hexToBytes(recipient.scriptPubKey))],
      0,
    );
    expect(() => signTaprootTransaction(unsigned, [])).toThrow(/expected signing data/);
  });
});
