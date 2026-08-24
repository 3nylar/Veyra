/**
 * Extended keys (BIP-32 serialisation) and BIP-48 multisig accounts.
 *
 * The xpub vectors are the published BIP-32 set. Matching them proves the
 * Base58Check encoding, the 78-byte layout, and the version bytes are all
 * correct at once — any one wrong produces a different string.
 *
 * For BIP-48 the property that matters is CONVERGENCE: every participant must
 * derive the same address from the same xpubs, in any order.
 */
import { describe, it, expect } from "vitest";
import { ExtendedKey, EXTENDED_KEY_VERSIONS } from "../../core/derivation/bip32.js";
import {
  Bip48MultisigWallet, multisigAccountPath, BIP48_PURPOSE, SCRIPT_TYPE_P2WSH,
} from "../../core/addresses/bip48.js";
import {
  base58Encode, base58Decode, base58CheckEncode, base58CheckDecode, Base58Error,
} from "../../core/addresses/base58.js";
import { mnemonicToSeed } from "../../core/mnemonic/index.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { MAINNET, TESTNET, REGTEST } from "../../core/bitcoin/networks.js";
import { hexToBytes, bytesToHex } from "../../core/crypto/bytes.js";

const SEED_1 = hexToBytes("000102030405060708090a0b0c0d0e0f");
const master = ExtendedKey.fromSeed(SEED_1);

describe("Base58", () => {
  it("PRESERVES leading zero bytes as leading '1' characters", () => {
    // The classic Base58 bug. Base conversion loses leading zeros because
    // they contribute nothing to the integer — and for a P2PKH address
    // (version byte 0x00) it happens on every single one.
    expect(base58Encode(new Uint8Array([0, 0, 1]))).toMatch(/^11/);
    expect(bytesToHex(base58Decode(base58Encode(new Uint8Array([0, 0, 1]))))).toBe("000001");
  });

  it("round-trips arbitrary bytes", () => {
    for (let i = 0; i < 100; i++) {
      const data = new Uint8Array(1 + Math.floor(Math.random() * 60));
      crypto.getRandomValues(data);
      expect(bytesToHex(base58Decode(base58Encode(data)))).toBe(bytesToHex(data));
    }
  });

  it("excludes the confusable characters 0, O, I and l", () => {
    const encoded = base58Encode(new Uint8Array(32).fill(0xff));
    for (const char of "0OIl") expect(encoded).not.toContain(char);
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => base58Decode("abc0def")).toThrow(/outside the Base58 alphabet/);
    expect(() => base58Decode("hello world")).toThrow();
  });

  it("does NOT echo the offending input in the error", () => {
    // This decodes user-supplied strings; reflecting input is a habit worth
    // not having.
    try {
      base58Decode("SECRETMARKER0");
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).not.toContain("SECRETMARKER");
    }
  });

  it("detects a corrupted checksum", () => {
    const encoded = base58CheckEncode(hexToBytes("00112233445566778899"));
    const corrupted = encoded.slice(0, -1) + (encoded.endsWith("A") ? "B" : "A");
    expect(() => base58CheckDecode(corrupted)).toThrow(/checksum mismatch/);
  });

  it("rejects a string too short to hold a checksum", () => {
    expect(() => base58CheckDecode("11")).toThrow(/too short/);
  });

  it("bounds input length — encoding is quadratic", () => {
    expect(() => base58Encode(new Uint8Array(300))).toThrow(/exceeds/);
  });
});

describe("BIP-32 extended keys — official vectors", () => {
  it("master xprv and xpub match the published strings", () => {
    expect(master.toExtendedPrivateKeyUnsafe("mainnet")).toBe(
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    );
    expect(master.toExtendedPublicKey("mainnet")).toBe(
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    );
  });

  it("m/0' matches the published strings", () => {
    const node = master.derivePath("m/0'");
    expect(node.toExtendedPrivateKeyUnsafe("mainnet")).toBe(
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    );
    expect(node.toExtendedPublicKey("mainnet")).toBe(
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    );
  });

  it("testnet uses tpub/tprv prefixes", () => {
    expect(master.toExtendedPublicKey("testnet").startsWith("tpub")).toBe(true);
    expect(master.toExtendedPrivateKeyUnsafe("testnet").startsWith("tprv")).toBe(true);
    expect(EXTENDED_KEY_VERSIONS.testnet.public).toBe(0x043587cf);
  });

  it("round-trips an xpub into a WATCH-ONLY node", () => {
    const reparsed = ExtendedKey.fromExtendedKey(master.toExtendedPublicKey("mainnet"));
    expect(reparsed.hasPrivateKey).toBe(false);
    expect(reparsed.publicKey.toHex()).toBe(master.publicKey.toHex());
    expect(bytesToHex(reparsed.chainCode)).toBe(bytesToHex(master.chainCode));
  });

  it("round-trips an xprv into a signing node", () => {
    const reparsed = ExtendedKey.fromExtendedKey(master.toExtendedPrivateKeyUnsafe("mainnet"));
    expect(reparsed.hasPrivateKey).toBe(true);
    expect(reparsed.privateKey.toHexUnsafe()).toBe(master.privateKey.toHexUnsafe());
  });

  it("a restored xpub derives the SAME children", () => {
    const watchOnly = ExtendedKey.fromExtendedKey(master.toExtendedPublicKey("mainnet"));
    for (const index of [0, 1, 5, 100]) {
      expect(watchOnly.derive(index).publicKey.toHex())
        .toBe(master.derive(index).publicKey.toHex());
    }
  });

  it("rejects unrecognised version bytes", () => {
    const data = base58CheckDecode(master.toExtendedPublicKey("mainnet"));
    data[0] = 0xff;
    expect(() => ExtendedKey.fromExtendedKey(base58CheckEncode(data)))
      .toThrow(/unrecognised extended key version/);
  });

  it("REJECTS an inconsistent depth-0 key", () => {
    // A crafted key claiming to be a master while carrying a parent could
    // masquerade as one, changing which addresses a co-signer derives.
    const data = base58CheckDecode(master.toExtendedPublicKey("mainnet"));
    data[9] = 0x01; // non-zero index at depth 0
    expect(() => ExtendedKey.fromExtendedKey(base58CheckEncode(data)))
      .toThrow(/depth-0 key must have index 0/);

    const data2 = base58CheckDecode(master.toExtendedPublicKey("mainnet"));
    data2[5] = 0x01; // non-zero parent fingerprint at depth 0
    expect(() => ExtendedKey.fromExtendedKey(base58CheckEncode(data2)))
      .toThrow(/zero parent fingerprint/);
  });

  it("rejects a wrong-length payload", () => {
    expect(() => ExtendedKey.fromExtendedKey(base58CheckEncode(new Uint8Array(77))))
      .toThrow(/78 bytes/);
  });

  it("the export method is named to read as alarming", () => {
    // An xprv is a full backup of every key in the subtree. The name should
    // be greppable and uncomfortable at a call site.
    expect(typeof master.toExtendedPrivateKeyUnsafe).toBe("function");
    expect("toExtendedPrivateKey" in master).toBe(false);
  });
});

describe("BIP-48 paths", () => {
  it("uses purpose 48 and script type 2' for P2WSH", () => {
    expect(BIP48_PURPOSE).toBe(48);
    expect(SCRIPT_TYPE_P2WSH).toBe(2);
    expect(multisigAccountPath(MAINNET, 0)).toBe("m/48'/0'/0'/2'");
    expect(multisigAccountPath(TESTNET, 3)).toBe("m/48'/1'/3'/2'");
  });

  it("everything down to script_type is HARDENED", () => {
    // So a shared account xpub cannot be walked upward to the master key —
    // which matters more here, because the xpub is given to other people.
    const path = multisigAccountPath(REGTEST, 0);
    expect(path.split("/").slice(1).every((segment) => segment.endsWith("'"))).toBe(true);
  });
});

describe("BIP-48 multisig wallet", () => {
  /** Three participants, each with their own seed — as in reality. */
  const seeds = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
  ];
  const masters = seeds.map((phrase) => ExtendedKey.fromSeed(mnemonicToSeed(phrase)));
  const accountKeys = masters.map((m) =>
    Bip48MultisigWallet.deriveAccountKey(m, REGTEST, 0),
  );
  const xpubs = accountKeys.map((k) => k.toExtendedPublicKey("testnet"));

  function wallet(order = [0, 1, 2]) {
    return Bip48MultisigWallet.fromExtendedKeys({
      threshold: 2,
      accountKeys: order.map((i) => xpubs[i]!),
      network: REGTEST,
    });
  }

  it("derives a 2-of-3 address from three xpubs", () => {
    const receive = wallet().receiveAddress(0);
    expect(receive.address.startsWith("bcrt1q")).toBe(true);
    expect(receive.path).toBe("m/48'/1'/0'/2'/0/0");
    expect(receive.account.describe).toBe("2-of-3");
  });

  it("CONVERGES: xpub order does not change the address", () => {
    // Without BIP-67 sorting, three participants listing their xpubs in three
    // orders would derive three different addresses — each convinced the
    // others were wrong.
    const a = wallet([0, 1, 2]).receiveAddress(0).address;
    const b = wallet([2, 0, 1]).receiveAddress(0).address;
    const c = wallet([1, 2, 0]).receiveAddress(0).address;
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it("derives a unique address per index", () => {
    const w = wallet();
    const addresses = Array.from({ length: 20 }, (_, i) => w.receiveAddress(i).address);
    expect(new Set(addresses).size).toBe(20);
  });

  it("receive and change chains are separate", () => {
    const w = wallet();
    expect(w.receiveAddress(0).address).not.toBe(w.changeAddress(0).address);
    expect(w.changeAddress(0).path).toBe("m/48'/1'/0'/2'/1/0");
  });

  it("a WATCH-ONLY participant derives the same addresses", () => {
    // The whole point of exchanging xpubs: a participant needs no private key
    // to know where the money is.
    const watchOnly = Bip48MultisigWallet.fromExtendedKeys({
      threshold: 2, accountKeys: xpubs, network: REGTEST,
    });
    expect(watchOnly.receiveAddress(5).address).toBe(wallet().receiveAddress(5).address);
  });

  it("signingKey returns only THIS participant's key", () => {
    const w = wallet();
    const key = w.signingKey(masters[0]!, 0, 0);
    const derived = PublicKey.fromPrivateKey(key);
    expect(w.deriveAccount(0, 0).includes(derived)).toBe(true);
    // And it is one of the three, not an aggregate.
    expect(w.positionOf(derived, 0, 0)).toBeGreaterThanOrEqual(0);
  });

  it("REFUSES a master that does not participate", () => {
    const outsider = ExtendedKey.fromSeed(mnemonicToSeed(
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ));
    expect(() => wallet().signingKey(outsider, 0, 0)).toThrow(/does not participate/);
  });

  it("REJECTS two co-signers with the same account key", () => {
    // One holder would fill two slots, collapsing a 2-of-3 to a 1-of-2.
    expect(() => Bip48MultisigWallet.fromExtendedKeys({
      threshold: 2, accountKeys: [xpubs[0]!, xpubs[0]!, xpubs[1]!], network: REGTEST,
    })).toThrow(/same account key/);
  });

  it("rejects an unspendable threshold", () => {
    expect(() => Bip48MultisigWallet.fromExtendedKeys({
      threshold: 4, accountKeys: xpubs, network: REGTEST,
    })).toThrow(/would be unspendable/);
  });

  it("the descriptor lets participants verify the setup out of band", () => {
    // An attacker who substitutes one xpub creates a wallet where they are a
    // co-signer. The addresses look fine and funds arrive normally — the
    // substitution is invisible until a spend needs a signature nobody has.
    const descriptor = wallet().descriptor();
    expect(descriptor.type).toBe("2-of-3");
    expect((descriptor.accountKeys as unknown[]).length).toBe(3);
    expect(descriptor.firstReceiveAddress).toBe(wallet().receiveAddress(0).address);
    // No private material.
    expect(JSON.stringify(descriptor)).not.toMatch(/xprv|tprv/);
  });

  it("a SUBSTITUTED xpub produces a different address — which is how you catch it", () => {
    const attacker = ExtendedKey.fromSeed(mnemonicToSeed(
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ));
    const attackerXpub = Bip48MultisigWallet
      .deriveAccountKey(attacker, REGTEST, 0)
      .toExtendedPublicKey("testnet");

    const substituted = Bip48MultisigWallet.fromExtendedKeys({
      threshold: 2, accountKeys: [xpubs[0]!, xpubs[1]!, attackerXpub], network: REGTEST,
    });
    expect(substituted.receiveAddress(0).address).not.toBe(wallet().receiveAddress(0).address);
  });

  it("different networks give different addresses", () => {
    const mainnetKeys = masters.map((m) =>
      Bip48MultisigWallet.deriveAccountKey(m, MAINNET, 0).toExtendedPublicKey("mainnet"),
    );
    const mainnetWallet = Bip48MultisigWallet.fromExtendedKeys({
      threshold: 2, accountKeys: mainnetKeys, network: MAINNET,
    });
    expect(mainnetWallet.receiveAddress(0).address.startsWith("bc1q")).toBe(true);
    expect(mainnetWallet.receiveAddress(0).address)
      .not.toBe(wallet().receiveAddress(0).address);
  });
});

describe("end-to-end: three participants sign a shared transaction", () => {
  it("two of three can spend, using only their own keys", async () => {
    const { signMultisigInput, combineSignatures, verifyMultisigTransaction } =
      await import("../../core/signing/multisig.js");
    const { Transaction, TxInput, TxOutput, SEQUENCE_RBF } =
      await import("../../core/transactions/transaction.js");

    const phrases = [
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ];
    const ms = phrases.map((p) => ExtendedKey.fromSeed(mnemonicToSeed(p)));
    const keys = ms.map((m) =>
      Bip48MultisigWallet.deriveAccountKey(m, REGTEST, 0).toExtendedPublicKey("testnet"),
    );

    const shared = Bip48MultisigWallet.fromExtendedKeys({
      threshold: 2, accountKeys: keys, network: REGTEST,
    });
    const { account } = shared.receiveAddress(0);

    const tx = new Transaction(
      2,
      [new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(900_000n, hexToBytes("0014" + "cd".repeat(20)))],
      0,
    );
    const inputs = [{ value: 1_000_000n, account }];

    // Participants 0 and 2 sign, each with only their own master key.
    const partials = [0, 2].map((i) =>
      signMultisigInput(tx, 0, inputs[0]!, shared.signingKey(ms[i]!, 0, 0)),
    );

    const signed = combineSignatures(tx, inputs, partials);
    expect(verifyMultisigTransaction(signed, inputs)).toBe(true);
  });
});
