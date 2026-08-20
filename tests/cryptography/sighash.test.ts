/**
 * BIP-143 SIGHASH TESTS
 *
 * The headline test is the official BIP-143 native-P2WPKH vector: a published
 * transaction, a published input value, and a published 32-byte digest. If
 * our independently-written preimage builder reproduces that exact digest,
 * the field order, endianness, scriptCode construction, and amount encoding
 * are all confirmed at once.
 */
import { describe, it, expect } from "vitest";
import { Transaction, TxInput, TxOutput } from "../../core/transactions/transaction.js";
import {
  sighash, sighashPreimage, p2wpkhScriptCode, SighashCache,
  SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
} from "../../core/signing/sighash.js";
import { PrivateKey } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

/** The unsigned transaction from BIP-143's "Native P2WPKH" example. */
const BIP143_UNSIGNED =
  "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000" +
  "000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" +
  "0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac" +
  "7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac" +
  "11000000";

/** Private key for the second input, per the spec. Its value is 6 BTC. */
const BIP143_KEY_1 = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
const BIP143_VALUE_1 = 600_000_000n;

describe("BIP-143 official native P2WPKH vector", () => {
  const tx = Transaction.fromHex(BIP143_UNSIGNED);
  const priv = PrivateKey.fromHex(BIP143_KEY_1);
  const pub = PublicKey.fromPrivateKey(priv);

  it("parses the published transaction", () => {
    expect(tx.version).toBe(1);
    expect(tx.inputs.length).toBe(2);
    expect(tx.outputs.length).toBe(2);
    expect(tx.locktime).toBe(0x11);
  });

  it("re-serialises byte-for-byte — the txid depends on exactness", () => {
    expect(tx.toHex()).toBe(BIP143_UNSIGNED);
  });

  it("derives the public key stated in the spec", () => {
    expect(pub.toHex()).toBe(
      "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357",
    );
  });

  it("produces the EXACT sighash published in BIP-143", () => {
    const digest = sighash(tx, 1, { value: BIP143_VALUE_1, publicKeyHash: pub.hash160() });
    expect(bytesToHex(digest)).toBe(
      "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
    );
  });

  it("builds a preimage of the expected length", () => {
    // 4 + 32 + 32 + 36 + 26 + 8 + 4 + 32 + 4 + 4 = 182
    const preimage = sighashPreimage(tx, 1, {
      value: BIP143_VALUE_1,
      publicKeyHash: pub.hash160(),
    });
    expect(preimage.length).toBe(182);
  });

  it("the amount appears in the preimage at the documented offset", () => {
    // Offset 4+32+32+36+26 = 130; 8 bytes little-endian.
    const preimage = sighashPreimage(tx, 1, {
      value: BIP143_VALUE_1,
      publicKeyHash: pub.hash160(),
    });
    const view = new DataView(preimage.buffer, preimage.byteOffset, preimage.length);
    expect(view.getBigUint64(130, true)).toBe(BIP143_VALUE_1);
  });
});

describe("the scriptCode is the LEGACY P2PKH script, not the witness program", () => {
  const hash = hexToBytes("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1");

  it("has the documented structure", () => {
    expect(bytesToHex(p2wpkhScriptCode(hash))).toBe(
      "76a914" + "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1" + "88ac",
    );
  });

  it("is 25 bytes: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG", () => {
    const script = p2wpkhScriptCode(hash);
    expect(script.length).toBe(25);
    expect(script[0]).toBe(0x76); // OP_DUP
    expect(script[1]).toBe(0xa9); // OP_HASH160
    expect(script[2]).toBe(0x14); // push 20
    expect(script[23]).toBe(0x88); // OP_EQUALVERIFY
    expect(script[24]).toBe(0xac); // OP_CHECKSIG
  });

  it("rejects a hash that is not 20 bytes", () => {
    expect(() => p2wpkhScriptCode(new Uint8Array(19))).toThrow(/20 bytes/);
    expect(() => p2wpkhScriptCode(new Uint8Array(32))).toThrow(/20 bytes/);
  });
});

describe("THE AMOUNT IS COMMITTED — the vulnerability BIP-143 closed", () => {
  const tx = Transaction.fromHex(BIP143_UNSIGNED);
  const pub = PublicKey.fromPrivateKey(PrivateKey.fromHex(BIP143_KEY_1));
  const hash160 = pub.hash160();

  it("a different stated input value produces a different sighash", () => {
    // The legacy attack: lie to the wallet about an input's value so the
    // difference silently becomes fee. Under BIP-143 the lie changes the
    // digest, so the signature simply will not verify.
    const honest = sighash(tx, 1, { value: BIP143_VALUE_1, publicKeyHash: hash160 });
    const lie = sighash(tx, 1, { value: 1_000_000_000n, publicKeyHash: hash160 });
    expect(bytesToHex(honest)).not.toBe(bytesToHex(lie));
  });

  it("even a one-satoshi difference changes the digest", () => {
    const a = sighash(tx, 1, { value: BIP143_VALUE_1, publicKeyHash: hash160 });
    const b = sighash(tx, 1, { value: BIP143_VALUE_1 + 1n, publicKeyHash: hash160 });
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it("rejects a negative value", () => {
    expect(() => sighash(tx, 1, { value: -1n, publicKeyHash: hash160 })).toThrow();
  });
});

describe("only SIGHASH_ALL is permitted", () => {
  const tx = Transaction.fromHex(BIP143_UNSIGNED);
  const hash160 = PublicKey.fromPrivateKey(PrivateKey.fromHex(BIP143_KEY_1)).hash160();

  it.each([
    ["SIGHASH_NONE", SIGHASH_NONE],
    ["SIGHASH_SINGLE", SIGHASH_SINGLE],
    ["SIGHASH_ANYONECANPAY|ALL", 0x81],
  ])("rejects %s — it commits to less than the whole transaction", (_label, type) => {
    expect(() => sighash(tx, 1, { value: BIP143_VALUE_1, publicKeyHash: hash160 }, type)).toThrow(
      /only SIGHASH_ALL/,
    );
  });

  it("the sighash type is itself inside the preimage", () => {
    const preimage = sighashPreimage(tx, 1, { value: BIP143_VALUE_1, publicKeyHash: hash160 });
    const view = new DataView(preimage.buffer, preimage.byteOffset, preimage.length);
    expect(view.getUint32(preimage.length - 4, true)).toBe(SIGHASH_ALL);
  });
});

describe("input index handling", () => {
  const tx = Transaction.fromHex(BIP143_UNSIGNED);
  const hash160 = PublicKey.fromPrivateKey(PrivateKey.fromHex(BIP143_KEY_1)).hash160();
  const signable = { value: BIP143_VALUE_1, publicKeyHash: hash160 };

  it("different inputs give different digests, even with identical values", () => {
    const a = sighash(tx, 0, signable);
    const b = sighash(tx, 1, signable);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it("rejects an out-of-range index", () => {
    expect(() => sighash(tx, 2, signable)).toThrow(/out of range/);
    expect(() => sighash(tx, -1, signable)).toThrow(/out of range/);
    expect(() => sighash(tx, 1.5, signable)).toThrow();
  });

  it("rejects a transaction with no inputs", () => {
    const empty = new Transaction(2, [], [new TxOutput(1000n, new Uint8Array(22))], 0);
    expect(() => new SighashCache(empty)).toThrow(/no inputs/);
  });
});

describe("SighashCache", () => {
  const tx = Transaction.fromHex(BIP143_UNSIGNED);
  const hash160 = PublicKey.fromPrivateKey(PrivateKey.fromHex(BIP143_KEY_1)).hash160();

  it("a cached digest matches an uncached one — the optimisation is transparent", () => {
    const cache = new SighashCache(tx);
    const cached = sighash(tx, 1, { value: BIP143_VALUE_1, publicKeyHash: hash160 }, SIGHASH_ALL, cache);
    const uncached = sighash(tx, 1, { value: BIP143_VALUE_1, publicKeyHash: hash160 });
    expect(bytesToHex(cached)).toBe(bytesToHex(uncached));
  });

  it("computes three 32-byte digests", () => {
    const cache = new SighashCache(tx);
    expect(cache.hashPrevouts.length).toBe(32);
    expect(cache.hashSequence.length).toBe(32);
    expect(cache.hashOutputs.length).toBe(32);
  });

  it("different transactions produce different cached digests", () => {
    const other = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 })],
      [new TxOutput(1000n, hexToBytes("0014" + "bb".repeat(20)))],
      0,
    );
    const a = new SighashCache(tx);
    const b = new SighashCache(other);
    expect(bytesToHex(a.hashOutputs)).not.toBe(bytesToHex(b.hashOutputs));
  });
});
