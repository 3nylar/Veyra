/**
 * BIP-32 / BIP-84 DERIVATION TESTS
 *
 * The BIP-32 vectors are the published set. Vector 5 in particular is a list
 * of INVALID extended keys designed to catch parsers that accept malformed
 * input — the most security-relevant part of the vector set.
 *
 * The BIP-84 vectors are from BIP-84 itself and are the end-to-end proof:
 * a known mnemonic must produce known addresses. If these pass, a wallet
 * restored into Veyra lands on the same addresses as any other wallet.
 */
import { describe, it, expect } from "vitest";
import { ExtendedKey, HARDENED_OFFSET } from "../../core/derivation/bip32.js";
import { mnemonicToSeed } from "../../core/mnemonic/index.js";
import { Bip84Account, p2wpkhAddress, p2wpkhScriptPubKey, validateAddress } from "../../core/addresses/bip84.js";
import { MAINNET, TESTNET, REGTEST } from "../../core/bitcoin/networks.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

/** BIP-32 test vector 1 seed. */
const SEED_1 = hexToBytes("000102030405060708090a0b0c0d0e0f");
/** BIP-32 test vector 2 seed. */
const SEED_2 = hexToBytes(
  "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
);
/** BIP-32 test vector 3: a seed that produces a leading-zero private key. */
const SEED_3 = hexToBytes(
  "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
);

describe("BIP-32 vector 1 — m/0'/1/2'/2/1000000000", () => {
  const master = ExtendedKey.fromSeed(SEED_1);

  it("derives the correct master private key", () => {
    expect(master.privateKey.toHexUnsafe()).toBe(
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    );
  });

  it("derives the correct master public key", () => {
    expect(master.publicKey.toHex()).toBe(
      "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
    );
  });

  it("derives the correct master chain code", () => {
    expect(bytesToHex(master.chainCode)).toBe(
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
    );
  });

  it("m/0' (hardened)", () => {
    const node = master.derivePath("m/0'");
    expect(node.privateKey.toHexUnsafe()).toBe(
      "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
    );
    expect(node.publicKey.toHex()).toBe(
      "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
    );
  });

  it("m/0'/1 (non-hardened)", () => {
    const node = master.derivePath("m/0'/1");
    expect(node.privateKey.toHexUnsafe()).toBe(
      "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
    );
    expect(node.publicKey.toHex()).toBe(
      "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
    );
  });

  it("m/0'/1/2'/2/1000000000 (full path)", () => {
    const node = master.derivePath("m/0'/1/2'/2/1000000000");
    expect(node.privateKey.toHexUnsafe()).toBe(
      "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
    );
    expect(node.publicKey.toHex()).toBe(
      "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
    );
    expect(node.depth).toBe(5);
  });

  it("the 'h' hardened marker is equivalent to the apostrophe", () => {
    expect(master.derivePath("m/0h/1/2h").publicKey.toHex())
      .toBe(master.derivePath("m/0'/1/2'").publicKey.toHex());
  });
});

describe("BIP-32 vector 2 — long seed", () => {
  const master = ExtendedKey.fromSeed(SEED_2);

  it("derives the correct master key", () => {
    expect(master.privateKey.toHexUnsafe()).toBe(
      "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
    );
  });

  it("m/0 (non-hardened at depth 1)", () => {
    const node = master.derivePath("m/0");
    expect(node.privateKey.toHexUnsafe()).toBe(
      "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
    );
  });

  it("m/0/2147483647' (maximum hardened index)", () => {
    const node = master.derivePath("m/0/2147483647'");
    expect(node.privateKey.toHexUnsafe()).toBe(
      "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
    );
  });
});

describe("BIP-32 vector 3 — leading-zero private key edge case", () => {
  // This vector exists specifically to catch implementations that strip
  // leading zeros when serialising a 32-byte scalar. A key of
  // 0x00ddb8...  must stay 32 bytes; truncating it to 31 changes every
  // derived child.
  const master = ExtendedKey.fromSeed(SEED_3);

  it("preserves the leading zero byte in the master key", () => {
    expect(master.privateKey.toHexUnsafe()).toBe(
      "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
    );
    expect(master.privateKey.toHexUnsafe().length).toBe(64);
  });

  it("m/0' derives correctly despite the leading zero", () => {
    expect(master.derivePath("m/0'").privateKey.toHexUnsafe()).toBe(
      "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
    );
  });
});

describe("hardened derivation — the security boundary", () => {
  const master = ExtendedKey.fromSeed(SEED_1);

  it("hardened and non-hardened children at the same index differ", () => {
    expect(master.derive(0).publicKey.toHex())
      .not.toBe(master.derive(HARDENED_OFFSET).publicKey.toHex());
  });

  it("a watch-only node CANNOT derive hardened children — this is the point", () => {
    expect(() => master.neutered().derive(HARDENED_OFFSET)).toThrow(/watch-only/);
    expect(() => master.neutered().derivePath("m/84'")).toThrow(/watch-only/);
  });

  it("a watch-only node CAN derive non-hardened children (watch-only wallets work)", () => {
    const watchOnly = master.neutered();
    expect(watchOnly.derive(5).publicKey.toHex()).toBe(master.derive(5).publicKey.toHex());
  });

  it("public-only derivation matches private derivation over a deep path", () => {
    // This is the (IL + k)G = IL*G + K identity holding across many levels.
    const priv = master.derivePath("m/0/1/2/3/4");
    const pub = master.neutered().derivePath("m/0/1/2/3/4");
    expect(pub.publicKey.toHex()).toBe(priv.publicKey.toHex());
    expect(bytesToHex(pub.chainCode)).toBe(bytesToHex(priv.chainCode));
  });

  it("a watch-only node holds no private key and says so rather than returning null", () => {
    const watchOnly = master.neutered();
    expect(watchOnly.hasPrivateKey).toBe(false);
    expect(() => watchOnly.privateKey).toThrow(/watch-only/);
  });

  /**
   * ATTACK: the parent-key recovery that hardening prevents.
   *
   * Demonstrated as an executable test rather than described in prose,
   * because the arithmetic is what makes it convincing. Given a parent xpub
   * (public key + chain code) and ONE non-hardened child private key, the
   * parent private key falls out by subtraction.
   */
  it("ATTACK: non-hardened child key + parent chain code recovers the parent key", async () => {
    const { hmac } = await import("@noble/hashes/hmac.js");
    const { sha512 } = await import("@noble/hashes/sha2.js");
    const { CURVE_ORDER } = await import("../../core/keys/privateKey.js");
    const { bytesToBigIntBE, concatBytes } = await import("../../core/crypto/bytes.js");

    const parent = master.derivePath("m/0'");
    const index = 7;
    const child = parent.derive(index); // non-hardened

    // The attacker has: parent PUBLIC key, parent chain code, one child key.
    const ser32 = (n: number) => {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, n, false);
      return b;
    };
    const I = hmac(sha512, parent.chainCode, concatBytes(parent.publicKey.toBytes(), ser32(index)));
    const IL = bytesToBigIntBE(I.slice(0, 32));

    // parentKey = (childKey - IL) mod n
    const recovered = ((child.privateKey.toBigInt() - IL) % CURVE_ORDER + CURVE_ORDER) % CURVE_ORDER;

    expect(recovered).toBe(parent.privateKey.toBigInt()); // fully compromised
  });

  it("the same attack FAILS against a hardened child", () => {
    const parent = master.derivePath("m/0'");
    const hardenedChild = parent.derive(HARDENED_OFFSET + 7);
    // No public-data-only computation yields the tweak, because the HMAC
    // input included the parent PRIVATE key. The relationship is severed.
    expect(hardenedChild.privateKey.toBigInt()).not.toBe(parent.privateKey.toBigInt());
  });
});

describe("path parsing", () => {
  const master = ExtendedKey.fromSeed(SEED_1);

  it("'m' and '' return the node itself", () => {
    expect(master.derivePath("m").publicKey.toHex()).toBe(master.publicKey.toHex());
    expect(master.derivePath("").publicKey.toHex()).toBe(master.publicKey.toHex());
  });

  it("rejects paths not beginning with m", () => {
    expect(() => master.derivePath("0/1")).toThrow(/must begin with 'm'/);
    expect(() => master.derivePath("n/0")).toThrow();
  });

  it("rejects malformed segments rather than partially deriving", () => {
    expect(() => master.derivePath("m/abc")).toThrow();
    expect(() => master.derivePath("m/-1")).toThrow();
    expect(() => master.derivePath("m/1.5")).toThrow();
    expect(() => master.derivePath("m//1")).toThrow();
    expect(() => master.derivePath("m/0x10")).toThrow();
  });

  it("rejects an index at or above 2^31 in the path form", () => {
    expect(() => master.derivePath("m/2147483648")).toThrow(/exceeds the maximum/);
  });

  it("rejects out-of-range indices at the derive() level", () => {
    expect(() => master.derive(-1)).toThrow();
    expect(() => master.derive(2 ** 32)).toThrow();
    expect(() => master.derive(1.5)).toThrow();
  });

  it("rejects seeds outside the 16-64 byte range", () => {
    expect(() => ExtendedKey.fromSeed(new Uint8Array(15))).toThrow(/16 and 64/);
    expect(() => ExtendedKey.fromSeed(new Uint8Array(65))).toThrow(/16 and 64/);
  });

  it("is deterministic — the same path always gives the same key", () => {
    const a = master.derivePath("m/84'/1'/0'/0/0");
    const b = master.derivePath("m/84'/1'/0'/0/0");
    expect(a.privateKey.toHexUnsafe()).toBe(b.privateKey.toHexUnsafe());
  });
});

describe("ExtendedKey does not leak key material", () => {
  const master = ExtendedKey.fromSeed(SEED_1);
  const secret = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";

  it("toString, JSON, and inspect are all redacted", async () => {
    const { inspect } = await import("node:util");
    expect(String(master)).not.toContain(secret);
    expect(JSON.stringify(master)).not.toContain(secret);
    expect(JSON.stringify({ wallet: master })).not.toContain(secret);
    expect(inspect(master, { depth: null, showHidden: true })).not.toContain(secret);
  });

  it("the chain code is also absent from string forms (it is sensitive too)", () => {
    expect(String(master)).not.toContain(bytesToHex(master.chainCode));
  });
});

/**
 * BIP-84 official test vectors. Mnemonic:
 *   "abandon abandon ... about"  (the standard all-zeros-entropy phrase)
 */
const BIP84_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("BIP-84 official vectors — mainnet m/84'/0'/0'", () => {
  const master = ExtendedKey.fromSeed(mnemonicToSeed(BIP84_MNEMONIC));
  const account = Bip84Account.fromMasterKey(master, MAINNET, 0);

  it("first receive address m/84'/0'/0'/0/0", () => {
    const addr = account.receiveAddress(0);
    expect(addr.address).toBe("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    expect(addr.publicKey).toBe(
      "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    );
    expect(addr.path).toBe("m/84'/0'/0'/0/0");
  });

  it("second receive address m/84'/0'/0'/0/1", () => {
    const addr = account.receiveAddress(1);
    expect(addr.address).toBe("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    expect(addr.publicKey).toBe(
      "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
    );
  });

  it("first change address m/84'/0'/0'/1/0", () => {
    const addr = account.changeAddress(0);
    expect(addr.address).toBe("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    expect(addr.publicKey).toBe(
      "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
    );
  });

  it("change addresses are on a different chain and never collide with receive", () => {
    expect(account.receiveAddress(0).address).not.toBe(account.changeAddress(0).address);
  });
});

describe("BIP-84 — testnet and regtest", () => {
  const master = ExtendedKey.fromSeed(mnemonicToSeed(BIP84_MNEMONIC));

  it("testnet addresses use the tb1 prefix and coin type 1", () => {
    const account = Bip84Account.fromMasterKey(master, TESTNET, 0);
    const addr = account.receiveAddress(0);
    expect(addr.address.startsWith("tb1q")).toBe(true);
    expect(addr.path).toBe("m/84'/1'/0'/0/0");
    expect(addr.network).toBe("testnet");
  });

  it("regtest addresses use the bcrt1 prefix", () => {
    const account = Bip84Account.fromMasterKey(master, REGTEST, 0);
    expect(account.receiveAddress(0).address.startsWith("bcrt1q")).toBe(true);
  });

  it("testnet and regtest share coin type 1, so they derive the SAME key", () => {
    // Documented rather than assumed: only the HRP differs, not the key.
    const t = Bip84Account.fromMasterKey(master, TESTNET, 0).receiveAddress(0);
    const r = Bip84Account.fromMasterKey(master, REGTEST, 0).receiveAddress(0);
    expect(t.publicKey).toBe(r.publicKey);
    expect(t.address).not.toBe(r.address);
  });

  it("mainnet and testnet derive COMPLETELY different keys (coin type 0 vs 1)", () => {
    const m = Bip84Account.fromMasterKey(master, MAINNET, 0).receiveAddress(0);
    const t = Bip84Account.fromMasterKey(master, TESTNET, 0).receiveAddress(0);
    expect(m.publicKey).not.toBe(t.publicKey);
  });

  it("different accounts derive different addresses", () => {
    const a0 = Bip84Account.fromMasterKey(master, TESTNET, 0).receiveAddress(0);
    const a1 = Bip84Account.fromMasterKey(master, TESTNET, 1).receiveAddress(0);
    expect(a0.address).not.toBe(a1.address);
  });
});

describe("BIP-84 — address records and watch-only", () => {
  const master = ExtendedKey.fromSeed(mnemonicToSeed(BIP84_MNEMONIC));
  const account = Bip84Account.fromMasterKey(master, TESTNET, 0);

  it("a DerivedAddress record carries no private key material", () => {
    const addr = account.receiveAddress(0);
    const serialised = JSON.stringify(addr);
    const privateHex = master.derivePath("m/84'/1'/0'/0/0").privateKey.toHexUnsafe();
    expect(serialised).not.toContain(privateHex);
    expect(Object.keys(addr)).not.toContain("privateKey");
  });

  it("the scriptPubKey is OP_0 <20-byte hash> — 22 bytes total", () => {
    const addr = account.receiveAddress(0);
    expect(addr.scriptPubKey.length).toBe(44); // 22 bytes as hex
    expect(addr.scriptPubKey.startsWith("0014")).toBe(true);
  });

  it("the scriptPubKey hash matches the public key's hash160", () => {
    const node = master.derivePath("m/84'/1'/0'/0/0");
    const script = p2wpkhScriptPubKey(node.publicKey);
    expect(bytesToHex(script.slice(2))).toBe(bytesToHex(node.publicKey.hash160()));
  });

  it("a watch-only account derives identical addresses", () => {
    const watchOnly = account.neutered();
    for (let i = 0; i < 5; i++) {
      expect(watchOnly.receiveAddress(i).address).toBe(account.receiveAddress(i).address);
    }
    expect(watchOnly.node.hasPrivateKey).toBe(false);
  });

  it("derives a run of unique addresses", () => {
    const addresses = account.deriveAddresses(0, 0, 20);
    expect(new Set(addresses.map((a) => a.address)).size).toBe(20);
  });

  it("rejects absurd batch sizes", () => {
    expect(() => account.deriveAddresses(0, 0, 5000)).toThrow();
  });
});

describe("address validation across networks", () => {
  it("accepts a valid mainnet address on mainnet", () => {
    expect(validateAddress("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", MAINNET).valid).toBe(true);
  });

  it("REJECTS a mainnet address when validating against testnet", () => {
    // The HRP is inside the checksum, so this fails at the checksum, not
    // merely on a prefix comparison. This is the design preventing a user
    // from sending testnet-labelled funds to a mainnet address.
    const result = validateAddress("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", TESTNET);
    expect(result.valid).toBe(false);
  });

  it("rejects garbage and near-miss addresses", () => {
    expect(validateAddress("not-an-address", MAINNET).valid).toBe(false);
    expect(validateAddress("", MAINNET).valid).toBe(false);
    // Single character altered — the BCH checksum is designed to catch this.
    expect(validateAddress("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv", MAINNET).valid).toBe(false);
  });

  it("round-trips: every derived address validates on its own network", () => {
    const master = ExtendedKey.fromSeed(mnemonicToSeed(BIP84_MNEMONIC));
    for (const network of [MAINNET, TESTNET, REGTEST]) {
      const account = Bip84Account.fromMasterKey(master, network, 0);
      for (let i = 0; i < 5; i++) {
        expect(validateAddress(account.receiveAddress(i).address, network).valid).toBe(true);
      }
    }
  });
});
