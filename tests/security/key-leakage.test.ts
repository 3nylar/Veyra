/**
 * ATTACK TESTS: private key and seed exposure.
 *
 * Threat model (docs/THREAT-MODEL.md): the LOCAL ATTACKER can read logs,
 * crash dumps, serialised application state, and error reports. The
 * NETWORK/API ATTACKER can read whatever the API serialises into a response.
 *
 * Neither attacker breaks any cryptography. They simply read a key that the
 * application handed them by accident. Historically this is a far more common
 * way for wallets to lose funds than any cryptographic weakness, so these
 * tests attack the object's *serialisation surface* directly.
 *
 * Each test below is an attack. Each must fail to find key material.
 */
import { describe, it, expect } from "vitest";
import { inspect } from "node:util";
import { PrivateKey } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";

/** A key whose hex is a distinctive marker we can grep any output for. */
function markerKey(): { key: PrivateKey; hex: string } {
  const hex = "c0ffee".padEnd(64, "a");
  return { key: PrivateKey.fromHex(hex), hex };
}

describe("ATTACK: extract the private key via accidental stringification", () => {
  it("String(key) does not leak", () => {
    const { key, hex } = markerKey();
    expect(String(key)).not.toContain(hex);
    expect(String(key)).toBe("PrivateKey<redacted>");
  });

  it("template interpolation does not leak", () => {
    const { key, hex } = markerKey();
    expect(`key is ${key}`).not.toContain(hex);
  });

  it("string concatenation does not leak", () => {
    const { key, hex } = markerKey();
    expect("" + key).not.toContain(hex);
  });

  it("JSON.stringify does not leak — the classic API-response leak", () => {
    const { key, hex } = markerKey();
    expect(JSON.stringify(key)).not.toContain(hex);
    expect(JSON.stringify({ wallet: { signingKey: key } })).not.toContain(hex);
    expect(JSON.stringify([key, key])).not.toContain(hex);
  });

  it("util.inspect / console.log does not leak", () => {
    const { key, hex } = markerKey();
    expect(inspect(key)).not.toContain(hex);
    expect(inspect({ key }, { depth: 10 })).not.toContain(hex);
    // Even with showHidden, which deliberately digs for internal slots.
    expect(inspect(key, { showHidden: true, depth: null })).not.toContain(hex);
  });

  it("Object.keys / entries / getOwnPropertyNames expose no key material", () => {
    const { key, hex } = markerKey();
    expect(Object.keys(key)).toEqual([]);
    expect(JSON.stringify(Object.entries(key))).not.toContain(hex);
    expect(Object.getOwnPropertyNames(key).join(",")).not.toContain(hex);
    // #bytes is a true private field: it is not reachable reflectively at all.
    expect(JSON.stringify(Object.getOwnPropertyDescriptors(key))).not.toContain(hex);
  });

  it("structuredClone-style spread copies nothing sensitive", () => {
    const { key, hex } = markerKey();
    expect(JSON.stringify({ ...key })).not.toContain(hex);
  });
});

describe("ATTACK: extract key material from thrown errors", () => {
  const secretHex = "b" .repeat(64);

  it("an out-of-range key does not appear in the rejection message", () => {
    // Attacker-controlled input reaching an error path must not be echoed;
    // otherwise a log aggregator becomes a key database.
    const overflow = "ff".repeat(32);
    try {
      PrivateKey.fromHex(overflow);
      expect.unreachable();
    } catch (e) {
      const err = e as Error;
      expect(err.message).not.toContain(overflow);
      expect(`${err.stack}`).not.toContain(overflow);
    }
  });

  it("a malformed-hex error does not echo the input", () => {
    const bad = "zz" + secretHex.slice(2);
    try {
      PrivateKey.fromHex(bad);
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain(bad);
    }
  });

  it("errors carry a stable machine-readable code instead of leaky prose", () => {
    try {
      PrivateKey.fromBytes(new Uint8Array(32));
      expect.unreachable();
    } catch (e) {
      expect((e as { code: string }).code).toBe("INVALID_PRIVATE_KEY");
    }
  });
});

describe("ATTACK: recover the private key from public data", () => {
  it("the public key's serialisation contains no private material", () => {
    const { key, hex } = markerKey();
    const pub = PublicKey.fromPrivateKey(key);
    expect(pub.toHex()).not.toContain(hex);
    expect(JSON.stringify(pub)).not.toContain(hex);
    expect(inspect(pub, { depth: null, showHidden: true })).not.toContain(hex);
  });

  it("the hash160 (address payload) contains no private material", () => {
    const { key, hex } = markerKey();
    const h = PublicKey.fromPrivateKey(key).hash160();
    expect(Buffer.from(h).toString("hex")).not.toContain(hex.slice(0, 12));
  });

  it("two different private keys never collide onto one public key", () => {
    const a = PublicKey.fromPrivateKey(PrivateKey.fromBigInt(1n)).toHex();
    const b = PublicKey.fromPrivateKey(PrivateKey.fromBigInt(2n)).toHex();
    expect(a).not.toBe(b);
  });
});

describe("ATTACK: read key material out of memory after use", () => {
  it("destroy() zeroes the key so a later heap dump finds nothing", () => {
    const key = PrivateKey.fromHex("a".repeat(64));
    const before = key.toBytes();
    expect(before.some((b) => b !== 0)).toBe(true);
    key.destroy();
    expect(key.toBytes().every((b) => b === 0)).toBe(true);
  });

  it("the caller's copy is independent — wiping one does not silently break the other", () => {
    // Documents the limitation honestly: toBytes() hands out a copy, so the
    // CALLER owns wiping it. Anything that calls toBytes() must clean up.
    const key = PrivateKey.fromHex("a".repeat(64));
    const copy = key.toBytes();
    key.destroy();
    expect(copy.every((b) => b === 0)).toBe(false); // the copy survives
    copy.fill(0);
    expect(copy.every((b) => b === 0)).toBe(true);
  });
});

describe("ATTACK: force a weak key through the generation path", () => {
  it("cannot inject a weak source into generateWalletEntropy", async () => {
    const mod = await import("../../core/crypto/entropy.js");
    // No parameter exists to pass a rigged generator through.
    expect(mod.generateWalletEntropy.length).toBe(0);
  });

  it("a rigged source still cannot produce an out-of-range key", () => {
    const rigged = (out: Uint8Array) => { out.fill(0); out[31] = 1; };
    expect(PrivateKey.generate(rigged).toBigInt()).toBe(1n);
  });
});
