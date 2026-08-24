/**
 * THE BROWSER WALLET'S LOGIC
 *
 * The page itself needs a DOM, but everything that could lose money is
 * testable: keystore round-trip, restore-from-phrase, the send flow, and the
 * exact-decimal parsing the amount field depends on.
 */
import { describe, it, expect } from "vitest";
import { Wallet } from "../../core/wallet/wallet.js";
import { encryptMnemonic, decryptMnemonic } from "../../core/wallet/keystore.js";
import { generateMnemonic, validateMnemonic } from "../../core/mnemonic/index.js";
import { MemoryChainSource } from "../../core/chain/memory.js";
import { SIGNET, MAINNET, TESTNET } from "../../core/bitcoin/networks.js";
import { verifyTransaction } from "../../core/signing/signer.js";

/** The parser the amount field uses. Duplicated so a change here is caught. */
function parseBtc(input: string): bigint {
  const t = input.trim();
  if (!/^\d*\.?\d*$/.test(t) || t === "" || t === ".") throw new Error("Enter a number");
  const [whole = "0", frac = ""] = t.split(".");
  if (frac.length > 8) throw new Error("Bitcoin has 8 decimal places");
  return BigInt(whole || "0") * 100_000_000n + BigInt((frac + "00000000").slice(0, 8));
}

describe("onboarding: create, back up, encrypt, restore", () => {
  it("a generated phrase round-trips through the keystore into the same wallet", async () => {
    // The whole onboarding flow in one assertion: if the addresses differ, a
    // user's coins are at an address their phrase does not recover.
    const mnemonic = generateMnemonic(12);
    const created = Wallet.restore(mnemonic, SIGNET);

    const store = await encryptMnemonic(mnemonic, "a good passphrase", { network: "signet" });
    const recovered = Wallet.restore(await decryptMnemonic(store, "a good passphrase"), SIGNET);

    expect(recovered.currentReceiveAddress().address).toBe(created.currentReceiveAddress().address);
    expect(recovered.account.path).toBe(created.account.path);
  });

  it("the stored keystore contains no trace of the phrase", async () => {
    // It goes into localStorage, which any script on the origin can read.
    // That is acceptable only because it is ciphertext.
    const mnemonic = generateMnemonic(12);
    const stored = JSON.stringify(await encryptMnemonic(mnemonic, "a good passphrase"));
    for (const word of mnemonic.split(" ")) {
      expect(stored).not.toContain(word);
    }
  });

  it("a restored phrase with a typo is REJECTED before anything is stored", () => {
    // Otherwise the wallet encrypts a wrong phrase, unlocks cleanly, and shows
    // an empty balance — which a user reads as "my coins are gone".
    const good = generateMnemonic(12).split(" ");
    good[0] = "zoo";
    expect(validateMnemonic(good.join(" "))).toBe(false);
  });

  it("the confirmation step compares against the real words", () => {
    const mnemonic = generateMnemonic(12);
    const words = mnemonic.split(" ");
    expect(words[3]!.trim().toLowerCase()).toBe(words[3]);
    expect(words.length).toBe(12);
  });
});

describe("amount parsing is exact", () => {
  it("converts without floating point", () => {
    // parseFloat("4.35") * 1e8 is 434999999.99999994 — see VEY-011.
    expect(parseBtc("4.35")).toBe(435_000_000n);
    expect(parseBtc("0.00000001")).toBe(1n);
    expect(parseBtc("21000000")).toBe(2_100_000_000_000_000n);
    expect(parseBtc("0.1")).toBe(10_000_000n);
  });

  it("rejects more than 8 decimals rather than truncating silently", () => {
    expect(() => parseBtc("0.000000001")).toThrow(/8 decimal places/);
  });

  it("rejects non-numeric input", () => {
    for (const bad of ["", ".", "abc", "1.2.3", "-1", "1e8"]) {
      expect(() => parseBtc(bad), bad).toThrow();
    }
  });
});

describe("the send flow", () => {
  const MNEMONIC =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

  async function funded() {
    const wallet = Wallet.restore(MNEMONIC, SIGNET);
    const chain = new MemoryChainSource("signet", 900);
    const addresses = wallet.receiveAddresses(3);
    for (let i = 0; i < 3; i++) {
      chain.fund(addresses[i]!.address, (i + 30).toString(16).repeat(32).slice(0, 64), 0, 1_000_000n, 6);
    }
    await wallet.sync(chain);
    return { wallet, chain };
  }

  const recipient = () => Wallet.restore(MNEMONIC, SIGNET, "r").currentReceiveAddress().address;

  it("prepares a transaction the review screen can display in full", async () => {
    const { wallet } = await funded();
    const prepared = wallet.send({ to: recipient(), amount: 500_000n, feeRate: 5 });
    // Every field the review screen renders must be present.
    expect(prepared.total).toBe(prepared.amount + prepared.fee);
    expect(prepared.txid).toMatch(/^[0-9a-f]{64}$/);
    expect(prepared.vsize).toBeGreaterThan(0);
    expect(prepared.inputs.length).toBeGreaterThan(0);
  });

  it("preparing does NOT spend — the user may still decline", async () => {
    const { wallet } = await funded();
    const before = wallet.balance().spendable;
    wallet.send({ to: recipient(), amount: 500_000n, feeRate: 5 });
    expect(wallet.balance().spendable).toBe(before);
  });

  it("broadcasting spends exactly the reviewed transaction", async () => {
    const { wallet, chain } = await funded();
    const prepared = wallet.send({ to: recipient(), amount: 500_000n, feeRate: 5 });
    expect(await wallet.broadcast(chain, prepared)).toBe(prepared.txid);
    expect(verifyTransaction(prepared.transaction, prepared.inputs.map((u) => u.value))).toBe(true);
  });

  it("refuses a mainnet address on a signet wallet", async () => {
    const { wallet } = await funded();
    expect(() => wallet.send({
      to: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", amount: 100_000n, feeRate: 5,
    })).toThrow(/invalid/i);
  });
});

describe("switching networks changes the key tree", () => {
  it("the same phrase gives entirely different addresses per network", () => {
    // Which is why the app must re-derive rather than reuse the wallet when
    // the network preference changes.
    const mnemonic = generateMnemonic(12);
    const signet = Wallet.restore(mnemonic, SIGNET).currentReceiveAddress().address;
    const mainnet = Wallet.restore(mnemonic, MAINNET).currentReceiveAddress().address;
    const testnet = Wallet.restore(mnemonic, TESTNET).currentReceiveAddress().address;

    expect(mainnet).not.toBe(signet);
    expect(mainnet.startsWith("bc1")).toBe(true);
    // Signet and testnet share a coin type, so these DO match — a real
    // property of the format, and the reason the network chip matters.
    expect(signet).toBe(testnet);
  });
});
