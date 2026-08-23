/**
 * REPLACE-BY-FEE (BIP-125)
 *
 * A fee bump is not an edit. Bitcoin transactions are immutable once signed —
 * a replacement is an entirely new transaction spending the SAME inputs, which
 * is what makes the two mutually exclusive.
 *
 * The rules tested here are the ones a network node enforces. Violating any of
 * them produces a rejection with a confusing message at broadcast time, so
 * they are checked locally where the error can be clear.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { Wallet, WalletError } from "../../core/wallet/wallet.js";
import { MemoryChainSource } from "../../core/chain/memory.js";
import { REGTEST } from "../../core/bitcoin/networks.js";
import { verifyTransaction } from "../../core/signing/signer.js";
import { SEQUENCE_RBF, Transaction } from "../../core/transactions/transaction.js";
import { DUST_THRESHOLD_P2WPKH } from "../../core/utxo/utxo.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const txid = (n: number) => n.toString(16).padStart(8, "0").repeat(8).slice(0, 64);

let wallet: Wallet;
let chain: MemoryChainSource;
let recipient: string;

beforeEach(async () => {
  wallet = Wallet.restore(MNEMONIC, REGTEST);
  chain = new MemoryChainSource("regtest", 500);
  const addresses = wallet.receiveAddresses(3);
  chain.fund(addresses[0]!.address, txid(1), 0, 5_000_000n, 6);
  await wallet.sync(chain);
  recipient = Wallet.restore(MNEMONIC, REGTEST, "recipient").currentReceiveAddress().address;
});

/** Send and broadcast, so the transaction becomes replaceable. */
async function sendAndBroadcast(amount = 1_000_000n, feeRate = 2) {
  const prepared = wallet.send({ to: recipient, amount, feeRate });
  await wallet.broadcast(chain, prepared);
  return prepared;
}

describe("the original must be replaceable at all", () => {
  it("every Veyra transaction signals RBF (rule 1)", async () => {
    const prepared = await sendAndBroadcast();
    for (const input of prepared.transaction.inputs) {
      // Below 0xfffffffe means replaceable.
      expect(input.sequence).toBe(SEQUENCE_RBF);
      expect(input.sequence).toBeLessThan(0xfffffffe);
    }
  });

  it("only broadcast transactions can be bumped", async () => {
    // A prepared-but-unsent transaction should be cancelled and rebuilt, not
    // replaced — nothing is on the network to replace.
    const prepared = wallet.send({ to: recipient, amount: 1_000_000n, feeRate: 2 });
    expect(() => wallet.bumpFee(prepared.txid, 10)).toThrow(/no broadcast transaction/);
  });

  it("an unknown txid is refused with an explanation", () => {
    expect(() => wallet.bumpFee(txid(99), 10)).toThrow(/not persisted across restarts/);
  });
});

describe("the replacement spends the SAME inputs", () => {
  it("input set is identical — that is what makes them mutually exclusive", async () => {
    const original = await sendAndBroadcast();
    const bumped = wallet.bumpFee(original.txid, 10);

    const key = (t: Transaction) =>
      t.inputs.map((i) => `${i.outpoint.txid}:${i.outpoint.vout}`).sort().join(",");
    expect(key(bumped.transaction)).toBe(key(original.transaction));
  });

  it("adds NO new inputs (rule 2: no new unconfirmed inputs)", async () => {
    const original = await sendAndBroadcast();
    const bumped = wallet.bumpFee(original.txid, 10);
    expect(bumped.transaction.inputs.length).toBe(original.transaction.inputs.length);
  });

  it("produces a DIFFERENT txid — it is a new transaction, not an edit", async () => {
    const original = await sendAndBroadcast();
    const bumped = wallet.bumpFee(original.txid, 10);
    expect(bumped.txid).not.toBe(original.txid);
    expect(bumped.replaces).toBe(original.txid);
  });
});

describe("the recipient is protected", () => {
  it("the payment amount is UNCHANGED", async () => {
    // A bump that quietly reduced the payment would be a different
    // transaction pretending to be the same one.
    const original = await sendAndBroadcast(1_000_000n, 2);
    const bumped = wallet.bumpFee(original.txid, 20);
    expect(bumped.amount).toBe(1_000_000n);
    expect(bumped.transaction.outputs[0]!.value).toBe(1_000_000n);
  });

  it("the recipient's script is byte-identical", async () => {
    const original = await sendAndBroadcast();
    const bumped = wallet.bumpFee(original.txid, 15);
    expect(Buffer.from(bumped.transaction.outputs[0]!.scriptPubKey).toString("hex"))
      .toBe(Buffer.from(original.transaction.outputs[0]!.scriptPubKey).toString("hex"));
  });

  it("the extra fee comes out of CHANGE, not the payment", async () => {
    const original = await sendAndBroadcast(1_000_000n, 2);
    const bumped = wallet.bumpFee(original.txid, 20);

    const increase = bumped.fee - original.fee;
    const changeReduction = original.change - bumped.change;
    expect(increase).toBeGreaterThan(0n);
    expect(changeReduction).toBe(increase);
  });
});

describe("BIP-125 fee rules", () => {
  it("rule 3: the absolute fee must exceed the original's", async () => {
    const original = await sendAndBroadcast(1_000_000n, 2);
    const bumped = wallet.bumpFee(original.txid, 10);
    expect(bumped.fee).toBeGreaterThan(original.fee);
  });

  it("rule 4: the INCREASE covers the replacement's own bandwidth", async () => {
    // Otherwise a node relays a second copy for free, and an attacker could
    // flood the network with endless one-satoshi bumps.
    const original = await sendAndBroadcast(1_000_000n, 2);
    const bumped = wallet.bumpFee(original.txid, 3);

    const increase = bumped.fee - original.fee;
    // At least 1 sat/vB of the replacement's size.
    expect(increase).toBeGreaterThanOrEqual(BigInt(bumped.vsize));
  });

  it("a barely-higher rate is still raised to meet rule 4", async () => {
    // Requesting 2.01 sat/vB over 2 would fail rule 4 on its own. The
    // implementation raises it to the minimum valid replacement rather than
    // building something the network will reject.
    const original = await sendAndBroadcast(1_000_000n, 2);
    const bumped = wallet.bumpFee(original.txid, 2.01);
    expect(bumped.fee - original.fee).toBeGreaterThanOrEqual(BigInt(bumped.vsize));
  });

  it("refuses a rate at or below the original", async () => {
    const original = await sendAndBroadcast(1_000_000n, 5);
    expect(() => wallet.bumpFee(original.txid, 5)).toThrow(/must exceed the original/);
    expect(() => wallet.bumpFee(original.txid, 1)).toThrow(/must exceed the original/);
  });

  it("refuses when change cannot cover the increase", async () => {
    // Spend nearly everything, leaving almost no change to draw from.
    const spendable = wallet.balance().spendable;
    const original = wallet.send({ to: recipient, amount: spendable - 3_000n, feeRate: 2 });
    await wallet.broadcast(chain, original);

    // Reducing the payment is never done automatically.
    expect(() => wallet.bumpFee(original.txid, 500)).toThrow(/inputs only cover/);
  });
});

describe("change handling", () => {
  it("DROPS the change output when it would fall below dust", async () => {
    // A dust output would not relay, so the remainder must become fee. That
    // is the only valid option, not a bug.
    const spendable = wallet.balance().spendable;
    const original = wallet.send({ to: recipient, amount: spendable - 20_000n, feeRate: 2 });
    await wallet.broadcast(chain, original);
    expect(original.change).toBeGreaterThan(0n);

    // Bump hard enough that the remaining change goes under 294 sat.
    const inputTotal = original.inputs.reduce((sum, u) => sum + u.value, 0n);
    const headroom = inputTotal - original.amount;
    const rateThatEatsChange = Number(headroom) / original.vsize - 0.5;

    const bumped = wallet.bumpFee(original.txid, rateThatEatsChange);
    if (bumped.change === 0n) {
      expect(bumped.transaction.outputs.length).toBe(1);
      expect(bumped.changeAddress).toBeNull();
    } else {
      expect(bumped.change).toBeGreaterThanOrEqual(DUST_THRESHOLD_P2WPKH);
    }
  });

  it("REUSES the original change script rather than deriving a fresh address", async () => {
    // The two transactions are mutually exclusive, so only one can ever
    // confirm. A fresh address would burn a gap-limit slot for an output that
    // may never exist.
    const original = await sendAndBroadcast(1_000_000n, 2);
    const bumped = wallet.bumpFee(original.txid, 8);
    expect(bumped.change).toBeGreaterThan(0n);
    expect(Buffer.from(bumped.transaction.outputs[1]!.scriptPubKey).toString("hex"))
      .toBe(Buffer.from(original.transaction.outputs[1]!.scriptPubKey).toString("hex"));
    expect(bumped.changeAddress).toBe(original.changeAddress);
  });

  it("change never falls below dust while remaining an output", async () => {
    for (const rate of [3, 5, 10, 25, 60]) {
      const wallet2 = Wallet.restore(MNEMONIC, REGTEST);
      const chain2 = new MemoryChainSource("regtest", 500);
      chain2.fund(wallet2.receiveAddresses(1)[0]!.address, txid(2), 0, 3_000_000n, 6);
      await wallet2.sync(chain2);

      const original = wallet2.send({ to: recipient, amount: 1_000_000n, feeRate: 2 });
      await wallet2.broadcast(chain2, original);
      const bumped = wallet2.bumpFee(original.txid, rate);
      if (bumped.change > 0n) expect(bumped.change).toBeGreaterThanOrEqual(DUST_THRESHOLD_P2WPKH);
    }
  });
});

describe("the replacement is a valid transaction", () => {
  it("verifies against its inputs", async () => {
    const original = await sendAndBroadcast();
    const bumped = wallet.bumpFee(original.txid, 12);
    expect(verifyTransaction(bumped.transaction, bumped.inputs.map((u) => u.value))).toBe(true);
  });

  it("round-trips through serialisation", async () => {
    const original = await sendAndBroadcast();
    const bumped = wallet.bumpFee(original.txid, 12);
    const reparsed = Transaction.fromHex(bumped.hex);
    expect(reparsed.txid()).toBe(bumped.txid);
    expect(verifyTransaction(reparsed, bumped.inputs.map((u) => u.value))).toBe(true);
  });

  it("conserves value: inputs = payment + change + fee", async () => {
    const original = await sendAndBroadcast();
    const bumped = wallet.bumpFee(original.txid, 15);
    const inputTotal = bumped.inputs.reduce((sum, u) => sum + u.value, 0n);
    expect(bumped.amount + bumped.change + bumped.fee).toBe(inputTotal);
  });

  it("still signals RBF, so it can be bumped again", async () => {
    const original = await sendAndBroadcast(1_000_000n, 2);
    const bumped = wallet.bumpFee(original.txid, 5);
    for (const input of bumped.transaction.inputs) {
      expect(input.sequence).toBe(SEQUENCE_RBF);
    }
  });
});

describe("superseding", () => {
  it("broadcasting a replacement retires the original", async () => {
    const original = await sendAndBroadcast(1_000_000n, 2);
    expect(wallet.replaceable.some((t) => t.txid === original.txid)).toBe(true);

    const bumped = wallet.bumpFee(original.txid, 10);
    await wallet.broadcast(chain, bumped);

    // Building a second bump on a transaction the network has discarded
    // would produce something that can never confirm.
    expect(wallet.replaceable.some((t) => t.txid === original.txid)).toBe(false);
    expect(() => wallet.bumpFee(original.txid, 20)).toThrow(/no broadcast transaction/);
  });

  it("the replacement itself becomes bumpable", async () => {
    const original = await sendAndBroadcast(1_000_000n, 2);
    const first = wallet.bumpFee(original.txid, 6);
    await wallet.broadcast(chain, first);

    const second = wallet.bumpFee(first.txid, 20);
    expect(second.fee).toBeGreaterThan(first.fee);
    expect(second.replaces).toBe(first.txid);
  });

  it("replaceable lists what can still be bumped", async () => {
    const original = await sendAndBroadcast(1_000_000n, 2);
    const list = wallet.replaceable;
    expect(list.length).toBe(1);
    expect(list[0]!.txid).toBe(original.txid);
    expect(list[0]!.fee).toBe(original.fee);
  });
});
