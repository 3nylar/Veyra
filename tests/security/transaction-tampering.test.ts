/**
 * ATTACK TESTS: transaction tampering.
 *
 * Spec §15 requires proof that a signature breaks when transaction data
 * changes. Each test below is an ATTACK — a specific modification an
 * adversary (or a buggy code path) might make to a signed transaction
 * between the user's approval and broadcast.
 *
 * Every one must fail verification. A test that passes here means an attacker
 * could alter that field without invalidating the user's authorisation.
 *
 * Threat model: the NETWORK ATTACKER and MALICIOUS RECIPIENT from
 * docs/THREAT-MODEL.md. Neither breaks any cryptography; both simply modify
 * bytes in flight and hope the signature still verifies.
 */
import { describe, it, expect } from "vitest";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../../core/transactions/transaction.js";
import { signTransaction, verifyTransaction, calculateFee, MAX_REASONABLE_FEE } from "../../core/signing/signer.js";
import { PrivateKey } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { p2wpkhScriptPubKey } from "../../core/addresses/bip84.js";
import { hexToBytes } from "../../core/crypto/bytes.js";

const ALICE = PrivateKey.fromHex("11".repeat(32));
const BOB = PublicKey.fromPrivateKey(PrivateKey.fromHex("22".repeat(32)));
const MALLORY = PublicKey.fromPrivateKey(PrivateKey.fromHex("33".repeat(32)));

const INPUT_VALUE = 100_000n;
const PAYMENT = 60_000n;
const CHANGE = 39_000n; // fee = 1000 sat

/** A standard signed 1-in, 2-out payment with change. */
function signedPayment(): Transaction {
  const unsigned = new Transaction(
    2,
    [new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
    [
      new TxOutput(PAYMENT, p2wpkhScriptPubKey(BOB)),
      new TxOutput(CHANGE, p2wpkhScriptPubKey(PublicKey.fromPrivateKey(ALICE))),
    ],
    0,
  );
  return signTransaction(unsigned, [{ value: INPUT_VALUE, privateKey: ALICE }]);
}

describe("baseline: a correctly signed transaction verifies", () => {
  const tx = signedPayment();

  it("verifies", () => {
    expect(verifyTransaction(tx, [INPUT_VALUE])).toBe(true);
  });

  it("has an empty scriptSig — native SegWit puts everything in the witness", () => {
    expect(tx.inputs[0]!.scriptSig.length).toBe(0);
  });

  it("has a 2-item witness: [signature+type, compressed pubkey]", () => {
    const witness = tx.inputs[0]!.witness;
    expect(witness.length).toBe(2);
    expect(witness[1]!.length).toBe(33);
    expect(witness[0]![witness[0]!.length - 1]).toBe(0x01); // SIGHASH_ALL
  });

  it("has the expected fee", () => {
    expect(calculateFee(tx, [INPUT_VALUE])).toBe(1000n);
  });

  it("round-trips through serialisation with the signature intact", () => {
    const reparsed = Transaction.fromHex(tx.toHex());
    expect(verifyTransaction(reparsed, [INPUT_VALUE])).toBe(true);
    expect(reparsed.txid()).toBe(tx.txid());
  });
});

describe("ATTACK: redirect the payment to a different recipient", () => {
  it("changing the destination invalidates the signature", () => {
    // The headline attack. Mallory intercepts the signed transaction and
    // swaps her script in for Bob's.
    const tx = signedPayment();
    const outputs = [...tx.outputs];
    outputs[0] = new TxOutput(PAYMENT, p2wpkhScriptPubKey(MALLORY));
    const tampered = new Transaction(tx.version, tx.inputs, outputs, tx.locktime);
    expect(verifyTransaction(tampered, [INPUT_VALUE])).toBe(false);
  });

  it("changing even ONE BYTE of the destination script invalidates it", () => {
    const tx = signedPayment();
    const script = Uint8Array.from(tx.outputs[0]!.scriptPubKey);
    script[script.length - 1] = script[script.length - 1]! ^ 0x01;
    const outputs = [...tx.outputs];
    outputs[0] = new TxOutput(PAYMENT, script);
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });
});

describe("ATTACK: change the amounts", () => {
  it("increasing the payment amount invalidates the signature", () => {
    const tx = signedPayment();
    const outputs = [...tx.outputs];
    outputs[0] = new TxOutput(PAYMENT + 1000n, tx.outputs[0]!.scriptPubKey);
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });

  it("a ONE SATOSHI change invalidates the signature", () => {
    const tx = signedPayment();
    const outputs = [...tx.outputs];
    outputs[0] = new TxOutput(PAYMENT + 1n, tx.outputs[0]!.scriptPubKey);
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });

  it("STEALING THE CHANGE invalidates the signature", () => {
    // Attacker reduces the change output and pockets the difference as fee
    // (miner-extractable). Must fail.
    const tx = signedPayment();
    const outputs = [...tx.outputs];
    outputs[1] = new TxOutput(1n, tx.outputs[1]!.scriptPubKey);
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });

  it("REDIRECTING THE CHANGE to the attacker invalidates the signature", () => {
    const tx = signedPayment();
    const outputs = [...tx.outputs];
    outputs[1] = new TxOutput(CHANGE, p2wpkhScriptPubKey(MALLORY));
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });
});

describe("ATTACK: alter the output set", () => {
  it("removing the change output invalidates the signature", () => {
    // Otherwise an attacker could delete the change output and let the whole
    // remainder go to the miner.
    const tx = signedPayment();
    const tampered = new Transaction(tx.version, tx.inputs, [tx.outputs[0]!], tx.locktime);
    expect(verifyTransaction(tampered, [INPUT_VALUE])).toBe(false);
  });

  it("appending an extra output invalidates the signature", () => {
    const tx = signedPayment();
    const outputs = [...tx.outputs, new TxOutput(1n, p2wpkhScriptPubKey(MALLORY))];
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });

  it("REORDERING outputs invalidates the signature", () => {
    // hashOutputs commits to order, not just contents.
    const tx = signedPayment();
    const outputs = [tx.outputs[1]!, tx.outputs[0]!];
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });
});

describe("ATTACK: alter the inputs", () => {
  it("changing which output is being spent invalidates the signature", () => {
    const tx = signedPayment();
    const inputs = [new TxInput({ txid: "cd".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF, tx.inputs[0]!.witness)];
    expect(verifyTransaction(new Transaction(tx.version, inputs, tx.outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });

  it("changing the vout index invalidates the signature", () => {
    const tx = signedPayment();
    const inputs = [new TxInput({ txid: tx.inputs[0]!.outpoint.txid, vout: 1 }, new Uint8Array(0), SEQUENCE_RBF, tx.inputs[0]!.witness)];
    expect(verifyTransaction(new Transaction(tx.version, inputs, tx.outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });

  it("changing the sequence invalidates the signature", () => {
    const tx = signedPayment();
    const inputs = [new TxInput(tx.inputs[0]!.outpoint, new Uint8Array(0), 0xffffffff, tx.inputs[0]!.witness)];
    expect(verifyTransaction(new Transaction(tx.version, inputs, tx.outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });
});

describe("ATTACK: alter transaction-level fields", () => {
  it("changing the version invalidates the signature", () => {
    const tx = signedPayment();
    expect(verifyTransaction(new Transaction(1, tx.inputs, tx.outputs, tx.locktime), [INPUT_VALUE])).toBe(false);
  });

  it("changing the locktime invalidates the signature", () => {
    const tx = signedPayment();
    expect(verifyTransaction(new Transaction(tx.version, tx.inputs, tx.outputs, 500_000), [INPUT_VALUE])).toBe(false);
  });
});

describe("ATTACK: lie about the input value (the BIP-143 fix)", () => {
  it("verification FAILS if the claimed input value differs from the signed one", () => {
    // Pre-SegWit this attack worked: the value was not signed, so a malicious
    // node could understate an input's value and the difference silently
    // became fee. BIP-143 puts the amount in the preimage.
    const tx = signedPayment();
    expect(verifyTransaction(tx, [INPUT_VALUE])).toBe(true);
    expect(verifyTransaction(tx, [INPUT_VALUE + 1n])).toBe(false);
    expect(verifyTransaction(tx, [10_000_000n])).toBe(false);
    expect(verifyTransaction(tx, [1n])).toBe(false);
  });
});

describe("ATTACK: forge or swap the witness", () => {
  it("substituting the attacker's public key invalidates the signature", () => {
    const tx = signedPayment();
    const witness = [tx.inputs[0]!.witness[0]!, MALLORY.toBytes()];
    expect(verifyTransaction(tx.withInput(0, tx.inputs[0]!.withWitness(witness)), [INPUT_VALUE])).toBe(false);
  });

  it("a signature from a different key does not verify", () => {
    const tx = signedPayment();
    const other = signTransaction(
      new Transaction(2, [new TxInput({ txid: "ab".repeat(32), vout: 0 })],
        [new TxOutput(PAYMENT, p2wpkhScriptPubKey(BOB)), new TxOutput(CHANGE, p2wpkhScriptPubKey(MALLORY))], 0),
      [{ value: INPUT_VALUE, privateKey: PrivateKey.fromHex("44".repeat(32)) }],
    );
    const swapped = tx.withInput(0, tx.inputs[0]!.withWitness(other.inputs[0]!.witness));
    expect(verifyTransaction(swapped, [INPUT_VALUE])).toBe(false);
  });

  it("an empty or malformed witness fails verification rather than throwing", () => {
    const tx = signedPayment();
    expect(verifyTransaction(tx.withInput(0, tx.inputs[0]!.withWitness([])), [INPUT_VALUE])).toBe(false);
    expect(verifyTransaction(tx.withInput(0, tx.inputs[0]!.withWitness([new Uint8Array(5)])), [INPUT_VALUE])).toBe(false);
    expect(verifyTransaction(
      tx.withInput(0, tx.inputs[0]!.withWitness([new Uint8Array(71), new Uint8Array(33)])),
      [INPUT_VALUE],
    )).toBe(false);
  });

  it("corrupting any byte of the signature invalidates it", () => {
    const tx = signedPayment();
    const sig = tx.inputs[0]!.witness[0]!;
    let broken = 0;
    for (let i = 0; i < sig.length; i++) {
      const mutated = Uint8Array.from(sig);
      mutated[i] = mutated[i]! ^ 0xff;
      const tampered = tx.withInput(0, tx.inputs[0]!.withWitness([mutated, tx.inputs[0]!.witness[1]!]));
      if (!verifyTransaction(tampered, [INPUT_VALUE])) broken++;
    }
    expect(broken).toBe(sig.length); // every single byte matters
  });
});

describe("SEGWIT: witness data does not affect the txid", () => {
  it("the txid is identical before and after signing", () => {
    // This is the malleability fix. The txid is stable from creation, which
    // is what makes chained unconfirmed transactions (and Lightning) safe.
    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(PAYMENT, p2wpkhScriptPubKey(BOB)), new TxOutput(CHANGE, p2wpkhScriptPubKey(PublicKey.fromPrivateKey(ALICE)))],
      0,
    );
    const signed = signTransaction(unsigned, [{ value: INPUT_VALUE, privateKey: ALICE }]);
    expect(signed.txid()).toBe(unsigned.txid());
  });

  it("but the WTXID does change, since it commits to the witness", () => {
    const tx = signedPayment();
    expect(tx.wtxid()).not.toBe(tx.txid());
  });

  it("vsize is smaller than raw size, thanks to the witness discount", () => {
    const tx = signedPayment();
    expect(tx.vsize()).toBeLessThan(tx.serialize().length);
    expect(tx.weight()).toBe(tx.serializeLegacy().length * 3 + tx.serialize().length);
  });
});

describe("§16: spending more than you have is refused BEFORE signing", () => {
  const script = p2wpkhScriptPubKey(BOB);

  it("refuses when outputs exceed inputs", () => {
    const tx = new Transaction(2, [new TxInput({ txid: "ab".repeat(32), vout: 0 })], [new TxOutput(200_000n, script)], 0);
    expect(() => signTransaction(tx, [{ value: INPUT_VALUE, privateKey: ALICE }]))
      .toThrow(/insufficient funds/);
  });

  it("refuses an absurd implied fee (a forgotten change output)", () => {
    // 100,000 sat in, 1 sat out -> 99,999 sat fee. Almost certainly a bug,
    // and irreversible if broadcast.
    const tx = new Transaction(2, [new TxInput({ txid: "ab".repeat(32), vout: 0 })], [new TxOutput(1n, script)], 0);
    expect(() => signTransaction(tx, [{ value: 50_000_000n, privateKey: ALICE }]))
      .toThrow(/exceeds the safety limit/);
  });

  it("refuses a transaction with no outputs", () => {
    const tx = new Transaction(2, [new TxInput({ txid: "ab".repeat(32), vout: 0 })], [], 0);
    expect(() => signTransaction(tx, [{ value: INPUT_VALUE, privateKey: ALICE }])).toThrow(/no outputs/);
  });

  it("refuses when the signing-data count does not match the input count", () => {
    const tx = new Transaction(2, [new TxInput({ txid: "ab".repeat(32), vout: 0 })], [new TxOutput(1000n, script)], 0);
    expect(() => signTransaction(tx, [])).toThrow(/expected signing data/);
    expect(() => signTransaction(tx, [
      { value: INPUT_VALUE, privateKey: ALICE }, { value: INPUT_VALUE, privateKey: ALICE },
    ])).toThrow(/expected signing data/);
  });

  it("rejects negative and over-supply values", () => {
    const tx = new Transaction(2, [new TxInput({ txid: "ab".repeat(32), vout: 0 })], [new TxOutput(100n, script)], 0);
    expect(() => signTransaction(tx, [{ value: -1n, privateKey: ALICE }])).toThrow();
    expect(() => new TxOutput(-1n, script)).toThrow(/negative/);
    expect(() => new TxOutput(2_100_000_000_000_001n, script)).toThrow(/money supply/);
  });
});

describe("multi-input transactions", () => {
  it("signs and verifies with several inputs and different keys", () => {
    const keys = [ALICE, PrivateKey.fromHex("55".repeat(32)), PrivateKey.fromHex("66".repeat(32))];
    const values = [50_000n, 30_000n, 25_000n];
    const unsigned = new Transaction(
      2,
      // Two hex chars repeated 32 times = 64 chars. The first attempt used a
      // single char repeated 32 times and the validator correctly rejected
      // it -- a reminder that the txid length check is load-bearing.
      keys.map((_, i) => new TxInput({ txid: (i + 10).toString(16).padStart(2, "0").repeat(32), vout: i })),
      [new TxOutput(100_000n, p2wpkhScriptPubKey(BOB)), new TxOutput(4_000n, p2wpkhScriptPubKey(PublicKey.fromPrivateKey(ALICE)))],
      0,
    );
    const signed = signTransaction(unsigned, keys.map((privateKey, i) => ({ value: values[i]!, privateKey })));
    expect(verifyTransaction(signed, values)).toBe(true);
    expect(calculateFee(signed, values)).toBe(1000n);
  });

  it("each input gets its own distinct signature", () => {
    const keys = [ALICE, PrivateKey.fromHex("55".repeat(32))];
    const values = [50_000n, 51_000n];
    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 }), new TxInput({ txid: "bb".repeat(32), vout: 1 })],
      [new TxOutput(100_000n, p2wpkhScriptPubKey(BOB))],
      0,
    );
    const signed = signTransaction(unsigned, keys.map((privateKey, i) => ({ value: values[i]!, privateKey })));
    expect(Buffer.from(signed.inputs[0]!.witness[0]!).toString("hex"))
      .not.toBe(Buffer.from(signed.inputs[1]!.witness[0]!).toString("hex"));
  });

  it("tampering with ONE input's witness fails the whole verification", () => {
    const keys = [ALICE, PrivateKey.fromHex("55".repeat(32))];
    const values = [50_000n, 51_000n];
    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 }), new TxInput({ txid: "bb".repeat(32), vout: 1 })],
      [new TxOutput(100_000n, p2wpkhScriptPubKey(BOB))],
      0,
    );
    const signed = signTransaction(unsigned, keys.map((privateKey, i) => ({ value: values[i]!, privateKey })));
    const broken = signed.withInput(1, signed.inputs[1]!.withWitness([signed.inputs[0]!.witness[0]!, signed.inputs[1]!.witness[1]!]));
    expect(verifyTransaction(broken, values)).toBe(false);
  });
});
