/**
 * FUZZ TESTS: the transaction parser (spec §34).
 *
 * `Transaction.fromBytes` consumes bytes that arrive from the network, from a
 * peer, or from an API request body. It is the largest untrusted-input
 * surface in the codebase.
 *
 * The property under test is simple and absolute:
 *
 *     For ANY input, the parser either returns a valid Transaction
 *     or throws a SerializationError. It never hangs, never allocates
 *     unboundedly, and never returns a partially-constructed object.
 *
 * A crash on malformed input is a denial-of-service bug. A silent
 * mis-parse — accepting bytes and returning a transaction that means
 * something other than what was sent — is far worse, and is why the
 * round-trip property below matters as much as the no-crash property.
 */
import { describe, it, expect } from "vitest";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../../core/transactions/transaction.js";
import { VeyraError } from "../../core/errors/index.js";
import { hexToBytes, bytesToHex } from "../../core/crypto/bytes.js";

/**
 * A parse attempt either succeeds or throws a VeyraError. Anything else — a
 * TypeError, a RangeError, an OOM — is a bug in the parser.
 */
function parseIsSafe(data: Uint8Array): { ok: boolean; unexpected?: string } {
  try {
    Transaction.fromBytes(data);
    return { ok: true };
  } catch (error) {
    if (error instanceof VeyraError) return { ok: true };
    return { ok: false, unexpected: `${(error as Error).name}: ${(error as Error).message}` };
  }
}

/** A known-good SegWit transaction to use as a mutation base. */
function validTransaction(): Transaction {
  return new Transaction(
    2,
    [
      new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF, [
        new Uint8Array(71).fill(0x30),
        new Uint8Array(33).fill(0x02),
      ]),
      new TxInput({ txid: "cd".repeat(32), vout: 1 }, new Uint8Array(0), SEQUENCE_RBF, [
        new Uint8Array(72).fill(0x30),
        new Uint8Array(33).fill(0x03),
      ]),
    ],
    [
      new TxOutput(50_000n, hexToBytes("0014" + "11".repeat(20))),
      new TxOutput(25_000n, hexToBytes("0014" + "22".repeat(20))),
    ],
    500_000,
  );
}

describe("parser never crashes on structurally invalid input", () => {
  it("handles empty and tiny inputs", () => {
    for (let length = 0; length < 20; length++) {
      const result = parseIsSafe(new Uint8Array(length));
      expect(result.unexpected).toBeUndefined();
    }
  });

  it("handles all-zero and all-0xFF buffers of many sizes", () => {
    for (const length of [1, 4, 10, 64, 100, 1000]) {
      for (const fill of [0x00, 0xff, 0x7f, 0x80]) {
        const result = parseIsSafe(new Uint8Array(length).fill(fill));
        expect(result.unexpected).toBeUndefined();
      }
    }
  });

  it("handles 2000 random byte strings", () => {
    const failures: string[] = [];
    for (let i = 0; i < 2000; i++) {
      const length = Math.floor(Math.random() * 200);
      const data = new Uint8Array(length);
      crypto.getRandomValues(data);
      const result = parseIsSafe(data);
      if (result.unexpected) failures.push(`len=${length}: ${result.unexpected}`);
    }
    expect(failures).toEqual([]);
  });

  it("handles random strings that begin with a plausible version field", () => {
    // Purely random bytes usually die at the first varint. Seeding a valid
    // version drives the fuzzer deeper into the parser.
    const failures: string[] = [];
    for (let i = 0; i < 2000; i++) {
      const data = new Uint8Array(4 + Math.floor(Math.random() * 150));
      crypto.getRandomValues(data);
      data.set([0x02, 0x00, 0x00, 0x00], 0);
      const result = parseIsSafe(data);
      if (result.unexpected) failures.push(result.unexpected);
    }
    expect(failures).toEqual([]);
  });

  it("handles random strings shaped like a SegWit header", () => {
    // version + marker + flag, then noise. Exercises the witness branch.
    const failures: string[] = [];
    for (let i = 0; i < 1500; i++) {
      const data = new Uint8Array(6 + Math.floor(Math.random() * 150));
      crypto.getRandomValues(data);
      data.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0);
      const result = parseIsSafe(data);
      if (result.unexpected) failures.push(result.unexpected);
    }
    expect(failures).toEqual([]);
  });
});

describe("bit-flip mutation of a valid transaction", () => {
  it("survives a single bit flip at every position", () => {
    const original = validTransaction().serialize();
    const failures: string[] = [];
    for (let byte = 0; byte < original.length; byte++) {
      for (let bit = 0; bit < 8; bit++) {
        const mutated = Uint8Array.from(original);
        mutated[byte] = mutated[byte]! ^ (1 << bit);
        const result = parseIsSafe(mutated);
        if (result.unexpected) failures.push(`byte ${byte} bit ${bit}: ${result.unexpected}`);
      }
    }
    expect(failures).toEqual([]);
    expect(original.length).toBeGreaterThan(200); // the loop really ran
  });

  it("survives truncation at every possible length", () => {
    const original = validTransaction().serialize();
    const failures: string[] = [];
    for (let length = 0; length < original.length; length++) {
      const result = parseIsSafe(original.slice(0, length));
      if (result.unexpected) failures.push(`truncated to ${length}: ${result.unexpected}`);
    }
    expect(failures).toEqual([]);
  });

  it("REJECTS trailing bytes rather than ignoring them", () => {
    // Silently ignoring trailing data would let an attacker append bytes and
    // change the raw encoding of a transaction the parser still accepts.
    const original = validTransaction().serialize();
    for (const extra of [1, 2, 10]) {
      const padded = new Uint8Array(original.length + extra);
      padded.set(original);
      expect(() => Transaction.fromBytes(padded)).toThrow(/trailing bytes/);
    }
  });

  it("survives random byte replacement (100 rounds x 5 mutations)", () => {
    const original = validTransaction().serialize();
    const failures: string[] = [];
    for (let round = 0; round < 100; round++) {
      const mutated = Uint8Array.from(original);
      for (let m = 0; m < 5; m++) {
        const position = Math.floor(Math.random() * mutated.length);
        mutated[position] = Math.floor(Math.random() * 256);
      }
      const result = parseIsSafe(mutated);
      if (result.unexpected) failures.push(result.unexpected);
    }
    expect(failures).toEqual([]);
  });
});

/**
 * NOTE on the timing assertions below.
 *
 * These are CATASTROPHE detectors, not performance assertions. The failure
 * mode they guard against is a parser that attempts to allocate 2^64 entries
 * — which does not take "a bit longer", it exhausts memory or never returns.
 * The thresholds are therefore deliberately loose, so a slow or loaded
 * machine cannot fail them.
 *
 * A tight wall-clock threshold measures the machine rather than the code and
 * fails on hardware that is merely slower. See docs/ATTACKS.md VEY-009.
 */
describe("resource-exhaustion resistance", () => {
  it("rejects a declared input count far larger than the data", () => {
    // "version 2, then 0xffffffffffffffff inputs". A parser that allocates
    // before checking would attempt an 18-quintillion-element array.
    const data = hexToBytes("02000000" + "ff" + "ffffffffffffffff");
    const start = Date.now();
    expect(() => Transaction.fromBytes(data)).toThrow();
    expect(Date.now() - start).toBeLessThan(10_000); // catastrophe bound, not a perf target
  });

  it("rejects a declared output count far larger than the data", () => {
    const data = hexToBytes("02000000" + "00" + "01" + "01" + "00".repeat(32) + "00000000" + "00" + "ffffffff" + "ff" + "ffffffffffffffff");
    const start = Date.now();
    expect(() => Transaction.fromBytes(data)).toThrow();
    expect(Date.now() - start).toBeLessThan(10_000); // catastrophe bound, not a perf target
  });

  it("rejects a script length exceeding the remaining buffer", () => {
    const data = hexToBytes("02000000" + "01" + "ab".repeat(32) + "00000000" + "fe" + "ffffff7f" + "ffffffff");
    expect(() => Transaction.fromBytes(data)).toThrow(/exceeds remaining data|unexpected end/);
  });

  it("rejects a witness stack size exceeding the remaining buffer", () => {
    const base = validTransaction().serialize();
    const hex = bytesToHex(base);
    // Corrupt the first witness stack count into a huge varint.
    const corrupted = hex.replace("02" + "47", "ff" + "ffffffffffffffff");
    if (corrupted !== hex) {
      const start = Date.now();
      expect(parseIsSafe(hexToBytes(corrupted)).unexpected).toBeUndefined();
      expect(Date.now() - start).toBeLessThan(10_000); // catastrophe bound, not a perf target
    }
  });

  it("parses a large but legitimate transaction in reasonable time", () => {
    const inputs = Array.from({ length: 200 }, (_, i) =>
      new TxInput({ txid: i.toString(16).padStart(2, "0").repeat(32), vout: i }, new Uint8Array(0), SEQUENCE_RBF, [
        new Uint8Array(71).fill(0x30),
        new Uint8Array(33).fill(0x02),
      ]),
    );
    const outputs = Array.from({ length: 200 }, () => new TxOutput(1000n, hexToBytes("0014" + "11".repeat(20))));
    const large = new Transaction(2, inputs, outputs, 0);
    const serialized = large.serialize();

    const start = Date.now();
    const reparsed = Transaction.fromBytes(serialized);
    expect(Date.now() - start).toBeLessThan(20_000); // catastrophe bound, not a perf target
    expect(reparsed.inputs.length).toBe(200);
    expect(reparsed.toHex()).toBe(large.toHex());
  });
});

describe("round-trip property: parse(serialize(tx)) === tx", () => {
  it("holds for 300 randomly-shaped transactions", () => {
    for (let i = 0; i < 300; i++) {
      const inputCount = 1 + Math.floor(Math.random() * 4);
      const outputCount = 1 + Math.floor(Math.random() * 4);
      const withWitness = Math.random() > 0.5;

      const inputs = Array.from({ length: inputCount }, (_, n) => {
        const witness = withWitness
          ? [new Uint8Array(70 + Math.floor(Math.random() * 3)).fill(0x30), new Uint8Array(33).fill(0x02)]
          : [];
        return new TxInput(
          { txid: n.toString(16).padStart(2, "0").repeat(32), vout: n },
          new Uint8Array(0),
          Math.floor(Math.random() * 0xffffffff),
          witness,
        );
      });
      const outputs = Array.from({ length: outputCount }, () =>
        new TxOutput(BigInt(Math.floor(Math.random() * 1_000_000)), hexToBytes("0014" + "ab".repeat(20))),
      );

      const tx = new Transaction(2, inputs, outputs, Math.floor(Math.random() * 1_000_000));
      const reparsed = Transaction.fromBytes(tx.serialize());

      expect(reparsed.toHex()).toBe(tx.toHex());
      expect(reparsed.txid()).toBe(tx.txid());
      expect(reparsed.inputs.length).toBe(inputCount);
      expect(reparsed.outputs.length).toBe(outputCount);
    }
  });

  it("preserves exact output values, including boundary amounts", () => {
    for (const value of [0n, 1n, 546n, 100_000_000n, 2_100_000_000_000_000n]) {
      const tx = new Transaction(
        2,
        [new TxInput({ txid: "ab".repeat(32), vout: 0 })],
        [new TxOutput(value, hexToBytes("0014" + "cd".repeat(20)))],
        0,
      );
      expect(Transaction.fromBytes(tx.serialize()).outputs[0]!.value).toBe(value);
    }
  });
});

describe("SegWit marker handling", () => {
  it("rejects a marker byte followed by an invalid flag", () => {
    // 0x00 marker must be followed by exactly 0x01.
    for (const flag of [0x00, 0x02, 0xff]) {
      const data = hexToBytes("02000000" + "00" + flag.toString(16).padStart(2, "0") + "01" + "ab".repeat(32) + "00000000" + "00" + "ffffffff" + "00" + "00000000");
      expect(() => Transaction.fromBytes(data)).toThrow();
    }
  });

  it("rejects a SegWit transaction declaring zero inputs", () => {
    const data = hexToBytes("02000000" + "0001" + "00" + "00" + "00000000");
    expect(() => Transaction.fromBytes(data)).toThrow(/no inputs/);
  });
});
