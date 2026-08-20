/**
 * TRANSACTION SERIALIZATION TESTS
 *
 * Byte-exactness is the property under test. A txid IS a hash of these bytes,
 * so "close enough" does not exist — a one-byte difference produces a
 * different transaction whose signature verifies against nothing.
 */
import { describe, it, expect } from "vitest";
import {
  Transaction, TxInput, TxOutput,
  SEQUENCE_FINAL, SEQUENCE_RBF, MAX_MONEY,
} from "../../core/transactions/transaction.js";
import { ByteWriter, ByteReader, reverseBytes } from "../../core/bitcoin/serialization.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

const script20 = (fill: string) => hexToBytes("0014" + fill.repeat(20));

describe("varint (CompactSize) encoding", () => {
  it.each([
    [0n, "00"],
    [1n, "01"],
    [252n, "fc"],
    [253n, "fdfd00"],
    [65535n, "fdffff"],
    [65536n, "fe00000100"],
    [4294967295n, "feffffffff"],
    [4294967296n, "ff0000000001000000"],
  ])("encodes %s minimally", (value, expected) => {
    expect(bytesToHex(new ByteWriter().writeVarInt(value).toBytes())).toBe(expected);
  });

  it("round-trips every boundary value", () => {
    for (const v of [0n, 252n, 253n, 65535n, 65536n, 4294967295n, 4294967296n, 2n ** 63n]) {
      expect(new ByteReader(new ByteWriter().writeVarInt(v).toBytes()).readVarInt()).toBe(v);
    }
  });

  it("REJECTS non-minimal encodings — they are a malleability vector", () => {
    // The value 1, written three different ways. All decode to 1, all have
    // different bytes, so all would give one logical transaction several
    // valid txids. That is third-party malleability.
    expect(() => new ByteReader(hexToBytes("fd0100")).readVarInt()).toThrow(/non-minimal/);
    expect(() => new ByteReader(hexToBytes("fe01000000")).readVarInt()).toThrow(/non-minimal/);
    expect(() => new ByteReader(hexToBytes("ff0100000000000000")).readVarInt()).toThrow(/non-minimal/);
    // 65535 in the 4-byte form rather than the 2-byte form.
    expect(() => new ByteReader(hexToBytes("feffff0000")).readVarInt()).toThrow(/non-minimal/);
  });

  it("rejects truncated input rather than reading past the end", () => {
    expect(() => new ByteReader(hexToBytes("fd01")).readVarInt()).toThrow(/unexpected end/);
    expect(() => new ByteReader(hexToBytes("ff")).readVarInt()).toThrow();
    expect(() => new ByteReader(new Uint8Array(0)).readVarInt()).toThrow();
  });
});

describe("integer encoding", () => {
  it("writes uint32 little-endian", () => {
    expect(bytesToHex(new ByteWriter().writeUint32LE(1).toBytes())).toBe("01000000");
    expect(bytesToHex(new ByteWriter().writeUint32LE(0xdeadbeef).toBytes())).toBe("efbeadde");
  });

  it("writes uint64 little-endian from BigInt", () => {
    expect(bytesToHex(new ByteWriter().writeUint64LE(1n).toBytes())).toBe("0100000000000000");
    expect(bytesToHex(new ByteWriter().writeUint64LE(MAX_MONEY).toBytes())).toBe("0040075af0750700");
  });

  it("rejects out-of-range values instead of wrapping", () => {
    expect(() => new ByteWriter().writeUint32LE(-1)).toThrow();
    expect(() => new ByteWriter().writeUint32LE(2 ** 32)).toThrow();
    expect(() => new ByteWriter().writeUint8(256)).toThrow();
    expect(() => new ByteWriter().writeUint64LE(-1n)).toThrow();
    expect(() => new ByteWriter().writeUint64LE(2n ** 64n)).toThrow();
  });
});

describe("txid ordering — wire vs display", () => {
  it("the display txid is the REVERSE of the wire bytes", () => {
    const tx = new Transaction(
      2,
      [new TxInput({ txid: "ab".repeat(32), vout: 0 })],
      [new TxOutput(1000n, script20("cc"))],
      0,
    );
    expect(tx.txid()).toBe(bytesToHex(reverseBytes(tx.txidBytes())));
  });

  it("reverseBytes does not mutate its input", () => {
    const original = hexToBytes("0102030405");
    const reversed = reverseBytes(original);
    expect(bytesToHex(original)).toBe("0102030405");
    expect(bytesToHex(reversed)).toBe("0504030201");
  });
});

describe("transaction round-tripping", () => {
  it("round-trips a legacy (no-witness) transaction", () => {
    const tx = new Transaction(
      1,
      [new TxInput({ txid: "aa".repeat(32), vout: 3 }, hexToBytes("51"), SEQUENCE_FINAL)],
      [new TxOutput(50_000n, script20("bb"))],
      500_000,
    );
    const reparsed = Transaction.fromHex(tx.toHex());
    expect(reparsed.toHex()).toBe(tx.toHex());
    expect(reparsed.version).toBe(1);
    expect(reparsed.locktime).toBe(500_000);
    expect(reparsed.inputs[0]!.sequence).toBe(SEQUENCE_FINAL);
  });

  it("round-trips a SegWit transaction with witness data", () => {
    const tx = new Transaction(
      2,
      [
        new TxInput({ txid: "aa".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF, [
          new Uint8Array(71).fill(1),
          new Uint8Array(33).fill(2),
        ]),
      ],
      [new TxOutput(1000n, script20("cc"))],
      0,
    );
    const reparsed = Transaction.fromHex(tx.toHex());
    expect(reparsed.toHex()).toBe(tx.toHex());
    expect(reparsed.inputs[0]!.witness.length).toBe(2);
  });

  it("uses the marker/flag 0x0001 only when a witness is present", () => {
    const withWitness = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF, [new Uint8Array(1)])],
      [new TxOutput(1n, script20("dd"))],
      0,
    );
    const without = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 })],
      [new TxOutput(1n, script20("dd"))],
      0,
    );
    expect(withWitness.toHex().slice(8, 12)).toBe("0001");
    expect(without.toHex().slice(8, 12)).not.toBe("0001");
  });

  it("txid ignores witness data; wtxid does not", () => {
    const base = new TxInput({ txid: "aa".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF);
    const outputs = [new TxOutput(1000n, script20("cc"))];
    const a = new Transaction(2, [base.withWitness([new Uint8Array(71).fill(1), new Uint8Array(33).fill(2)])], outputs, 0);
    const b = new Transaction(2, [base.withWitness([new Uint8Array(71).fill(9), new Uint8Array(33).fill(8)])], outputs, 0);
    expect(a.txid()).toBe(b.txid()); // identical — witness excluded
    expect(a.wtxid()).not.toBe(b.wtxid()); // different — witness included
  });
});

describe("weight and vsize", () => {
  it("vsize equals byte length for a witness-free transaction", () => {
    const tx = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 })],
      [new TxOutput(1000n, script20("cc"))],
      0,
    );
    expect(tx.vsize()).toBe(tx.serialize().length);
  });

  it("witness data is discounted to a quarter weight", () => {
    const tx = new Transaction(
      2,
      [
        new TxInput({ txid: "aa".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF, [
          new Uint8Array(71),
          new Uint8Array(33),
        ]),
      ],
      [new TxOutput(1000n, script20("cc"))],
      0,
    );
    expect(tx.vsize()).toBeLessThan(tx.serialize().length);
    expect(tx.weight()).toBe(tx.serializeLegacy().length * 3 + tx.serialize().length);
  });
});

describe("validation on construction", () => {
  it("rejects malformed txids", () => {
    expect(() => new TxInput({ txid: "abc", vout: 0 })).toThrow(/64 lowercase hex/);
    expect(() => new TxInput({ txid: "AB".repeat(32), vout: 0 })).toThrow(); // uppercase
    expect(() => new TxInput({ txid: "zz".repeat(32), vout: 0 })).toThrow();
    expect(() => new TxInput({ txid: "ab".repeat(31), vout: 0 })).toThrow();
  });

  it("rejects out-of-range vout, sequence, version, and locktime", () => {
    expect(() => new TxInput({ txid: "ab".repeat(32), vout: -1 })).toThrow();
    expect(() => new TxInput({ txid: "ab".repeat(32), vout: 2 ** 32 })).toThrow();
    expect(() => new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), -1)).toThrow();
    expect(() => new Transaction(-1)).toThrow();
    expect(() => new Transaction(2, [], [], 2 ** 32)).toThrow();
  });

  it("rejects output values outside [0, MAX_MONEY]", () => {
    expect(() => new TxOutput(-1n, new Uint8Array(1))).toThrow(/negative/);
    expect(() => new TxOutput(MAX_MONEY + 1n, new Uint8Array(1))).toThrow(/money supply/);
    expect(() => new TxOutput(MAX_MONEY, new Uint8Array(1))).not.toThrow();
    expect(() => new TxOutput(0n, new Uint8Array(1))).not.toThrow();
  });

  it("transactions are immutable — withInput returns a new object", () => {
    const tx = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 })],
      [new TxOutput(1n, script20("ee"))],
      0,
    );
    const modified = tx.withInput(0, tx.inputs[0]!.withWitness([new Uint8Array(5)]));
    expect(tx.inputs[0]!.witness.length).toBe(0);
    expect(modified.inputs[0]!.witness.length).toBe(1);
    expect(modified).not.toBe(tx);
  });

  it("withInput rejects an out-of-range index", () => {
    const tx = new Transaction(
      2,
      [new TxInput({ txid: "aa".repeat(32), vout: 0 })],
      [new TxOutput(1n, script20("ee"))],
      0,
    );
    expect(() => tx.withInput(5, tx.inputs[0]!)).toThrow(/out of range/);
  });
});
