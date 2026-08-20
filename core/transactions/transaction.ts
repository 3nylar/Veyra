/**
 * TRANSACTIONS
 *
 * ─── Bitcoin does not have balances ────────────────────────────────────────
 * There is no account, no row in a table, no `balance -= amount`. There are
 * only unspent transaction outputs (UTXOs). A transaction:
 *
 *   1. CONSUMES some existing outputs entirely (inputs), and
 *   2. CREATES new outputs.
 *
 * Inputs are all-or-nothing. If you hold a single 1 BTC output and wish to
 * send 0.1, you consume the whole 1 BTC and create two outputs: 0.1 to the
 * recipient and ~0.9 back to yourself. That second output is CHANGE, and
 * forgetting it means the entire remainder becomes fee. This has happened
 * for real, repeatedly, in amounts that made the news.
 *
 * The fee is never written down anywhere. It is implicit:
 *
 *     fee = sum(input values) − sum(output values)
 *
 * Which means a transaction cannot state its own fee, and a wallet that
 * miscalculates input values will silently overpay. Veyra therefore requires
 * every input to carry its value explicitly (see `SignableInput`), and
 * verifies the arithmetic before signing rather than trusting it.
 *
 * ─── Anatomy ───────────────────────────────────────────────────────────────
 *
 *   version    4 bytes    consensus rule selector (1 or 2; 2 enables BIP-68)
 *   [marker]   0x00       SegWit only — invalid as an input count, which is
 *   [flag]     0x01       how old nodes detect and skip the witness
 *   inputs     varint + n × TxIn
 *   outputs    varint + n × TxOut
 *   [witness]  SegWit only — one stack per input
 *   locktime   4 bytes    earliest block/time this may be mined
 *
 * ─── txid vs wtxid, and why SegWit exists ──────────────────────────────────
 *
 *     txid  = HASH256(serialisation WITHOUT witness data)
 *     wtxid = HASH256(serialisation WITH witness data)
 *
 * Before SegWit, signatures lived in the input's scriptSig, which was inside
 * the txid computation. But a signature cannot commit to its own hash — so
 * third parties could alter the encoding of a signature (padding an ECDSA
 * DER value, flipping S to n−S) and change the txid without invalidating
 * anything. Any system tracking transactions by txid broke. This is
 * TRANSACTION MALLEABILITY, and it is why Mt. Gox's withdrawal system failed
 * and why Lightning was impossible before 2017.
 *
 * SegWit moves signatures OUT of the txid computation. The txid now commits
 * only to what the transaction *does*, not to how its authorisation was
 * encoded — so it is stable the moment it is created, before it is even
 * signed. That stability is what makes chained unconfirmed transactions
 * (and therefore Lightning channels) safe.
 */

import { ByteWriter, ByteReader, reverseBytes, doubleSha256, SerializationError } from "../bitcoin/serialization.js";
import { bytesToHex, hexToBytes } from "../crypto/bytes.js";

/** Sequence value disabling both RBF and relative timelocks. */
export const SEQUENCE_FINAL = 0xffffffff;

/**
 * Sequence signalling opt-in Replace-By-Fee (BIP-125).
 *
 * Any value below 0xfffffffe signals RBF. Veyra uses this by default: a
 * transaction stuck at too low a fee can otherwise be unspendable for days
 * with no recourse. Opting in costs nothing and preserves the ability to
 * bump. The trade-off is that some merchants treat RBF transactions as less
 * trustworthy while unconfirmed, which is a reasonable position for them to
 * take and does not affect safety for the sender.
 */
export const SEQUENCE_RBF = 0xfffffffd;

/** Maximum satoshis that will ever exist: 21,000,000 BTC. */
export const MAX_MONEY = 2_100_000_000_000_000n;

/** An output being consumed, identified by the transaction and index it came from. */
export interface OutPoint {
  /** Previous transaction id in DISPLAY order (reversed hex, as block explorers show). */
  readonly txid: string;
  /** Index of the output within that transaction. */
  readonly vout: number;
}

export class TxInput {
  constructor(
    readonly outpoint: OutPoint,
    /** Legacy unlocking script. Empty for native SegWit inputs. */
    readonly scriptSig: Uint8Array = new Uint8Array(0),
    readonly sequence: number = SEQUENCE_RBF,
    /** Witness stack. Empty until signed. */
    readonly witness: Uint8Array[] = [],
  ) {
    if (!/^[0-9a-f]{64}$/.test(outpoint.txid)) {
      throw new SerializationError("txid must be 64 lowercase hex characters");
    }
    if (!Number.isInteger(outpoint.vout) || outpoint.vout < 0 || outpoint.vout > 0xffffffff) {
      throw new SerializationError("vout must be a uint32");
    }
    if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffffffff) {
      throw new SerializationError("sequence must be a uint32");
    }
  }

  get hasWitness(): boolean {
    return this.witness.length > 0;
  }

  /** Outpoint in wire format: 32-byte reversed txid ‖ uint32 LE index. */
  serializeOutPoint(): Uint8Array {
    return new ByteWriter()
      .writeBytes(reverseBytes(hexToBytes(this.outpoint.txid)))
      .writeUint32LE(this.outpoint.vout)
      .toBytes();
  }

  /** Attach a witness stack, returning a new input. Inputs are immutable. */
  withWitness(witness: Uint8Array[]): TxInput {
    return new TxInput(this.outpoint, this.scriptSig, this.sequence, witness);
  }
}

export class TxOutput {
  constructor(
    /** Amount in satoshis. BigInt — never a float. */
    readonly value: bigint,
    /** The locking script defining who may spend this. */
    readonly scriptPubKey: Uint8Array,
  ) {
    if (value < 0n) throw new SerializationError("output value cannot be negative");
    if (value > MAX_MONEY) throw new SerializationError("output value exceeds the money supply");
  }

  serialize(): Uint8Array {
    return new ByteWriter()
      .writeUint64LE(this.value)
      .writeVarBytes(this.scriptPubKey)
      .toBytes();
  }
}

export class Transaction {
  constructor(
    readonly version: number = 2,
    readonly inputs: readonly TxInput[] = [],
    readonly outputs: readonly TxOutput[] = [],
    readonly locktime: number = 0,
  ) {
    if (!Number.isInteger(version) || version < 0 || version > 0xffffffff) {
      throw new SerializationError("version must be a uint32");
    }
    if (!Number.isInteger(locktime) || locktime < 0 || locktime > 0xffffffff) {
      throw new SerializationError("locktime must be a uint32");
    }
  }

  get hasWitness(): boolean {
    return this.inputs.some((input) => input.hasWitness);
  }

  /**
   * Serialise WITHOUT witness data. This is what the txid is computed over,
   * and what pre-SegWit nodes see.
   */
  serializeLegacy(): Uint8Array {
    const writer = new ByteWriter();
    writer.writeUint32LE(this.version);
    writer.writeVarInt(this.inputs.length);
    for (const input of this.inputs) {
      writer.writeBytes(input.serializeOutPoint());
      writer.writeVarBytes(input.scriptSig);
      writer.writeUint32LE(input.sequence);
    }
    writer.writeVarInt(this.outputs.length);
    for (const output of this.outputs) writer.writeBytes(output.serialize());
    writer.writeUint32LE(this.locktime);
    return writer.toBytes();
  }

  /**
   * Full serialisation including witness data — what gets broadcast.
   *
   * The marker/flag trick: after the version, a SegWit transaction writes
   * 0x00 0x01. A pre-SegWit parser reads 0x00 as the input count, which is
   * invalid (a transaction must have inputs), so it knows to stop rather than
   * misinterpret the data. Backwards compatibility through a deliberately
   * impossible value.
   */
  serialize(): Uint8Array {
    if (!this.hasWitness) return this.serializeLegacy();

    const writer = new ByteWriter();
    writer.writeUint32LE(this.version);
    writer.writeUint8(0x00); // marker
    writer.writeUint8(0x01); // flag
    writer.writeVarInt(this.inputs.length);
    for (const input of this.inputs) {
      writer.writeBytes(input.serializeOutPoint());
      writer.writeVarBytes(input.scriptSig);
      writer.writeUint32LE(input.sequence);
    }
    writer.writeVarInt(this.outputs.length);
    for (const output of this.outputs) writer.writeBytes(output.serialize());

    // One witness stack per input, in order. Inputs without a witness get an
    // explicit zero-length stack — the count must line up with the inputs.
    for (const input of this.inputs) {
      writer.writeVarInt(input.witness.length);
      for (const item of input.witness) writer.writeVarBytes(item);
    }
    writer.writeUint32LE(this.locktime);
    return writer.toBytes();
  }

  /** Raw txid bytes, wire (internal) order. */
  txidBytes(): Uint8Array {
    return doubleSha256(this.serializeLegacy());
  }

  /**
   * The txid as displayed by block explorers — REVERSED hex.
   *
   * See serialization.ts on why this reversal exists and why it is isolated.
   */
  txid(): string {
    return bytesToHex(reverseBytes(this.txidBytes()));
  }

  /** Witness txid — commits to signatures as well. */
  wtxid(): string {
    return bytesToHex(reverseBytes(doubleSha256(this.serialize())));
  }

  /**
   * Virtual size in vbytes, the unit fees are actually charged in.
   *
   *     weight = base_size × 3 + total_size
   *     vsize  = ceil(weight / 4)
   *
   * Witness data counts a quarter as much as non-witness data. That discount
   * is the direct economic reason to use SegWit: the same payment costs
   * meaningfully less. Fee estimation MUST use vsize — using raw byte length
   * overpays substantially on a witness-heavy transaction.
   */
  weight(): number {
    const base = this.serializeLegacy().length;
    const total = this.serialize().length;
    return base * 3 + total;
  }

  vsize(): number {
    return Math.ceil(this.weight() / 4);
  }

  /** Total satoshis created by this transaction's outputs. */
  totalOutputValue(): bigint {
    return this.outputs.reduce((sum, output) => sum + output.value, 0n);
  }

  /** Replace one input, returning a new transaction. Transactions are immutable. */
  withInput(index: number, input: TxInput): Transaction {
    if (index < 0 || index >= this.inputs.length) {
      throw new SerializationError("input index out of range");
    }
    const inputs = [...this.inputs];
    inputs[index] = input;
    return new Transaction(this.version, inputs, this.outputs, this.locktime);
  }

  toHex(): string {
    return bytesToHex(this.serialize());
  }

  /**
   * Parse a raw transaction.
   *
   * Attack surface: this consumes untrusted bytes from the network. Every
   * length is bounded against the remaining buffer before allocation, every
   * varint must be minimally encoded, and trailing bytes are rejected. See
   * tests/security/parsing.test.ts, which fuzzes this directly.
   */
  static fromBytes(data: Uint8Array): Transaction {
    const reader = new ByteReader(data);
    const version = reader.readUint32LE();

    let segwit = false;
    let inputCount = reader.readVarInt();

    // A zero input count is invalid, so 0x00 here signals the SegWit marker.
    if (inputCount === 0n) {
      const flag = reader.readUint8();
      if (flag !== 0x01) throw new SerializationError("invalid SegWit flag");
      segwit = true;
      inputCount = reader.readVarInt();
      if (inputCount === 0n) throw new SerializationError("transaction has no inputs");
    }
    if (inputCount > BigInt(data.length)) {
      throw new SerializationError("input count exceeds plausible bounds");
    }

    const inputs: TxInput[] = [];
    for (let i = 0n; i < inputCount; i++) {
      const prevTxid = bytesToHex(reverseBytes(reader.readBytes(32)));
      const vout = reader.readUint32LE();
      const scriptSig = reader.readVarBytes();
      const sequence = reader.readUint32LE();
      inputs.push(new TxInput({ txid: prevTxid, vout }, scriptSig, sequence));
    }

    const outputCount = reader.readVarInt();
    if (outputCount > BigInt(data.length)) {
      throw new SerializationError("output count exceeds plausible bounds");
    }
    const outputs: TxOutput[] = [];
    for (let i = 0n; i < outputCount; i++) {
      const value = reader.readUint64LE();
      const scriptPubKey = reader.readVarBytes();
      outputs.push(new TxOutput(value, scriptPubKey));
    }

    if (segwit) {
      for (let i = 0; i < inputs.length; i++) {
        const stackSize = reader.readVarInt();
        if (stackSize > BigInt(reader.remaining + 1)) {
          throw new SerializationError("witness stack size exceeds remaining data");
        }
        const stack: Uint8Array[] = [];
        for (let j = 0n; j < stackSize; j++) stack.push(reader.readVarBytes());
        inputs[i] = inputs[i]!.withWitness(stack);
      }
    }

    const locktime = reader.readUint32LE();
    reader.assertConsumed();
    return new Transaction(version, inputs, outputs, locktime);
  }

  static fromHex(hex: string): Transaction {
    return Transaction.fromBytes(hexToBytes(hex));
  }
}
