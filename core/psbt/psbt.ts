/**
 * BIP-174 — PARTIALLY SIGNED BITCOIN TRANSACTIONS
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  WHY THIS EXISTS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Veyra's multisig already works — but only with itself. A partial signature
 * in Veyra's own shape cannot be handed to a hardware wallet, to Sparrow, or
 * to Bitcoin Core, so a 2-of-3 arrangement would require every participant to
 * run Veyra. That is a poor property for a scheme whose entire purpose is
 * distributing trust: it replaces "trust one seed" with "trust one codebase".
 *
 * PSBT is the interchange format that fixes it. A PSBT carries an unsigned
 * transaction plus everything a signer needs to sign it — input values,
 * scripts, derivation paths — so a signer that has never seen the wallet can
 * still verify what it is signing.
 *
 * ─── The format ────────────────────────────────────────────────────────────
 *     magic  0x70736274 0xff        "psbt" and a byte that is not valid ASCII
 *     global key-value map, terminated by an empty key (0x00)
 *     one key-value map per INPUT, each terminated by 0x00
 *     one key-value map per OUTPUT, each terminated by 0x00
 *
 * Each record is:
 *     <compact-size keylen> <keytype byte> <keydata…> <compact-size vallen> <value…>
 *
 * The trailing `0xff` in the magic is deliberate: it makes the format
 * impossible to confuse with text, so a PSBT pasted into a field expecting
 * something else fails immediately rather than being partially interpreted.
 *
 * ─── The rule that matters most when combining ─────────────────────────────
 * **Unknown fields must be PRESERVED, never dropped.**
 *
 * A PSBT may pass through several tools. If a combiner discards fields it does
 * not understand, it silently destroys data a later signer needs — and the
 * failure appears somewhere else entirely, as a signer that inexplicably
 * cannot sign. BIP-174 is explicit about this, and `combine()` below carries
 * unknown records through untouched.
 *
 * ─── witness_utxo and the amount ───────────────────────────────────────────
 * For a SegWit input, `witness_utxo` (0x01) supplies the output being spent —
 * its value and its script. This is what lets an offline signer verify the
 * amount it is committing to, since BIP-143 puts the value inside the
 * signature preimage.
 *
 * The alternative, `non_witness_utxo` (0x00), carries the entire previous
 * transaction. It exists because pre-SegWit inputs have no other way to prove
 * an amount — and because a hardware wallet signing a *mix* of input types was
 * once vulnerable to a fee-inflation attack when trusting witness_utxo alone.
 * Veyra emits witness_utxo for its SegWit-only inputs, and states that
 * limitation rather than implying general PSBT support.
 *
 * ─── Scope ─────────────────────────────────────────────────────────────────
 * Implemented: creation, witness_utxo, witness scripts, BIP-32 derivations,
 * partial signatures, sighash type, combine, and finalisation for P2WPKH and
 * P2WSH multisig.
 *
 * NOT implemented: non_witness_utxo, legacy P2PKH/P2SH, taproot fields
 * (BIP-371), PSBT v2 (BIP-370), proprietary fields. Unsupported *inputs* are
 * rejected at finalisation rather than silently producing a broken witness.
 */

import { ByteWriter, ByteReader, SerializationError } from "../bitcoin/serialization.js";
import { Transaction, TxInput, TxOutput } from "../transactions/transaction.js";
import { bytesToHex, hexToBytes, concatBytes, bytesToBase64, base64ToBytes } from "../crypto/bytes.js";
import { VeyraError } from "../errors/index.js";

export class PsbtError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `PSBT: ${reason}`);
    this.name = "PsbtError";
  }
}

/** "psbt" followed by 0xff — deliberately not valid text. */
export const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

/** Global key types. */
export const GLOBAL_UNSIGNED_TX = 0x00;
export const GLOBAL_VERSION = 0xfb;

/** Input key types. */
export const IN_NON_WITNESS_UTXO = 0x00;
export const IN_WITNESS_UTXO = 0x01;
export const IN_PARTIAL_SIG = 0x02;
export const IN_SIGHASH_TYPE = 0x03;
export const IN_REDEEM_SCRIPT = 0x04;
export const IN_WITNESS_SCRIPT = 0x05;
export const IN_BIP32_DERIVATION = 0x06;
export const IN_FINAL_SCRIPTSIG = 0x07;
export const IN_FINAL_SCRIPTWITNESS = 0x08;

/** Output key types. */
export const OUT_REDEEM_SCRIPT = 0x00;
export const OUT_WITNESS_SCRIPT = 0x01;
export const OUT_BIP32_DERIVATION = 0x02;

/** Largest PSBT we will parse. A bound against hostile input. */
const MAX_PSBT_BYTES = 1024 * 1024;

/** One key-value record. `key` is keytype ‖ keydata. */
interface Record_ {
  readonly key: Uint8Array;
  readonly value: Uint8Array;
}

/** An ordered map preserving unknown records. */
class RecordMap {
  private records: Record_[] = [];

  set(keyType: number, keyData: Uint8Array, value: Uint8Array): void {
    const key = concatBytes(new Uint8Array([keyType]), keyData);
    const hex = bytesToHex(key);
    const existing = this.records.findIndex((r) => bytesToHex(r.key) === hex);
    if (existing >= 0) this.records[existing] = { key, value };
    else this.records.push({ key, value });
  }

  get(keyType: number, keyData = new Uint8Array(0)): Uint8Array | undefined {
    const hex = bytesToHex(concatBytes(new Uint8Array([keyType]), keyData));
    return this.records.find((r) => bytesToHex(r.key) === hex)?.value;
  }

  /** All records of a type, e.g. every partial signature. */
  getAll(keyType: number): Array<{ keyData: Uint8Array; value: Uint8Array }> {
    return this.records
      .filter((r) => r.key[0] === keyType)
      .map((r) => ({ keyData: r.key.slice(1), value: r.value }));
  }

  delete(keyType: number, keyData = new Uint8Array(0)): void {
    const hex = bytesToHex(concatBytes(new Uint8Array([keyType]), keyData));
    this.records = this.records.filter((r) => bytesToHex(r.key) !== hex);
  }

  deleteAll(keyType: number): void {
    this.records = this.records.filter((r) => r.key[0] !== keyType);
  }

  has(keyType: number, keyData = new Uint8Array(0)): boolean {
    return this.get(keyType, keyData) !== undefined;
  }

  get all(): readonly Record_[] {
    return this.records;
  }

  /**
   * Merge another map in.
   *
   * Records already present are kept — a combiner must not overwrite one
   * signer's contribution with another's. Records it does not understand are
   * carried through, which is BIP-174's explicit requirement and the reason
   * this is a record list rather than typed fields.
   */
  merge(other: RecordMap): void {
    for (const record of other.all) {
      const hex = bytesToHex(record.key);
      if (!this.records.some((r) => bytesToHex(r.key) === hex)) {
        this.records.push(record);
      }
    }
  }

  serialize(writer: ByteWriter): void {
    // Sorted by key, so the same logical PSBT always serialises identically —
    // otherwise two combiners could produce different bytes for the same
    // content, and any hash or equality check over a PSBT would be unreliable.
    const sorted = [...this.records].sort((a, b) =>
      bytesToHex(a.key) < bytesToHex(b.key) ? -1 : 1,
    );
    for (const record of sorted) {
      writer.writeVarBytes(record.key);
      writer.writeVarBytes(record.value);
    }
    writer.writeUint8(0x00); // separator: an empty key ends the map
  }

  static parse(reader: ByteReader): RecordMap {
    const map = new RecordMap();
    for (;;) {
      if (reader.remaining === 0) throw new PsbtError("unterminated key-value map");
      const keyLength = reader.readVarInt();
      if (keyLength === 0n) return map; // separator
      if (keyLength > BigInt(reader.remaining)) {
        throw new PsbtError("key length exceeds remaining data");
      }
      const key = reader.readBytes(Number(keyLength));
      const value = reader.readVarBytes();

      const hex = bytesToHex(key);
      if (map.records.some((r) => bytesToHex(r.key) === hex)) {
        // BIP-174: duplicate keys are invalid. Accepting them would make the
        // meaning of a PSBT depend on parse order.
        throw new PsbtError("duplicate key in a key-value map");
      }
      map.records.push({ key, value });
    }
  }
}

/** A BIP-32 derivation: which key, under which master, at which path. */
export interface Bip32Derivation {
  readonly publicKey: Uint8Array;
  readonly masterFingerprint: Uint8Array;
  readonly path: string;
}

export class Psbt {
  private global = new RecordMap();
  private inputs: RecordMap[] = [];
  private outputs: RecordMap[] = [];
  private unsignedTx: Transaction;

  private constructor(unsignedTx: Transaction) {
    this.unsignedTx = unsignedTx;
    this.inputs = unsignedTx.inputs.map(() => new RecordMap());
    this.outputs = unsignedTx.outputs.map(() => new RecordMap());

    const serialised = unsignedTx.serializeLegacy();
    this.global.set(GLOBAL_UNSIGNED_TX, new Uint8Array(0), serialised);
  }

  /**
   * Create a PSBT from an unsigned transaction.
   *
   * The transaction must carry NO signatures. BIP-174 requires it, and the
   * reason is structural: the unsigned transaction is the shared reference
   * every signer commits to, so if it already contained a witness, different
   * participants could be signing different things.
   */
  static create(transaction: Transaction): Psbt {
    for (const [i, input] of transaction.inputs.entries()) {
      if (input.witness.length > 0) {
        throw new PsbtError(`input ${i} already has a witness; a PSBT starts unsigned`);
      }
      if (input.scriptSig.length > 0) {
        throw new PsbtError(`input ${i} already has a scriptSig; a PSBT starts unsigned`);
      }
    }
    if (transaction.inputs.length === 0) throw new PsbtError("transaction has no inputs");
    return new Psbt(transaction);
  }

  get transaction(): Transaction {
    return this.unsignedTx;
  }

  get inputCount(): number {
    return this.inputs.length;
  }

  private assertInput(index: number): RecordMap {
    const input = this.inputs[index];
    if (!input) throw new PsbtError(`input index ${index} out of range`);
    return input;
  }

  // ── Fields a signer needs ───────────────────────────────────────────────

  /**
   * The output being spent: its value and script.
   *
   * This is what lets an offline signer verify the amount it commits to,
   * since BIP-143 puts the value inside the preimage. Without it a signer is
   * trusting the coordinator about how much is being spent.
   */
  setWitnessUtxo(index: number, value: bigint, scriptPubKey: Uint8Array): this {
    this.assertInput(index).set(
      IN_WITNESS_UTXO,
      new Uint8Array(0),
      new TxOutput(value, scriptPubKey).serialize(),
    );
    return this;
  }

  getWitnessUtxo(index: number): { value: bigint; scriptPubKey: Uint8Array } | undefined {
    const raw = this.assertInput(index).get(IN_WITNESS_UTXO);
    if (!raw) return undefined;
    const reader = new ByteReader(raw);
    return { value: reader.readUint64LE(), scriptPubKey: reader.readVarBytes() };
  }

  /** The witnessScript for a P2WSH input — the multisig script itself. */
  setWitnessScript(index: number, script: Uint8Array): this {
    this.assertInput(index).set(IN_WITNESS_SCRIPT, new Uint8Array(0), script);
    return this;
  }

  getWitnessScript(index: number): Uint8Array | undefined {
    return this.assertInput(index).get(IN_WITNESS_SCRIPT);
  }

  setSighashType(index: number, sighashType: number): this {
    const value = new Uint8Array(4);
    new DataView(value.buffer).setUint32(0, sighashType, true);
    this.assertInput(index).set(IN_SIGHASH_TYPE, new Uint8Array(0), value);
    return this;
  }

  getSighashType(index: number): number | undefined {
    const raw = this.assertInput(index).get(IN_SIGHASH_TYPE);
    if (!raw || raw.length !== 4) return undefined;
    return new DataView(raw.buffer, raw.byteOffset, 4).getUint32(0, true);
  }

  /**
   * Tell a signer where its key lives.
   *
   * A hardware wallet holds a seed, not individual keys — it needs the path to
   * derive the right one, and the master fingerprint to know whether the key
   * is even its own.
   */
  setBip32Derivation(index: number, derivation: Bip32Derivation): this {
    if (derivation.masterFingerprint.length !== 4) {
      throw new PsbtError("master fingerprint must be 4 bytes");
    }
    this.assertInput(index).set(
      IN_BIP32_DERIVATION,
      derivation.publicKey,
      concatBytes(derivation.masterFingerprint, encodePath(derivation.path)),
    );
    return this;
  }

  getBip32Derivations(index: number): Bip32Derivation[] {
    return this.assertInput(index)
      .getAll(IN_BIP32_DERIVATION)
      .map(({ keyData, value }) => ({
        publicKey: keyData,
        masterFingerprint: value.slice(0, 4),
        path: decodePath(value.slice(4)),
      }));
  }

  // ── Signing ─────────────────────────────────────────────────────────────

  /** Attach a partial signature, keyed by the signer's public key. */
  addPartialSignature(index: number, publicKey: Uint8Array, signature: Uint8Array): this {
    if (publicKey.length !== 33) {
      throw new PsbtError("public key must be 33 bytes (compressed)");
    }
    if (signature.length < 8 || signature.length > 73) {
      throw new PsbtError("signature has an implausible length");
    }
    this.assertInput(index).set(IN_PARTIAL_SIG, publicKey, signature);
    return this;
  }

  getPartialSignatures(index: number): Array<{ publicKey: Uint8Array; signature: Uint8Array }> {
    return this.assertInput(index)
      .getAll(IN_PARTIAL_SIG)
      .map(({ keyData, value }) => ({ publicKey: keyData, signature: value }));
  }

  /**
   * Merge another PSBT for the same transaction.
   *
   * Both must describe the SAME unsigned transaction — otherwise a combiner
   * could be tricked into merging signatures for a payment nobody approved.
   * Existing records win, so one signer cannot overwrite another's, and
   * unknown records are carried through untouched.
   */
  combine(other: Psbt): this {
    if (this.unsignedTx.txid() !== other.unsignedTx.txid()) {
      throw new PsbtError(
        "cannot combine PSBTs for different transactions — the unsigned txids differ",
      );
    }
    if (other.inputs.length !== this.inputs.length) {
      throw new PsbtError("input counts differ");
    }

    this.global.merge(other.global);
    for (let i = 0; i < this.inputs.length; i++) this.inputs[i]!.merge(other.inputs[i]!);
    for (let i = 0; i < this.outputs.length; i++) this.outputs[i]!.merge(other.outputs[i]!);
    return this;
  }

  /**
   * Finalise: turn partial signatures into a witness.
   *
   * Supports P2WPKH (one signature plus its key) and P2WSH multisig (the
   * dummy element, the signatures in script order, then the script).
   *
   * An input type this does not understand is REJECTED rather than
   * best-effort finalised, because a plausible-but-wrong witness produces a
   * transaction that fails on-chain with no indication why.
   */
  finalize(): this {
    for (let index = 0; index < this.inputs.length; index++) {
      const input = this.assertInput(index);
      if (input.has(IN_FINAL_SCRIPTWITNESS)) continue; // already done

      const utxo = this.getWitnessUtxo(index);
      if (!utxo) {
        throw new PsbtError(
          `input ${index}: no witness_utxo. Only SegWit inputs are supported; ` +
            `non_witness_utxo is not implemented.`,
        );
      }

      const signatures = this.getPartialSignatures(index);
      if (signatures.length === 0) {
        throw new PsbtError(`input ${index}: no signatures to finalise`);
      }

      const script = utxo.scriptPubKey;
      let witness: Uint8Array[];

      if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
        // P2WPKH: exactly one signature, and the key goes in the witness
        // because the output commits only to its hash.
        if (signatures.length !== 1) {
          throw new PsbtError(
            `input ${index}: P2WPKH takes exactly one signature, found ${signatures.length}`,
          );
        }
        witness = [signatures[0]!.signature, signatures[0]!.publicKey];
      } else if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
        // P2WSH.
        const witnessScript = this.getWitnessScript(index);
        if (!witnessScript) {
          throw new PsbtError(`input ${index}: P2WSH input has no witness_script`);
        }

        const threshold = witnessScript[0]! - 0x50; // OP_m
        if (threshold < 1 || threshold > 16) {
          throw new PsbtError(`input ${index}: witness_script is not a recognised multisig`);
        }
        if (signatures.length < threshold) {
          throw new PsbtError(
            `input ${index}: ${signatures.length} of ${threshold} required signatures`,
          );
        }

        // Order signatures to match the key order inside the script.
        // CHECKMULTISIG walks both in one pass and does not search.
        const keyOrder = extractPublicKeys(witnessScript).map(bytesToHex);
        const ordered = [...signatures].sort(
          (a, b) => keyOrder.indexOf(bytesToHex(a.publicKey)) - keyOrder.indexOf(bytesToHex(b.publicKey)),
        );
        for (const signature of ordered) {
          if (!keyOrder.includes(bytesToHex(signature.publicKey))) {
            throw new PsbtError(
              `input ${index}: a signature is from a key not present in the witness_script`,
            );
          }
        }

        witness = [
          new Uint8Array(0), // the OP_CHECKMULTISIG dummy element
          ...ordered.slice(0, threshold).map((s) => s.signature),
          witnessScript,
        ];
      } else {
        throw new PsbtError(
          `input ${index}: unsupported script type. Only P2WPKH and P2WSH are implemented.`,
        );
      }

      const writer = new ByteWriter();
      writer.writeVarInt(witness.length);
      for (const item of witness) writer.writeVarBytes(item);
      input.set(IN_FINAL_SCRIPTWITNESS, new Uint8Array(0), writer.toBytes());

      // BIP-174: once finalised, the fields that produced the witness are
      // removed. They are no longer needed, and leaving them invites a tool
      // into re-deriving something that has already been settled.
      input.deleteAll(IN_PARTIAL_SIG);
      input.deleteAll(IN_BIP32_DERIVATION);
      input.delete(IN_SIGHASH_TYPE);
      input.delete(IN_WITNESS_SCRIPT);
    }
    return this;
  }

  /** Extract the broadcastable transaction. Requires finalisation. */
  extract(): Transaction {
    let result = this.unsignedTx;

    for (let index = 0; index < this.inputs.length; index++) {
      const raw = this.assertInput(index).get(IN_FINAL_SCRIPTWITNESS);
      if (!raw) throw new PsbtError(`input ${index} is not finalised`);

      const reader = new ByteReader(raw);
      const count = Number(reader.readVarInt());
      const witness: Uint8Array[] = [];
      for (let i = 0; i < count; i++) witness.push(reader.readVarBytes());

      result = result.withInput(index, result.inputs[index]!.withWitness(witness));
    }
    return result;
  }

  get isFinalized(): boolean {
    return this.inputs.every((input) => input.has(IN_FINAL_SCRIPTWITNESS));
  }

  // ── Serialisation ───────────────────────────────────────────────────────

  serialize(): Uint8Array {
    const writer = new ByteWriter();
    writer.writeBytes(PSBT_MAGIC);
    this.global.serialize(writer);
    for (const input of this.inputs) input.serialize(writer);
    for (const output of this.outputs) output.serialize(writer);
    return writer.toBytes();
  }

  /** Base64, the form PSBTs are normally exchanged in. */
  toBase64(): string {
    return bytesToBase64(this.serialize());
  }

  toHex(): string {
    return bytesToHex(this.serialize());
  }

  static fromBytes(data: Uint8Array): Psbt {
    // Every parse failure surfaces as a PsbtError, including ones originating
    // in the byte-reader beneath. A caller should not have to know that PSBT
    // parsing reuses the transaction serialiser, and catching two error types
    // for one operation is the kind of detail that gets forgotten.
    try {
      return Psbt.parseInternal(data);
    } catch (error) {
      if (error instanceof PsbtError) throw error;
      if (error instanceof SerializationError) {
        throw new PsbtError(`malformed PSBT: ${error.message.replace(/^Serialization: /, "")}`);
      }
      throw error;
    }
  }

  private static parseInternal(data: Uint8Array): Psbt {
    if (data.length > MAX_PSBT_BYTES) throw new PsbtError("PSBT exceeds the maximum size");
    if (data.length < 5) throw new PsbtError("too short to be a PSBT");

    for (let i = 0; i < PSBT_MAGIC.length; i++) {
      if (data[i] !== PSBT_MAGIC[i]) throw new PsbtError("bad magic bytes — this is not a PSBT");
    }

    const reader = new ByteReader(data.slice(PSBT_MAGIC.length));
    const global = RecordMap.parse(reader);

    const rawTx = global.get(GLOBAL_UNSIGNED_TX);
    if (!rawTx) throw new PsbtError("no unsigned transaction in the global map");

    let unsignedTx: Transaction;
    try {
      unsignedTx = Transaction.fromBytes(rawTx);
    } catch (error) {
      throw new PsbtError(`unsigned transaction is malformed: ${(error as Error).message}`);
    }
    for (const [i, input] of unsignedTx.inputs.entries()) {
      if (input.witness.length > 0 || input.scriptSig.length > 0) {
        throw new PsbtError(`the global unsigned transaction must be unsigned (input ${i})`);
      }
    }

    const psbt = new Psbt(unsignedTx);
    psbt.global = global;

    for (let i = 0; i < unsignedTx.inputs.length; i++) {
      if (reader.remaining === 0) throw new PsbtError(`missing map for input ${i}`);
      psbt.inputs[i] = RecordMap.parse(reader);
    }
    for (let i = 0; i < unsignedTx.outputs.length; i++) {
      if (reader.remaining === 0) throw new PsbtError(`missing map for output ${i}`);
      psbt.outputs[i] = RecordMap.parse(reader);
    }
    if (reader.remaining !== 0) throw new PsbtError("trailing data after the output maps");

    return psbt;
  }

  static fromBase64(text: string): Psbt {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text.trim())) {
      throw new PsbtError("not valid base64");
    }
    return Psbt.fromBytes(base64ToBytes(text));
  }

  static fromHex(hex: string): Psbt {
    return Psbt.fromBytes(hexToBytes(hex));
  }
}

/** BIP-32 path as 4-byte little-endian indices, per BIP-174. */
function encodePath(path: string): Uint8Array {
  const trimmed = path.trim();
  if (trimmed === "m" || trimmed === "") return new Uint8Array(0);
  if (!trimmed.startsWith("m/")) throw new PsbtError("derivation path must start with 'm'");

  const writer = new ByteWriter();
  for (const segment of trimmed.slice(2).split("/")) {
    const hardened = segment.endsWith("'") || segment.endsWith("h");
    const raw = hardened ? segment.slice(0, -1) : segment;
    if (!/^\d+$/.test(raw)) throw new PsbtError(`invalid path segment '${segment}'`);
    const index = Number.parseInt(raw, 10);
    if (index >= 0x80000000) throw new PsbtError("path index out of range");
    writer.writeUint32LE(hardened ? index + 0x80000000 : index);
  }
  return writer.toBytes();
}

function decodePath(data: Uint8Array): string {
  if (data.length % 4 !== 0) throw new PsbtError("derivation path length is not a multiple of 4");
  const reader = new ByteReader(data);
  const segments: string[] = [];
  while (reader.remaining > 0) {
    const value = reader.readUint32LE();
    segments.push(value >= 0x80000000 ? `${value - 0x80000000}'` : String(value));
  }
  return segments.length === 0 ? "m" : `m/${segments.join("/")}`;
}

/** Pull the 33-byte public keys out of a multisig witnessScript, in order. */
function extractPublicKeys(script: Uint8Array): Uint8Array[] {
  const keys: Uint8Array[] = [];
  let offset = 1; // skip OP_m
  while (offset < script.length - 2) {
    const length = script[offset]!;
    if (length !== 33) break; // OP_n reached, or not a plain multisig
    keys.push(script.slice(offset + 1, offset + 1 + length));
    offset += 1 + length;
  }
  return keys;
}
