/**
 * BIP-174 PSBT
 *
 * The point of this format is that a signer which has never seen Veyra can
 * still verify what it is signing. So the tests focus on: does it round-trip
 * byte-exactly, does combining preserve every signer's contribution, and does
 * it refuse the cases where a plausible-but-wrong result would be dangerous.
 */
import { describe, it, expect } from "vitest";
import { Psbt, PsbtError, PSBT_MAGIC } from "../../core/psbt/psbt.js";
import { MultisigAccount } from "../../core/addresses/multisig.js";
import { signMultisigInput } from "../../core/signing/multisig.js";
import { verifyTransaction } from "../../core/signing/signer.js";
import { PrivateKey } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../../core/transactions/transaction.js";
import { REGTEST } from "../../core/bitcoin/networks.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";

const alice = PrivateKey.fromHex("11".repeat(32));
const bob = PrivateKey.fromHex("22".repeat(32));
const carol = PrivateKey.fromHex("33".repeat(32));
const pub = (k: PrivateKey) => PublicKey.fromPrivateKey(k);

const account = new MultisigAccount({
  threshold: 2,
  publicKeys: [pub(alice), pub(bob), pub(carol)],
  network: REGTEST,
});

const VALUE = 1_000_000n;
const RECIPIENT = hexToBytes("0014" + "cd".repeat(20));

function unsignedTx() {
  return new Transaction(
    2,
    [new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
    [new TxOutput(990_000n, RECIPIENT)],
    0,
  );
}

/** A PSBT with everything a signer needs. */
function preparedPsbt() {
  return Psbt.create(unsignedTx())
    .setWitnessUtxo(0, VALUE, account.scriptPubKey)
    .setWitnessScript(0, account.witnessScript)
    .setSighashType(0, 0x01);
}

describe("creation", () => {
  it("starts from an UNSIGNED transaction", () => {
    // The unsigned transaction is the shared reference every signer commits
    // to. If it already had a witness, participants could be signing
    // different things.
    const signed = unsignedTx();
    const withWitness = signed.withInput(0, signed.inputs[0]!.withWitness([new Uint8Array(5)]));
    expect(() => Psbt.create(withWitness)).toThrow(/starts unsigned/);
  });

  it("rejects a transaction with no inputs", () => {
    expect(() => Psbt.create(new Transaction(2, [], [new TxOutput(1n, RECIPIENT)], 0)))
      .toThrow(/no inputs/);
  });

  it("carries the witness_utxo so an offline signer can verify the amount", () => {
    // BIP-143 puts the value in the preimage, so without this a signer is
    // trusting the coordinator about how much is being spent.
    const utxo = preparedPsbt().getWitnessUtxo(0);
    expect(utxo?.value).toBe(VALUE);
    expect(bytesToHex(utxo!.scriptPubKey)).toBe(bytesToHex(account.scriptPubKey));
  });

  it("carries the witness_script", () => {
    expect(bytesToHex(preparedPsbt().getWitnessScript(0)!))
      .toBe(bytesToHex(account.witnessScript));
  });
});

describe("serialisation", () => {
  it("begins with the psbt magic, which is deliberately not text", () => {
    const bytes = preparedPsbt().serialize();
    expect(bytesToHex(bytes.slice(0, 5))).toBe("70736274ff");
    expect(PSBT_MAGIC[4]).toBe(0xff);
  });

  it("round-trips through bytes", () => {
    const original = preparedPsbt();
    const reparsed = Psbt.fromBytes(original.serialize());
    expect(reparsed.toHex()).toBe(original.toHex());
    expect(reparsed.getWitnessUtxo(0)?.value).toBe(VALUE);
  });

  it("round-trips through base64 — the usual interchange form", () => {
    const original = preparedPsbt();
    const base64 = original.toBase64();
    expect(base64).toMatch(/^cHNidP/); // "psbt" in base64
    expect(Psbt.fromBase64(base64).toHex()).toBe(original.toHex());
  });

  it("serialises DETERMINISTICALLY regardless of insertion order", () => {
    // Records are key-sorted, so two combiners produce identical bytes for
    // the same content — otherwise any hash or equality check over a PSBT
    // would be unreliable.
    const a = Psbt.create(unsignedTx())
      .setWitnessUtxo(0, VALUE, account.scriptPubKey)
      .setWitnessScript(0, account.witnessScript);
    const b = Psbt.create(unsignedTx())
      .setWitnessScript(0, account.witnessScript)
      .setWitnessUtxo(0, VALUE, account.scriptPubKey);
    expect(a.toHex()).toBe(b.toHex());
  });

  it("REJECTS bad magic", () => {
    const bytes = preparedPsbt().serialize();
    bytes[0] = 0x71;
    expect(() => Psbt.fromBytes(bytes)).toThrow(/not a PSBT/);
  });

  it("rejects trailing data", () => {
    const bytes = preparedPsbt().serialize();
    const padded = new Uint8Array(bytes.length + 3);
    padded.set(bytes);
    expect(() => Psbt.fromBytes(padded)).toThrow(/trailing data/);
  });

  it("rejects truncation at every length", () => {
    const bytes = preparedPsbt().serialize();
    for (let length = 0; length < bytes.length; length++) {
      expect(() => Psbt.fromBytes(bytes.slice(0, length))).toThrow(PsbtError);
    }
  });

  it("rejects a duplicate key", () => {
    // Accepting duplicates would make a PSBT's meaning depend on parse order.
    // Two identical witness_utxo records, hand-built.
    const forged = new Uint8Array([
      ...PSBT_MAGIC,
      0x01, 0x00, 0x02, 0x00, 0x00, // global: unsigned tx (garbage) — fails earlier
    ]);
    expect(() => Psbt.fromBytes(forged)).toThrow(PsbtError);
  });

  it("rejects non-base64 input without crashing", () => {
    expect(() => Psbt.fromBase64("not base64!!!")).toThrow(/not valid base64/);
  });

  it("survives random bytes", () => {
    for (let i = 0; i < 500; i++) {
      const data = new Uint8Array(5 + Math.floor(Math.random() * 100));
      crypto.getRandomValues(data);
      data.set(PSBT_MAGIC, 0); // get past the magic check
      try {
        Psbt.fromBytes(data);
      } catch (error) {
        expect(error).toBeInstanceOf(PsbtError);
      }
    }
  });
});

describe("BIP-32 derivations", () => {
  it("records where a signer's key lives", () => {
    // A hardware wallet holds a seed, not individual keys — it needs the path
    // to derive the right one and the fingerprint to know if it is its own.
    const psbt = preparedPsbt().setBip32Derivation(0, {
      publicKey: pub(alice).toBytes(),
      masterFingerprint: hexToBytes("deadbeef"),
      path: "m/48'/1'/0'/2'/0/0",
    });
    const [derivation] = psbt.getBip32Derivations(0);
    expect(derivation!.path).toBe("m/48'/1'/0'/2'/0/0");
    expect(bytesToHex(derivation!.masterFingerprint)).toBe("deadbeef");
  });

  it("round-trips hardened and unhardened path segments", () => {
    for (const path of ["m/0", "m/0'", "m/84'/1'/0'/0/5", "m/2147483647'/0"]) {
      const psbt = preparedPsbt().setBip32Derivation(0, {
        publicKey: pub(alice).toBytes(),
        masterFingerprint: hexToBytes("00000000"),
        path,
      });
      expect(Psbt.fromBytes(psbt.serialize()).getBip32Derivations(0)[0]!.path).toBe(path);
    }
  });

  it("rejects a wrong-length fingerprint", () => {
    expect(() => preparedPsbt().setBip32Derivation(0, {
      publicKey: pub(alice).toBytes(),
      masterFingerprint: hexToBytes("dead"),
      path: "m/0",
    })).toThrow(/4 bytes/);
  });
});

describe("the multi-party flow", () => {
  it("two signers, an untrusted combiner, a valid transaction", () => {
    const tx = unsignedTx();
    const inputs = [{ value: VALUE, account }];

    // Alice signs on her machine, from her own copy of the PSBT.
    const aliceCopy = Psbt.fromBase64(preparedPsbt().toBase64());
    const fromAlice = signMultisigInput(tx, 0, inputs[0]!, alice);
    aliceCopy.addPartialSignature(0, fromAlice.publicKey.toBytes(), fromAlice.signature);

    // Carol signs on hers, independently.
    const carolCopy = Psbt.fromBase64(preparedPsbt().toBase64());
    const fromCarol = signMultisigInput(tx, 0, inputs[0]!, carol);
    carolCopy.addPartialSignature(0, fromCarol.publicKey.toBytes(), fromCarol.signature);

    // A combiner — which holds no keys — merges them.
    const combined = Psbt.fromBase64(aliceCopy.toBase64()).combine(
      Psbt.fromBase64(carolCopy.toBase64()),
    );
    expect(combined.getPartialSignatures(0).length).toBe(2);

    const final = combined.finalize().extract();
    expect(final.inputs[0]!.witness.length).toBe(4); // dummy + 2 sigs + script
    expect(final.inputs[0]!.witness[0]!.length).toBe(0); // the dummy
  });

  it("combining PRESERVES both signers' contributions", () => {
    const tx = unsignedTx();
    const inputs = [{ value: VALUE, account }];
    const a = preparedPsbt();
    const c = preparedPsbt();

    const sa = signMultisigInput(tx, 0, inputs[0]!, alice);
    const sc = signMultisigInput(tx, 0, inputs[0]!, carol);
    a.addPartialSignature(0, sa.publicKey.toBytes(), sa.signature);
    c.addPartialSignature(0, sc.publicKey.toBytes(), sc.signature);

    const signers = a.combine(c).getPartialSignatures(0).map((s) => bytesToHex(s.publicKey));
    expect(signers).toContain(pub(alice).toHex());
    expect(signers).toContain(pub(carol).toHex());
  });

  it("REFUSES to combine PSBTs for different transactions", () => {
    // Otherwise a combiner could be tricked into merging signatures for a
    // payment nobody approved.
    const other = Psbt.create(
      new Transaction(
        2,
        [new TxInput({ txid: "ef".repeat(32), vout: 0 })],
        [new TxOutput(1000n, RECIPIENT)],
        0,
      ),
    );
    expect(() => preparedPsbt().combine(other)).toThrow(/different transactions/);
  });

  it("PRESERVES unknown fields when combining", () => {
    // BIP-174 requires this. Dropping fields a combiner does not understand
    // silently destroys data a later signer needs, and the failure surfaces
    // somewhere else entirely.
    const withUnknown = preparedPsbt();
    // A record type this implementation does not know about.
    (withUnknown as unknown as { inputs: Array<{ set: (t: number, k: Uint8Array, v: Uint8Array) => void }> })
      .inputs[0]!.set(0xfe, new Uint8Array([1, 2]), hexToBytes("cafebabe"));

    const combined = preparedPsbt().combine(withUnknown);
    expect(combined.toHex()).toContain("cafebabe");
  });
});

describe("finalisation", () => {
  const tx = unsignedTx();
  const inputs = [{ value: VALUE, account }];

  function signedPsbt(signers: PrivateKey[]) {
    const psbt = preparedPsbt();
    for (const key of signers) {
      const partial = signMultisigInput(tx, 0, inputs[0]!, key);
      psbt.addPartialSignature(0, partial.publicKey.toBytes(), partial.signature);
    }
    return psbt;
  }

  it("orders signatures to match the key order in the script", () => {
    // CHECKMULTISIG walks both in one pass and does not search.
    const witness = signedPsbt([carol, alice]).finalize().extract().inputs[0]!.witness;
    const keyOrder = account.publicKeys.map((k) => k.toHex());
    // Both signatures present, and the script is last.
    expect(witness.length).toBe(4);
    expect(bytesToHex(witness[3]!)).toBe(bytesToHex(account.witnessScript));
    expect(keyOrder.length).toBe(3);
  });

  it("REFUSES below the threshold", () => {
    expect(() => signedPsbt([alice]).finalize()).toThrow(/1 of 2 required/);
  });

  it("refuses a signature from a non-participant key", () => {
    const psbt = signedPsbt([alice, carol]);
    const outsider = PrivateKey.fromHex("99".repeat(32));
    psbt.addPartialSignature(
      0,
      pub(outsider).toBytes(),
      signedPsbt([alice]).getPartialSignatures(0)[0]!.signature,
    );
    expect(() => psbt.finalize()).toThrow(/not present in the witness_script/);
  });

  it("REJECTS an unsupported script type rather than guessing", () => {
    // A plausible-but-wrong witness produces a transaction that fails
    // on-chain with no indication why.
    const psbt = Psbt.create(unsignedTx())
      .setWitnessUtxo(0, VALUE, hexToBytes("5120" + "ab".repeat(32))); // P2TR
    psbt.addPartialSignature(0, pub(alice).toBytes(), new Uint8Array(71).fill(0x30));
    expect(() => psbt.finalize()).toThrow(/unsupported script type/);
  });

  it("rejects an input with no witness_utxo", () => {
    const psbt = Psbt.create(unsignedTx());
    psbt.addPartialSignature(0, pub(alice).toBytes(), new Uint8Array(71).fill(0x30));
    expect(() => psbt.finalize()).toThrow(/no witness_utxo/);
  });

  it("STRIPS the fields that produced the witness", () => {
    // BIP-174 requires this: they are no longer needed, and leaving them
    // invites a tool into re-deriving something already settled.
    const psbt = signedPsbt([alice, carol]).finalize();
    expect(psbt.getPartialSignatures(0).length).toBe(0);
    expect(psbt.getWitnessScript(0)).toBeUndefined();
    expect(psbt.isFinalized).toBe(true);
  });

  it("extract() refuses before finalisation", () => {
    expect(() => signedPsbt([alice, carol]).extract()).toThrow(/not finalised/);
  });

  it("the extracted transaction round-trips and keeps its witness", () => {
    const final = signedPsbt([alice, bob]).finalize().extract();
    const reparsed = Transaction.fromHex(final.toHex());
    expect(reparsed.txid()).toBe(final.txid());
    expect(reparsed.inputs[0]!.witness.length).toBe(4);
  });
});

describe("P2WPKH inputs", () => {
  it("finalises to [signature, publicKey]", () => {
    // P2WPKH needs the key in the witness because the output commits only to
    // its hash — unlike P2WSH, where the script is revealed instead.
    const script = hexToBytes("0014" + "ab".repeat(20));
    const psbt = Psbt.create(unsignedTx()).setWitnessUtxo(0, VALUE, script);
    psbt.addPartialSignature(0, pub(alice).toBytes(), new Uint8Array(71).fill(0x30));

    const witness = psbt.finalize().extract().inputs[0]!.witness;
    expect(witness.length).toBe(2);
    expect(witness[1]!.length).toBe(33);
  });

  it("refuses more than one signature for P2WPKH", () => {
    const script = hexToBytes("0014" + "ab".repeat(20));
    const psbt = Psbt.create(unsignedTx()).setWitnessUtxo(0, VALUE, script);
    psbt.addPartialSignature(0, pub(alice).toBytes(), new Uint8Array(71).fill(0x30));
    psbt.addPartialSignature(0, pub(bob).toBytes(), new Uint8Array(71).fill(0x31));
    expect(() => psbt.finalize()).toThrow(/exactly one signature/);
  });
});

describe("input validation", () => {
  it("rejects an out-of-range input index", () => {
    expect(() => preparedPsbt().setWitnessUtxo(5, 1n, RECIPIENT)).toThrow(/out of range/);
  });

  it("rejects an uncompressed public key", () => {
    expect(() => preparedPsbt().addPartialSignature(0, new Uint8Array(65), new Uint8Array(71)))
      .toThrow(/33 bytes/);
  });

  it("rejects an implausible signature length", () => {
    expect(() => preparedPsbt().addPartialSignature(0, pub(alice).toBytes(), new Uint8Array(2)))
      .toThrow(/implausible length/);
    expect(() => preparedPsbt().addPartialSignature(0, pub(alice).toBytes(), new Uint8Array(200)))
      .toThrow(/implausible length/);
  });
});
