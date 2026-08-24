/**
 * P2WSH MULTISIG
 *
 * The property under test is the one that motivates the whole module: at no
 * point does any machine hold enough key material to spend alone. Each signer
 * works independently; the combiner takes only public data.
 */
import { describe, it, expect } from "vitest";
import {
  MultisigAccount, multisigWitnessScript, sortPublicKeys,
  p2wshAddress, p2wshScriptPubKey, MAX_MULTISIG_PARTICIPANTS,
} from "../../core/addresses/multisig.js";
import {
  signMultisigInput, signMultisigTransaction, combineSignatures,
  verifyMultisigTransaction, signingProgress, MultisigError,
  type PartialSignature, type MultisigInput,
} from "../../core/signing/multisig.js";
import { PrivateKey } from "../../core/keys/privateKey.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../../core/transactions/transaction.js";
import { REGTEST, MAINNET } from "../../core/bitcoin/networks.js";
import { sha256 } from "../../core/crypto/hashes.js";
import { bytesToHex, hexToBytes } from "../../core/crypto/bytes.js";
import { decodeSegwitAddress, bech32Decode } from "../../core/addresses/bech32.js";

/** Three independent holders. In reality these live on three machines. */
const alice = PrivateKey.fromHex("11".repeat(32));
const bob = PrivateKey.fromHex("22".repeat(32));
const carol = PrivateKey.fromHex("33".repeat(32));
const mallory = PrivateKey.fromHex("44".repeat(32));

const pub = (key: PrivateKey) => PublicKey.fromPrivateKey(key);

const account2of3 = new MultisigAccount({
  threshold: 2,
  publicKeys: [pub(alice), pub(bob), pub(carol)],
  network: REGTEST,
});

const VALUE = 1_000_000n;
const inputs: MultisigInput[] = [{ value: VALUE, account: account2of3 }];

function unsignedTx() {
  return new Transaction(
    2,
    [new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
    [new TxOutput(900_000n, hexToBytes("0014" + "cd".repeat(20)))],
    0,
  );
}

describe("the script", () => {
  it("is OP_2 <3 keys> OP_3 OP_CHECKMULTISIG", () => {
    const script = account2of3.witnessScript;
    expect(script[0]).toBe(0x52); // OP_2
    expect(script[script.length - 2]).toBe(0x53); // OP_3
    expect(script[script.length - 1]).toBe(0xae); // OP_CHECKMULTISIG
    // 1 + 3*(1+33) + 1 + 1 = 105
    expect(script.length).toBe(105);
  });

  it("SORTS keys per BIP-67, so key ORDER does not change the address", () => {
    // Without a canonical order, three parties supplying the same keys in
    // different orders would each derive a different address and believe the
    // others were wrong.
    const a = new MultisigAccount({ threshold: 2, publicKeys: [pub(alice), pub(bob), pub(carol)], network: REGTEST });
    const b = new MultisigAccount({ threshold: 2, publicKeys: [pub(carol), pub(alice), pub(bob)], network: REGTEST });
    const c = new MultisigAccount({ threshold: 2, publicKeys: [pub(bob), pub(carol), pub(alice)], network: REGTEST });
    expect(a.address).toBe(b.address);
    expect(b.address).toBe(c.address);
  });

  it("sorted order is lexicographic by compressed key", () => {
    const sorted = sortPublicKeys([pub(carol), pub(alice), pub(bob)]);
    const hexes = sorted.map((k) => k.toHex());
    expect([...hexes].sort()).toEqual(hexes);
  });

  it("REJECTS a duplicate key", () => {
    // The same key twice would let one holder satisfy two slots, silently
    // reducing a 2-of-3 to a 1-of-2 for that participant.
    expect(() => new MultisigAccount({
      threshold: 2, publicKeys: [pub(alice), pub(alice), pub(bob)], network: REGTEST,
    })).toThrow(/duplicate public key/);
  });

  it("REJECTS a threshold above the participant count", () => {
    // 4-of-3 is unspendable, and the failure would only appear at signing.
    expect(() => multisigWitnessScript(4, [pub(alice), pub(bob), pub(carol)]))
      .toThrow(/would be unspendable/);
  });

  it("rejects degenerate configurations", () => {
    expect(() => multisigWitnessScript(0, [pub(alice), pub(bob)])).toThrow(/at least 1/);
    expect(() => multisigWitnessScript(1, [pub(alice)])).toThrow(/at least 2 participants/);
  });

  it("caps participants at the consensus limit", () => {
    const many = Array.from({ length: MAX_MULTISIG_PARTICIPANTS + 1 }, () =>
      pub(PrivateKey.generate()),
    );
    expect(() => multisigWitnessScript(2, many)).toThrow(/at most 20/);
  });
});

describe("the address", () => {
  it("commits to SHA-256 of the script, not HASH160", () => {
    // 32 bytes, not 20: a script is attacker-influenceable in multi-party
    // settings, and 20 bytes gives only ~80-bit collision resistance.
    const { program } = decodeSegwitAddress("bcrt", account2of3.address);
    expect(program.length).toBe(32);
    expect(bytesToHex(program)).toBe(bytesToHex(sha256(account2of3.witnessScript)));
  });

  it("is witness version 0, therefore BECH32 not bech32m", () => {
    expect(decodeSegwitAddress("bcrt", account2of3.address).version).toBe(0);
    expect(bech32Decode(account2of3.address).variant).toBe("bech32");
  });

  it("scriptPubKey is OP_0 PUSH32 <hash>", () => {
    const script = account2of3.scriptPubKey;
    expect(script.length).toBe(34);
    expect(script[0]).toBe(0x00);
    expect(script[1]).toBe(0x20);
  });

  it("differs from a P2WPKH address on the same network", () => {
    expect(account2of3.address.length).toBeGreaterThan(50); // longer than bc1q…
  });

  it("network prefixes are correct", () => {
    const mainnet = new MultisigAccount({
      threshold: 2, publicKeys: [pub(alice), pub(bob), pub(carol)], network: MAINNET,
    });
    expect(mainnet.address.startsWith("bc1q")).toBe(true);
    expect(account2of3.address.startsWith("bcrt1q")).toBe(true);
  });

  it("a DIFFERENT threshold gives a different address", () => {
    // The threshold is inside the script, so 2-of-3 and 3-of-3 over the same
    // keys are different addresses with different funds.
    const threeOfThree = new MultisigAccount({
      threshold: 3, publicKeys: [pub(alice), pub(bob), pub(carol)], network: REGTEST,
    });
    expect(threeOfThree.address).not.toBe(account2of3.address);
  });

  it("describes itself and exposes only public data", () => {
    expect(account2of3.describe).toBe("2-of-3");
    const json = JSON.stringify(account2of3.toJSON());
    expect(json).not.toContain(alice.toHexUnsafe());
    expect(json).not.toMatch(/private|secret|seed/i);
  });
});

describe("independent signing — no key is ever combined", () => {
  it("each participant signs alone, with only their own key", () => {
    const tx = unsignedTx();
    const fromAlice = signMultisigInput(tx, 0, inputs[0]!, alice);
    const fromBob = signMultisigInput(tx, 0, inputs[0]!, bob);

    expect(fromAlice.publicKey.equals(pub(alice))).toBe(true);
    expect(fromBob.publicKey.equals(pub(bob))).toBe(true);
    expect(bytesToHex(fromAlice.signature)).not.toBe(bytesToHex(fromBob.signature));
  });

  it("a partial signature contains NO private material", () => {
    const partial = signMultisigInput(unsignedTx(), 0, inputs[0]!, alice);
    const serialised = bytesToHex(partial.signature) + partial.publicKey.toHex();
    expect(serialised).not.toContain(alice.toHexUnsafe());
  });

  it("combineSignatures takes NO private keys — the API expresses the guarantee", () => {
    // You could not build a reconstructing coordinator by accident, because
    // there is no parameter for it.
    expect(combineSignatures.length).toBe(3); // transaction, inputs, partials
    expect(combineSignatures.toString()).not.toMatch(/privateKey|PrivateKey/);
  });

  it("REFUSES to sign for an arrangement the key does not participate in", () => {
    expect(() => signMultisigInput(unsignedTx(), 0, inputs[0]!, mallory))
      .toThrow(/not a participant/);
  });
});

describe("combining", () => {
  it("2 of 3 signatures produce a spendable transaction", () => {
    const tx = unsignedTx();
    const partials = [
      signMultisigInput(tx, 0, inputs[0]!, alice),
      signMultisigInput(tx, 0, inputs[0]!, bob),
    ];
    const signed = combineSignatures(tx, inputs, partials);
    expect(verifyMultisigTransaction(signed, inputs)).toBe(true);
  });

  it("the witness begins with the EMPTY DUMMY element", () => {
    // OP_CHECKMULTISIG pops one item more than it needs — an off-by-one that
    // could not be fixed without a hard fork. Omitting it fails the script.
    const tx = unsignedTx();
    const signed = combineSignatures(tx, inputs, [
      signMultisigInput(tx, 0, inputs[0]!, alice),
      signMultisigInput(tx, 0, inputs[0]!, bob),
    ]);
    const witness = signed.inputs[0]!.witness;
    expect(witness[0]!.length).toBe(0);
    // dummy + 2 signatures + script
    expect(witness.length).toBe(4);
    expect(bytesToHex(witness[3]!)).toBe(bytesToHex(account2of3.witnessScript));
  });

  it("ORDERS signatures to match the key order in the script", () => {
    // CHECKMULTISIG walks both in one pass and does not search; out of order
    // is a script failure with no clue as to why.
    const tx = unsignedTx();
    // Supplied deliberately backwards.
    const partials = [
      signMultisigInput(tx, 0, inputs[0]!, carol),
      signMultisigInput(tx, 0, inputs[0]!, alice),
    ];
    const signed = combineSignatures(tx, inputs, partials);
    expect(verifyMultisigTransaction(signed, inputs)).toBe(true);
  });

  it("works for every pair of participants", () => {
    for (const [x, y] of [[alice, bob], [alice, carol], [bob, carol]] as const) {
      const tx = unsignedTx();
      const signed = combineSignatures(tx, inputs, [
        signMultisigInput(tx, 0, inputs[0]!, x),
        signMultisigInput(tx, 0, inputs[0]!, y),
      ]);
      expect(verifyMultisigTransaction(signed, inputs)).toBe(true);
    }
  });

  it("drops signatures beyond the threshold", () => {
    const tx = unsignedTx();
    const signed = combineSignatures(tx, inputs, [
      signMultisigInput(tx, 0, inputs[0]!, alice),
      signMultisigInput(tx, 0, inputs[0]!, bob),
      signMultisigInput(tx, 0, inputs[0]!, carol),
    ]);
    // A leftover signature costs witness bytes and fails CHECKMULTISIG.
    expect(signed.inputs[0]!.witness.length).toBe(4);
  });
});

describe("ATTACK: one holder tries to spend alone", () => {
  it("a single signature is REFUSED — the whole point", () => {
    const tx = unsignedTx();
    expect(() => combineSignatures(tx, inputs, [signMultisigInput(tx, 0, inputs[0]!, alice)]))
      .toThrow(/1 of 2 required signatures/);
  });

  it("the SAME participant twice does not satisfy the threshold", () => {
    // Otherwise one holder could sign twice and spend alone.
    const tx = unsignedTx();
    const partial = signMultisigInput(tx, 0, inputs[0]!, alice);
    expect(() => combineSignatures(tx, inputs, [partial, { ...partial }]))
      .toThrow(/two signatures from the same participant/);
  });

  it("a non-participant's signature is REJECTED", () => {
    const tx = unsignedTx();
    const outsider: PartialSignature = {
      inputIndex: 0,
      signature: signMultisigInput(tx, 0, [{ value: VALUE, account: new MultisigAccount({
        threshold: 2, publicKeys: [pub(mallory), pub(alice), pub(bob)], network: REGTEST,
      }) }][0]!, mallory).signature,
      publicKey: pub(mallory),
    };
    expect(() => combineSignatures(tx, inputs, [
      signMultisigInput(tx, 0, inputs[0]!, alice), outsider,
    ])).toThrow(/not a participant/);
  });

  it("a forged signature attributed to a real participant is REJECTED", () => {
    // A coordinator is untrusted by assumption, so this must be caught here
    // rather than at broadcast.
    const tx = unsignedTx();
    const real = signMultisigInput(tx, 0, inputs[0]!, alice);
    const forged: PartialSignature = {
      inputIndex: 0,
      signature: real.signature, // Alice's signature…
      publicKey: pub(bob), // …claimed as Bob's
    };
    expect(() => combineSignatures(tx, inputs, [real, forged]))
      .toThrow(/does not verify against the claimed public key/);
  });

  it("a signature for a DIFFERENT transaction is rejected", () => {
    const tx = unsignedTx();
    const other = new Transaction(
      2, tx.inputs,
      [new TxOutput(500_000n, hexToBytes("0014" + "ee".repeat(20)))],
      0,
    );
    const wrongTx = signMultisigInput(other, 0, inputs[0]!, bob);
    expect(() => combineSignatures(tx, inputs, [
      signMultisigInput(tx, 0, inputs[0]!, alice), wrongTx,
    ])).toThrow(/does not verify/);
  });
});

describe("ATTACK: tampering after signatures are collected", () => {
  function signedTx() {
    const tx = unsignedTx();
    return combineSignatures(tx, inputs, [
      signMultisigInput(tx, 0, inputs[0]!, alice),
      signMultisigInput(tx, 0, inputs[0]!, bob),
    ]);
  }

  it("changing the recipient invalidates it", () => {
    const signed = signedTx();
    const tampered = new Transaction(
      signed.version, signed.inputs,
      [new TxOutput(900_000n, hexToBytes("0014" + "ff".repeat(20)))],
      signed.locktime,
    );
    expect(verifyMultisigTransaction(tampered, inputs)).toBe(false);
  });

  it("changing the amount by one satoshi invalidates it", () => {
    const signed = signedTx();
    const tampered = new Transaction(
      signed.version, signed.inputs,
      [new TxOutput(900_001n, signed.outputs[0]!.scriptPubKey)],
      signed.locktime,
    );
    expect(verifyMultisigTransaction(tampered, inputs)).toBe(false);
  });

  it("REMOVING the dummy element invalidates the witness", () => {
    const signed = signedTx();
    const witness = signed.inputs[0]!.witness.slice(1);
    const broken = signed.withInput(0, signed.inputs[0]!.withWitness(witness));
    expect(verifyMultisigTransaction(broken, inputs)).toBe(false);
  });

  it("swapping in a DIFFERENT witnessScript invalidates it", () => {
    // The signature commits to the script, so a participant cannot be tricked
    // into signing for a 1-of-3 they believed was 2-of-3.
    const signed = signedTx();
    const other = new MultisigAccount({
      threshold: 1, publicKeys: [pub(alice), pub(mallory)], network: REGTEST,
    });
    const witness = [...signed.inputs[0]!.witness];
    witness[witness.length - 1] = other.witnessScript;
    const broken = signed.withInput(0, signed.inputs[0]!.withWitness(witness));
    expect(verifyMultisigTransaction(broken, inputs)).toBe(false);
  });

  it("lying about the input value invalidates it — BIP-143 signs the amount", () => {
    const signed = signedTx();
    expect(verifyMultisigTransaction(signed, [{ value: VALUE + 1n, account: account2of3 }]))
      .toBe(false);
  });

  it("corrupting any byte of a signature invalidates it", () => {
    const signed = signedTx();
    const signature = signed.inputs[0]!.witness[1]!;
    let broken = 0;
    for (let i = 0; i < signature.length; i++) {
      const mutated = Uint8Array.from(signature);
      mutated[i] = mutated[i]! ^ 0xff;
      const witness = [...signed.inputs[0]!.witness];
      witness[1] = mutated;
      if (!verifyMultisigTransaction(signed.withInput(0, signed.inputs[0]!.withWitness(witness)), inputs)) {
        broken++;
      }
    }
    expect(broken).toBe(signature.length);
  });
});

describe("thresholds and progress", () => {
  it("3-of-5 requires exactly three", () => {
    const keys = [alice, bob, carol, mallory, PrivateKey.fromHex("55".repeat(32))];
    const account = new MultisigAccount({
      threshold: 3, publicKeys: keys.map(pub), network: REGTEST,
    });
    const local: MultisigInput[] = [{ value: VALUE, account }];
    const tx = unsignedTx();

    const two = keys.slice(0, 2).map((k) => signMultisigInput(tx, 0, local[0]!, k));
    expect(() => combineSignatures(tx, local, two)).toThrow(/2 of 3 required/);

    const three = keys.slice(0, 3).map((k) => signMultisigInput(tx, 0, local[0]!, k));
    expect(verifyMultisigTransaction(combineSignatures(tx, local, three), local)).toBe(true);
  });

  it("progress reports who is still missing", () => {
    const tx = unsignedTx();
    const partials = [signMultisigInput(tx, 0, inputs[0]!, alice)];
    const [progress] = signingProgress(inputs, partials);

    expect(progress!.collected).toBe(1);
    expect(progress!.required).toBe(2);
    expect(progress!.complete).toBe(false);
    expect(progress!.missing.length).toBe(2);
    expect(progress!.missing).not.toContain(pub(alice).toHex());
  });

  it("progress reveals nothing secret", () => {
    const tx = unsignedTx();
    const [progress] = signingProgress(inputs, [signMultisigInput(tx, 0, inputs[0]!, alice)]);
    // Everything here is already public in the witnessScript.
    expect(JSON.stringify(progress)).not.toContain(alice.toHexUnsafe());
  });

  it("signMultisigTransaction skips inputs the key does not control", () => {
    const tx = unsignedTx();
    const partials = signMultisigTransaction(tx, inputs, mallory);
    expect(partials.length).toBe(0);
  });
});

describe("fee estimation accounts for the larger witness", () => {
  it("a 2-of-3 witness is bigger than a single-key one", () => {
    // A wallet that under-estimates produces transactions that will not relay.
    expect(account2of3.estimatedWitnessVsize).toBeGreaterThan(27); // P2WPKH ≈ 27 vbytes
  });

  it("more signatures cost more", () => {
    const threeOfFive = new MultisigAccount({
      threshold: 3,
      publicKeys: [alice, bob, carol, mallory, PrivateKey.fromHex("66".repeat(32))].map(pub),
      network: REGTEST,
    });
    expect(threeOfFive.estimatedWitnessVsize).toBeGreaterThan(account2of3.estimatedWitnessVsize);
  });
});
