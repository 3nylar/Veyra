# Veyra — Multisig

> **The single-seed problem.** Everywhere else in Veyra, one compromised seed
> means total, silent, permanent loss. Multisig is the answer to that, and it
> is the only feature here that changes the *shape* of the risk rather than
> reducing its probability.

---

## Why P2WSH and not Shamir secret sharing

Both split control across several holders. They differ in one decisive respect.

| | Shamir | Multisig |
| --- | --- | --- |
| What is split | One private key, into shares | Nothing — each holder has their own key |
| To sign | Shares are **recombined** | Each signs independently |
| Worst moment | One machine briefly holds the whole key | No such moment exists |
| Enforced by | The software implementing it | **Bitcoin consensus** |
| Verifiable by others | No | Yes — the script is on-chain |

The recombination step is the problem. Compromise that machine at that instant
and you have everything; the split is a storage property, not a signing one.

And a Shamir threshold is only as good as the code enforcing it. If that code
has a bug, the network will happily accept a transaction signed by a
reconstructed key — because as far as Bitcoin is concerned, it *is* a valid
single-key signature. A multisig threshold is enforced by every node.

**The trade-offs are real.** Multisig costs more in fees, is visible on-chain
before Taproot, and fixes the participant set at address-creation time. Shamir
is cheaper and invisible. For a project whose argument is that you should be
able to verify what it does, consensus-enforced beats software-enforced.

---

## The guarantee, expressed in the API

```ts
combineSignatures(transaction, inputs, partials)   // no private key parameter
```

`combineSignatures` takes no private keys **and cannot**. A coordinator that
reconstructs a key is not something you could build here by accident, because
there is no argument for it. The coordinator can be entirely untrusted — it
handles only signatures, which are public and useless for anything but the
transaction they were made for.

---

## Usage

```ts
const account = new MultisigAccount({
  threshold: 2,
  publicKeys: [alicePub, bobPub, carolPub],
  network: REGTEST,
});

account.address;    // bcrt1q… (P2WSH)
account.describe;   // "2-of-3"
```

Each holder signs on their own machine:

```ts
const mine = signMultisigInput(tx, 0, { value, account }, myPrivateKey);
// send `mine` anywhere — it contains no private material
```

Anyone combines:

```ts
const signed = combineSignatures(tx, [{ value, account }], [fromAlice, fromCarol]);
verifyMultisigTransaction(signed, [{ value, account }]);   // true
```

---

## Three details that are easy to get wrong

### The empty dummy element

```
witness = [ <empty>, sig_1, … sig_t, witnessScript ]
```

`OP_CHECKMULTISIG` pops one item more than it needs — an off-by-one in the
original implementation that could not be fixed without a hard fork. Omitting
the empty element fails the script. It is the most common mistake in
hand-written multisig code, and only a real node catches it.

### Signature order is consensus-critical

`OP_CHECKMULTISIG` walks signatures and public keys in a **single pass** and
does not search. Signatures must appear in the same relative order as their
keys in the script. Out of order is a script failure with no message
indicating why. `combineSignatures` sorts for you.

### Keys are sorted (BIP-67)

Public keys are ordered lexicographically before entering the script. Without
a canonical order, three parties supplying the same three keys in different
orders would derive three *different* addresses — each believing the others
were wrong.

---

## What is checked, and where

| Check | Enforced by |
| --- | --- |
| Threshold met | Veyra locally, **and** Bitcoin consensus |
| Signature belongs to a participant | Veyra — the combiner is untrusted |
| No duplicate signer | Veyra — one holder must not fill two slots |
| Signature verifies | Veyra, and every node |
| Witness structure | **Only** a node — see the regtest suite |

Veyra's local refusals are a convenience: they produce a clear error instead of
an opaque network rejection. The guarantee that actually protects the funds is
consensus, and `tests/integration/regtest.test.ts` proves it — one test
confirms Core **accepts** a 2-of-3 spend, another confirms it **rejects** a
single-signature attempt on the same output.

---

## Setting one up (BIP-48)

Raw public keys make multisig a primitive, not something a person can use.
BIP-48 gives each participant an HD branch, so they exchange account xpubs
**once** and thereafter derive the same unlimited sequence of shared addresses
independently.

```
m / 48' / coin_type' / account' / 2' / change / index
                                  └─ script type: 2' = native P2WSH
```

Each participant derives and shares their account key:

```ts
const mine = Bip48MultisigWallet.deriveAccountKey(myMaster, REGTEST, 0);
mine.toExtendedPublicKey("testnet");   // tpub… — send this to the others
```

Everyone constructs the identical wallet from the collected set:

```ts
const shared = Bip48MultisigWallet.fromExtendedKeys({
  threshold: 2,
  accountKeys: [tpubAlice, tpubBob, tpubCarol],
  network: REGTEST,
});

shared.receiveAddress(0).address;   // every participant derives the same one
```

### Order does not matter

Keys are sorted per BIP-67 at every index. Without that, three participants
listing their xpubs in three different orders would derive three *different*
addresses at index 0 — each convinced the others were wrong, with funds
possibly sent somewhere only one of them was watching.

### ⚠️ Verify the setup out of band

`shared.descriptor()` produces a record to compare through a channel the
coordinator does not control.

An attacker who substitutes one participant's xpub for their own creates a
wallet where **they** are a co-signer. The addresses look completely normal,
funds arrive normally, and nothing reveals the substitution until a spend needs
a signature nobody can produce. Comparing the first receive address and the
fingerprints out of band is the only defence.

### ⚠️ Multisig distributes spending authority, not visibility

An account xpub reveals every address in its subtree and every balance
attached to them. Sharing it is unavoidable — co-signers cannot derive the
addresses otherwise — so **anyone you add as a co-signer can watch everything**.
That is a property of multisig, not of this implementation.

## PSBT

Partial signatures are exchanged as **BIP-174 PSBTs**, so a participant does
not have to run Veyra. A hardware wallet, Sparrow, or Bitcoin Core can hold one
of the keys.

That matters more than it first appears: a proprietary partial-signature format
would replace *"trust one seed"* with *"trust one codebase"* — which is barely
an improvement for a scheme whose purpose is distributing trust.

```ts
const psbt = Psbt.create(unsignedTx)
  .setWitnessUtxo(0, value, account.scriptPubKey)
  .setWitnessScript(0, account.witnessScript);

psbt.toBase64();     // cHNidP8B… — hand this to any signer
```

Each holder signs their own copy; anyone combines them:

```ts
combined = Psbt.fromBase64(a).combine(Psbt.fromBase64(b));
const tx = combined.finalize().extract();
```

### Three rules the format depends on

**Unknown fields are preserved.** A PSBT may pass through several tools. A
combiner that drops fields it does not understand silently destroys data a
later signer needs, and the failure appears somewhere else entirely.

**`witness_utxo` carries the amount.** BIP-143 puts the input value inside the
signature preimage, so an offline signer needs it to verify what it is
committing to. Without it, a signer is trusting the coordinator about how much
is being spent.

**Serialisation is deterministic.** Records are key-sorted, so two combiners
produce identical bytes for the same content — otherwise any hash or equality
check over a PSBT would be unreliable.

### What is NOT supported

`non_witness_utxo`, legacy P2PKH/P2SH, Taproot fields (BIP-371), PSBT v2
(BIP-370), and proprietary fields. Unsupported inputs are **rejected at
finalisation** rather than best-effort finalised — a plausible-but-wrong
witness produces a transaction that fails on-chain with no indication why.

Two regtest tests check this against Bitcoin Core: one confirms Core can
`decodepsbt` a Veyra-produced PSBT, the other broadcasts a transaction
extracted from a two-signer PSBT round-tripped through base64.

## Limitations

- **PSBT covers SegWit only.** No `non_witness_utxo`, so legacy inputs and
  some hardware-wallet flows are unsupported.
- **Not wired into `Wallet`.** Multisig is a separate primitive; the wallet's
  send flow is still single-key.
- **Participant set is fixed** at address creation. Changing it means moving
  the funds to a new address.
- **Taproot multisig (MuSig2/FROST)** would be cheaper and indistinguishable
  from a single-key spend. Not implemented.
