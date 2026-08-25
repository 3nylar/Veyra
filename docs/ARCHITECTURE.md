# Veyra — Architecture

---

## Dependency direction

```
   app/  ──┐
           ├──►  core/
   api/  ──┘      └── depends on nothing in this repository
```

`app/` and `api/` are two independent front ends over the same wallet core, not
a stack. The browser pages import `core/` directly and talk to a chain source
themselves; the HTTP API is a separate, localhost-only tool. Neither depends on
the other.

> Until increment 21 this read `app/ ──► api/ ──► core/`, because the interface
> was a React client for the API. That client was never deployed and was
> removed; the diagram had been describing an arrangement that no longer
> shipped.

`core/` must never import from `api/` or `app/`, and must not use Node-only or
DOM-only APIs. That is what makes it testable without a server and genuinely
portable — it runs unchanged in Node, a browser, and React Native.

Both halves are **enforced by source scans**, not by convention:
`tests/cryptography/portability.test.ts` fails the build on any `node:` import,
`Buffer`, or DOM global. That guard exists because the portability claim sat in
this document for months while being false — see [ATTACKS.md](ATTACKS.md)
VEY-014.

Within `core/`, dependencies point downward only:

```
   wallet/ ──► utxo/, transactions/, signing/, addresses/, chain/
      │
      └──► derivation/ ──► keys/ ──► crypto/
                                       └── reference/  (imported by NOTHING)
```

---

## The three boundaries

### 1. The secrecy boundary — `core/wallet/`

Secrets stop here. `Wallet` holds the seed and derives keys; everything above
it deals in addresses, amounts, and transaction hex.

There is **no `getMnemonic()`** and **no `exportPrivateKey()`**. Not guarded,
not admin-only — absent. The mnemonic is returned exactly once, at creation.
Lose it and the funds are unrecoverable, which is the honest position for
self-custody: *a copy the wallet can retrieve is a copy an attacker can
retrieve.*

### 2. The trust boundary — `api/`

Everything crossing inward is hostile until validated. Authentication, rate
limiting, body limits, and strict parsing live here. No route and no service
method can reach key material, and a reflection test fails the build if one is
added.

### 3. The isolation boundary — `core/crypto/reference/`

Readable, dependency-free SHA-256 and secp256k1, kept **out** of production by
a source scan. They are correct — and timing-unsafe by construction, since
double-and-add leaks the scalar's bit pattern. A correct-but-unsafe
implementation passes every functional test, so only a structural guard works.

---

## Module map

| Module | Responsibility |
| --- | --- |
| `core/crypto/` | Entropy, hashes, byte utilities |
| `core/keys/` | Private and public keys, validation, redaction |
| `core/mnemonic/` | BIP-39: wordlist, checksum, seed derivation |
| `core/derivation/` | BIP-32 hierarchical deterministic keys |
| `core/addresses/` | Bech32/Bech32m, BIP-84 addresses |
| `core/bitcoin/` | Networks, wire serialisation |
| `core/transactions/` | Transaction model, parsing, txid |
| `core/signing/` | BIP-143 sighash, ECDSA, the signer |
| `core/utxo/` | UTXO set, fees, coin selection |
| `core/wallet/` | The secrecy boundary; orchestration |
| `core/chain/` | Chain sources: Esplora, Bitcoin Core RPC, in-memory |
| `core/errors/` | Typed errors that never carry secrets |
| `api/src/` | HTTP boundary |

---

## Key design decisions and their trade-offs

**Audited libraries for anything touching a key.** `@noble/curves` and
`@noble/hashes` — both audited, zero transitive dependencies, no native
bindings. Zero transitive dependencies is a security criterion, not a nicety:
every transitive package is a supply-chain entry point into a process holding
private keys.

**Bech32 implemented rather than imported.** It is an error-detecting code, not
a secret — the input is public by definition, so there is no timing sensitivity
and the constant-time argument does not apply. It is also the best-specified
algorithm in Bitcoin, with published *invalid* vectors.

**The API server uses no framework.** Body limits, header handling, and error
serialisation are all security-relevant, and a framework would hide them. The
trade-off is real: Express is far better tested than this router, and any
internet-facing deployment needs a reverse proxy regardless.

**Immutable value types.** `Transaction`, `TxInput`, `UtxoSet` return new
instances rather than mutating. A UTXO set that changes underneath a
transaction being built is a race condition with money attached.

**BigInt for all amounts.** JSON numbers are IEEE doubles; `0.1 * 1e8` is
`10000000.000000002`. "Usually correct" is not a property money arithmetic may
have.

**Errors carry two messages.** A public one (constant strings, no interpolated
state) and an internal one logged server-side. Separate fields, so the
serialiser cannot send the wrong one.

---

## Not yet built

Lightning. Persistent wallet state — the RBF replacement map lives in memory,
so restarting loses the ability to fee-bump anything broadcast before it.
Broadcasting has never been exercised against a live chain source, and nothing
has been driven through a real browser end to end.

No directory exists for any of it, because an empty directory in a tree implies
work that has not happened.
