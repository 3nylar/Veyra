# Veyra — Testing

**593 tests across 20 files** — 583 that need no node, plus 10 regtest
integration tests. All 593 passing as of 2026-08-20.

The philosophy: a test is only worth having if it could fail for a reason that
matters. Several tests in this repository exist specifically because they catch
failures that *no behavioural test can*.

---

## Layers

| Directory | Count | Purpose |
| --- | --- | --- |
| `tests/cryptography/` | 260 | Primitives against official vectors |
| `tests/security/` | 52 | Written as attacks, not assertions |
| `tests/unit/` | 141 | Serialisation, wallet, chain sync |
| `tests/fuzz/` | 18 | Malformed input against parsers |
| `api/tests/` | 55 | Every §21 attack category |
| `tests/integration/` | 10 | Consensus validation against Bitcoin Core ✅ |

```powershell
npm test             # everything
npm run test:unit    # no node required
npm run test:api     # API attacks
npm run test:regtest # needs bitcoind — see REGTEST.md
npm run typecheck    # strict TS: noUncheckedIndexedAccess, exactOptionalPropertyTypes
```

---

## 1. Official vectors, never self-consistency

Testing an implementation against its own output proves only that it agrees
with itself. For a wallet that is worthless: the entire purpose of BIP-39 is
that *other* wallets can read the phrase.

| Standard | Source |
| --- | --- |
| SHA-256 | NIST FIPS 180-4 |
| RIPEMD-160 | Reference publication |
| BIP-39 | Trezor vectors (entropy, mnemonic, seed) |
| BIP-32 | Published vectors 1–3, including the leading-zero case |
| BIP-84 | Published mainnet addresses |
| BIP-173 / BIP-350 | Valid **and invalid** Bech32/Bech32m vectors |
| BIP-143 | Native P2WPKH sighash (`c37af311…`) |

The invalid vectors matter more than the valid ones. Any implementation can
encode correctly; the security property is rejecting malformed input.

---

## 2. Source-tree guards — the most valuable tests here

Two failure modes cannot be detected behaviourally:

**Weak entropy.** A wallet built on `Math.random()` generates addresses,
receives coins, and signs valid transactions. The output is structurally
perfect; only the *distribution* is wrong. No test of its output reveals this.
So the suite reads `core/**/*.ts`, strips comments, and fails if
`Math.random()` or a timestamp-as-seed appears.

**Reference code reaching production.** The educational SHA-256 and secp256k1
in `core/crypto/reference/` are *correct* — and timing-unsafe by construction.
A correct-but-unsafe implementation passes every functional test. So the suite
asserts no production module imports them, that they import nothing themselves,
and that each carries the `NOT A SECURITY BOUNDARY` banner.

Both guards carry **backstop assertions** that the filtered file list is
non-empty. This is not paranoia — see [ATTACKS.md](ATTACKS.md) VEY-001, where a
separator bug made three of these tests pass while checking nothing.

---

## 3. Property testing (§33)

Example tests prove only the cases someone thought of. These invariants run
across thousands of randomised scenarios:

- **~6,000 coin-selection scenarios**: selection never covers less than
  `target + fee`; `inputs = target + fee + change`; change is never dust; no
  coin selected twice or from outside the supplied set; frozen, unconfirmed,
  and immature coins never selected. Each strategy tested independently.
- **200 randomised sends**: outputs plus fee always equal inputs.
- **256 single-bit digest mutations**: every one breaks signature verification.
- **>1,000 Bech32 character substitutions**: every one is detected.

---

## 4. Attacks, not assertions

`tests/security/` and `api/tests/` are written from the attacker's side.

**Transaction tampering (35 tests)** — redirect the payment, alter the amount
by one satoshi, steal the change, redirect the change, reorder outputs, change
which UTXO is spent, lie about the input value, swap the public key, corrupt
every individual byte of the signature. All must fail verification.

**Key leakage (17 tests)** — extract a private key through `String()`,
template interpolation, `JSON.stringify` (nested and in arrays), `util.inspect`
with `showHidden`, `Object.keys`, property descriptors, spread, error messages,
and stack traces.

**API (55 tests)** — every §21 category: forged and near-miss tokens, timing
oracles, oversized and lied-about bodies, prototype pollution, path traversal,
replay, IDOR probing, endpoint enumeration, and secret leakage. Includes a
reflection test asserting no service method could expose key material.

---

## 5. Fuzzing (§34)

`Transaction.fromBytes` consumes untrusted network data — the largest hostile
input surface in the codebase. The invariant is absolute:

> For **any** input, the parser either returns a valid Transaction or throws a
> typed error. Never hangs, never allocates unboundedly, never silently
> mis-parses.

Coverage: a single bit flip at **every position** of a valid transaction
(~1,900 mutations), truncation at **every length**, 5,500 random inputs seeded
to reach different parser depths, and declared lengths near 2⁶⁴.

---

## 6. What the suite CANNOT establish

The honest limits, because a green suite invites more confidence than it earns:

- ~~**Consensus acceptance.**~~ **Closed 2026-08-20** — Bitcoin Core accepted a
  Veyra transaction on regtest. Note this covers regtest only; mainnet policy
  differs in some respects and has never been exercised.
- **Statistical randomness quality.** The entropy tests catch a *broken*
  generator (stuck, counting, short period), not a subtly biased one. That
  needs Dieharder or the NIST STS.
- **Side-channel resistance.** No timing analysis is performed. We rely on
  `@noble`'s constant-time claims.
- **Real network behaviour.** Both chain clients are tested against controlled
  fakes.
- **`MemoryChainSource` is not a node.** It validates nothing. A broadcast
  succeeding there means nothing about the real network.

---

## 7. Skipped tests are reported, not hidden

Regtest tests use `describe.skipIf`, so they report as **skipped** rather than
passing, and an always-running companion test prints a warning:

```
⚠️  Regtest integration tests were skipped.
   Consensus validation against Bitcoin Core has NOT been performed.
```

A skipped test honestly reports that verification did not happen. A mock
standing in for a node would report success while verifying nothing.
