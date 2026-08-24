# Veyra

**A self-custodial Bitcoin wallet built as a cryptography learning laboratory.**

Veyra is not trying to compete with production wallets. It exists so that its
implementation can be opened, read, questioned, and attacked — and so that
every cryptographic decision inside it can be explained rather than deferred to
a library.

> ⚠️ **Status: Phase 1 complete.** Veyra is a working wallet core: it generates
> mnemonics, derives HD key trees, produces addresses, tracks UTXOs, selects
> coins, calculates fees, and builds, signs, and verifies transactions.
>
> **Consensus-verified.** On 2026-08-20 Bitcoin Core accepted a transaction
> Veyra built and signed, on regtest, and computed the same txid — so the
> serialisation is byte-exact and the signing path satisfies real consensus
> rules, not just my reading of them. Run `npm run test:regtest` to reproduce.
>
> Still missing: Lightning. The Esplora client
> has **not** been tested against a live server. Nothing here has handled real
> funds. There is no challenge deployment.

---

## What is built

| Component | Status | Source | Docs |
| --- | --- | --- | --- |
| Entropy generation | ✅ | `core/crypto/entropy.ts` | [CRYPTOGRAPHY §1](docs/CRYPTOGRAPHY.md#1-entropy) |
| Hash primitives | ✅ | `core/crypto/hashes.ts` | [§2](docs/CRYPTOGRAPHY.md#2-hashing) |
| Private keys | ✅ | `core/keys/privateKey.ts` | [§3](docs/CRYPTOGRAPHY.md#3-private-keys) |
| Public-key derivation | ✅ | `core/keys/publicKey.ts` | [§4](docs/CRYPTOGRAPHY.md#4-secp256k1-and-public-keys) |
| Reference implementations | ✅ | `core/crypto/reference/` | [§5](docs/CRYPTOGRAPHY.md#5-the-reference-implementations) |
| Mnemonics (BIP-39) | ✅ | `core/mnemonic/` | [§8](docs/CRYPTOGRAPHY.md#8-bip-39--mnemonics) |
| HD derivation (BIP-32) | ✅ | `core/derivation/bip32.ts` | [§9](docs/CRYPTOGRAPHY.md#9-bip-32--hierarchical-deterministic-wallets) |
| Addresses (BIP-84 / Bech32) | ✅ | `core/addresses/` | [§10](docs/CRYPTOGRAPHY.md#10-bip-84--addresses) |
| Network parameters | ✅ | `core/bitcoin/networks.ts` | [§10](docs/CRYPTOGRAPHY.md#10-bip-84--addresses) |
| Transactions | ✅ | `core/transactions/` | [§12](docs/CRYPTOGRAPHY.md#12-transactions-and-the-utxo-model) |
| BIP-143 sighash | ✅ | `core/signing/sighash.ts` | [§13](docs/CRYPTOGRAPHY.md#13-bip-143--what-a-signature-commits-to) |
| Signatures (ECDSA) | ✅ | `core/signing/ecdsa.ts` | [§11](docs/CRYPTOGRAPHY.md#11-digital-signatures--ecdsa) |
| Transaction signing | ✅ | `core/signing/signer.ts` | [§14](docs/CRYPTOGRAPHY.md#14-what-15-tampering-tests-prove) |
| UTXOs / fees / coin selection | ✅ | `core/utxo/` | [§15](docs/CRYPTOGRAPHY.md#15-utxos-fees-and-coin-selection) |
| Wallet layer | ✅ | `core/wallet/wallet.ts` | [§16](docs/CRYPTOGRAPHY.md#16-the-wallet-layer) |
| Chain sync / broadcast | ✅ | `core/chain/` | [§17](docs/CRYPTOGRAPHY.md#17-chain-connectivity--the-untrusted-boundary) |
| Bitcoin Core RPC source | ✅ Verified live | `core/chain/bitcoinRpc.ts` | [REGTEST.md](docs/REGTEST.md) |
| Esplora source | ⚠️ Untested live | `core/chain/esplora.ts` | [§17](docs/CRYPTOGRAPHY.md#17-chain-connectivity--the-untrusted-boundary) |
| Regtest integration suite | ✅ Passing | `tests/integration/` | [REGTEST.md](docs/REGTEST.md) |
| HTTP API | ✅ | `api/src/` | [api/README.md](api/README.md) |
| Interface | ✅ | `app/src/` | [app/README.md](app/README.md) |
| Transaction history | ✅ | `core/chain/` | [api/README.md](api/README.md) |
| Live fee estimation | ✅ | `core/chain/` | [api/README.md](api/README.md) |
| RBF fee bumping (BIP-125) | ✅ | `core/wallet/wallet.ts` | [api/README.md](api/README.md) |
| Taproot (BIP-86 / BIP-341) | ✅ | `core/addresses/taproot.ts` | [§19](docs/CRYPTOGRAPHY.md) |
| Spending policy engine | ✅ | `core/policy/` | [api/README.md](api/README.md) |
| Watch-only wallet | ✅ | `core/wallet/watchOnly.ts` | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Encrypted keystore | ✅ | `core/wallet/keystore.ts` | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Deployable API (Docker/Fly/Render) | ✅ | `Dockerfile`, `deploy/` | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Offline client-side signer | ✅ | `app/signer.html` | [docs/STANDALONE.md](docs/STANDALONE.md) |
| Client-side watch wallet | ✅ | `app/watch.html` | [docs/STANDALONE.md](docs/STANDALONE.md) |
| Standalone single-file build | ✅ | `scripts/build-standalone.ts` | [docs/STANDALONE.md](docs/STANDALONE.md) |
| P2WSH multisig (t-of-n) | ✅ | `core/addresses/multisig.ts` | [docs/MULTISIG.md](docs/MULTISIG.md) |
| PSBT (BIP-174) | ✅ | `core/psbt/psbt.ts` | [docs/MULTISIG.md](docs/MULTISIG.md#psbt) |
| BIP-48 multisig accounts | ✅ | `core/addresses/bip48.ts` | [docs/MULTISIG.md](docs/MULTISIG.md#setting-one-up-bip-48) |
| Extended keys (xpub/xprv) | ✅ | `core/derivation/bip32.ts` | — |
| Lightning | ⬜ Not started | — | — |

---

## What "self-custodial" means

Nobody holds your keys but you. There is no account, no password reset, no
support desk, and no institution that can freeze, reverse, or restore anything.
A Bitcoin private key is just an integer; whoever knows it controls the coins,
permanently and indistinguishably from the rightful owner.

That is the whole reason this repository is written the way it is. Custodial
software can absorb a bug with a database rollback. Self-custodial software
cannot.

---

## How ownership actually works

```
  OS CSPRNG            k ∈ [1, n−1]          K = kG              HASH160(K)
 ───────────►  entropy ───────────► private ─────────► public ──────────────► address
                                     key                key
                                            └── one-way: ECDLP ──┘  └── one-way: preimage ──┘
```

Two independent one-way functions separate a public address from the secret
that controls it. Neither has ever been inverted at these parameter sizes, and
neither is *proven* hard — a distinction [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md)
takes seriously.

---

## What cryptography does it use?

- **secp256k1** — elliptic curve, via [`@noble/curves`](https://github.com/paulmillr/noble-curves)
- **SHA-256 / RIPEMD-160** — via [`@noble/hashes`](https://github.com/paulmillr/noble-hashes)
- **OS CSPRNG** — via Web Crypto `getRandomValues`

Every dependency is justified in a table at
[CRYPTOGRAPHY §7](docs/CRYPTOGRAPHY.md#7-dependencies), including what security
assumption it carries and why it was chosen over alternatives.

**Bitcoin does not encrypt transactions.** Every transaction on the chain is
public. Cryptography here provides *authentication* and *commitment*, never
confidentiality. If a wallet's documentation says otherwise, distrust it.

---

## Two rules this project follows

**1. Use audited libraries for anything that touches a real key.**
Hand-rolled production cryptography is how wallets lose money.

**2. Never hide behind the library.**
`core/crypto/reference/` contains readable, dependency-free implementations of
SHA-256 and secp256k1 point arithmetic. They are proven correct against the
audited libraries by differential testing — and proven *never imported by
production code* by a source-tree scan that fails CI. They are for
understanding, and the test suite enforces that they can never quietly become
the security boundary.

---

## How to run the tests

```bash
npm install
npm test          # full suite
npm run typecheck # strict TypeScript, no implicit any, no unchecked indexing
npm run demo        # entropy -> mnemonic -> seed -> address -> signed tx
npm run demo:wallet # full send flow with fee review and spending guards
npm run demo:sync   # chain scan, broadcast, and a hostile-server rejection

npm run test:unit    # everything that needs no node
npm run test:api     # 63 API attacks (§21)
npm run test:regtest # consensus validation against Bitcoin Core (needs a node)

npm run api          # start the HTTP API — see api/README.md
npm run docs:build   # generate the documentation site
npm run app          # start the interface — see app/README.md
                     #   wallet:  http://127.0.0.1:5173
                     #   API docs: http://127.0.0.1:5173/docs/
```

Current suite: **892 tests across 30 files** — 874 that need no node, plus 18
regtest integration tests that require a running Bitcoin Core node and are
**the most important tests in the repository**. See
[docs/REGTEST.md](docs/REGTEST.md).

`npm run demo` prints the whole pipeline and produces real testnet addresses:

```
5. RECEIVE ADDRESSES
    m/84'/1'/0'/0/0  tb1qg0yw6s6cpvwjf7ulqmzcurtywmuaznusdwx06v
    m/84'/1'/0'/0/1  tb1qfqwvqyw6np7706pjlp4eqk9eejetqf72a36tm3
```

**Live documentation:** <https://veyra-apidocs.vercel.app>

### ✅ Consensus verification

On **2026-08-20**, all 10 regtest integration tests passed against Bitcoin Core
v29 on Windows. Bitcoin Core accepted a Veyra-built transaction, computed an
identical txid, rejected a tampered recipient, and confirmed that change is
spendable and a restored mnemonic finds real funds.

This is the only test in the repository that validates against consensus rather
than against the specification as I read it. Reproduce with
`npm run test:regtest` — see [docs/REGTEST.md](docs/REGTEST.md).

### ⚠️ What has still NOT been verified

- **The Esplora client has never spoken to a live server.** Only the Bitcoin
  Core RPC client is consensus-verified; Esplora is tested against a fake.
- **No code here has handled real funds**, on any network.
- **No independent security review** has been performed.
- **Mainnet is untested.** Only regtest has been exercised end to end.

### Verified against official test vectors

Interoperability is the whole point of a backup phrase, so nothing here is
tested only against itself:

| Standard | Vectors |
| --- | --- |
| SHA-256 | NIST FIPS 180-4 |
| BIP-39 | Trezor reference vectors (entropy, mnemonic, seed) |
| BIP-32 | Published vectors 1–3, including the leading-zero edge case |
| BIP-84 | Published mainnet addresses |
| BIP-173 / BIP-350 | Valid **and invalid** Bech32/Bech32m vectors |
| BIP-143 | Official native-P2WPKH sighash vector (`c37af311…`) |
| BIP-86 | Published Taproot addresses — all three vectors |
| BIP-32 xpub/xprv | Published extended-key strings |

---

## How to attack it

The security tests are written as attacks, not as assertions.

**`tests/security/key-leakage.test.ts`** tries to extract a private key through
stringification, JSON serialisation, `util.inspect` with `showHidden`,
reflection, error messages, and stack traces.

**`tests/security/transaction-tampering.test.ts`** takes a signed transaction
and attempts to redirect the payment, alter amounts by a single satoshi, steal
or redirect the change, reorder outputs, swap in a different public key, lie
about the input value, and corrupt every individual byte of the signature.
All 35 must fail to verify.

**`tests/cryptography/coin-selection.test.ts`** asserts §33 property invariants
across ~6,000 randomly generated scenarios: selection never covers less than
target plus fee, value always balances, change is never dust, no coin is
selected twice or from outside the supplied set.

**`api/tests/api-security.test.ts`** attacks the HTTP layer across every §21
category: forged and near-miss tokens, timing oracles, oversized and lied-about
bodies, prototype pollution, path traversal, replay, IDOR probing, endpoint
enumeration, and secret leakage. It asserts by reflection that no service
method could expose key material.

**`tests/fuzz/transaction-parser.test.ts`** attacks the parser with bit flips at
every position, truncation at every length, 5,500 random inputs, and declared
lengths near 2⁶⁴. The invariant: parse correctly or throw a typed error — never
crash, never allocate unboundedly, never silently mis-parse.

The most useful tests in the repository are the two **source-tree guards**,
because they catch failures no behavioural test can:

- `Math.random()` anywhere in `core/` fails the suite. A weak-entropy wallet
  works perfectly and is worthless; only reading the source catches it.
- Any production import of `core/crypto/reference/` fails the suite.

If you find something, see [SECURITY.md](SECURITY.md). A failing test is the
most useful artefact — under §31 it becomes the permanent regression test.

---

## The security challenge

**Not yet live.** A publicly funded challenge wallet (~$10 in BTC) is planned
once Phase 1 is complete, the security suite passes, and a threat model is
published. Scope, rules, and disclosure process will be defined then.

Until a wallet exists, there is nothing to attack and nothing is claimed. This
README will not describe a challenge that has not been deployed.

---

## Documentation

| Document | Contents |
| --- | --- |
| [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | Every primitive: what it is, why, how, how it fails, how it was tested |
| [THREAT-MODEL.md](docs/THREAT-MODEL.md) | Attackers, assumptions, trust boundaries, and unresolved weaknesses |
| [ATTACKS.md](docs/ATTACKS.md) | Real defects found during development, with root cause and lesson |
| [TESTING.md](docs/TESTING.md) | Test philosophy, and what the suite cannot establish |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module map, boundaries, design trade-offs |
| [REGTEST.md](docs/REGTEST.md) | Consensus validation against Bitcoin Core |
| [api/README.md](api/README.md) | API endpoints, security controls, limitations |
| [app/README.md](app/README.md) | Interface design decisions and accessibility |
| `app/docs/` | 14-page documentation site with a live request console. Generated by `npm run docs:build`, served at `/docs/` |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Hosting the API safely, and securing the local wallet |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |

Documentation is written alongside the code it documents, never ahead of it.
`docs/ATTACKS.md` is worth reading first if you want to judge the project's
honesty: it records fifteen real defects, including two where a security guard
silently stopped guarding, and one where a test measured the machine rather
than the code.

---

## License

MIT
