# Veyra — Cryptography

> **Status.** This document covers only what is *implemented and tested* today:
> entropy, hashing, private keys, public-key derivation, BIP-39 mnemonics,
> BIP-32 HD derivation, BIP-84 addresses, transactions, BIP-143 sighash, ECDSA
> signing, UTXO management, coin selection, the wallet layer, and chain
> synchronisation. The API and UI are not yet built and are therefore not
> documented here. Veyra does not describe unbuilt code as if it existed.

---

## 0. The one-paragraph version

A Bitcoin private key is an integer `k` drawn uniformly at random from
`[1, n−1]`. Multiplying the fixed generator point `G` by `k` on the secp256k1
curve gives a public key `K = kG`. That multiplication is cheap forwards and
believed infeasible backwards, which is the entire basis of ownership. Hashing
`K` produces a short, irreversible payment destination. Nothing here is
encrypted — Bitcoin authenticates and commits; it does not conceal.

```
  OS CSPRNG            k ∈ [1, n−1]          K = kG              HASH160(K)
 ───────────►  entropy ───────────► private ─────────► public ──────────────► address
                                     key                key
                                            └── one-way: ECDLP ──┘  └── one-way: preimage ──┘
```

---

## 1. Entropy

**Implementation:** [`core/crypto/entropy.ts`](../core/crypto/entropy.ts) ·
**Tests:** [`tests/cryptography/entropy.test.ts`](../tests/cryptography/entropy.test.ts)

### What is it?

Entropy measures unpredictability. A 128-bit value carries 128 bits of entropy
only if an adversary who fully understands the generating *process* still faces
2¹²⁸ equally likely candidates.

### Why is it necessary?

Every guarantee downstream rests on it. secp256k1's hardness protects a key
that was sampled uniformly; it offers nothing against a key drawn from a small
or predictable set. **An attacker does not break the curve — he enumerates the
generator.**

| Incident | Failure | Result |
| --- | --- | --- |
| Debian OpenSSL (2006–08) | Seed space reduced to ~32,768 values | Two years of keys enumerable |
| Android `SecureRandom` (2013) | Repeated ECDSA nonces | Keys recovered from on-chain signatures; wallets drained |
| Brainwallets | Human-chosen passphrases | Emptied by dictionary sweep within seconds of funding |

### How does it work here?

Veyra does not implement a generator. It delegates to the OS CSPRNG via
`crypto.getRandomValues` — `getrandom(2)` on Linux, `BCryptGenRandom` on
Windows, `CCRandomGenerateBytes` on macOS. We use the Web Crypto global rather
than `node:crypto` so that `core/` runs unchanged in Node, browsers, and React
Native.

**There is no fallback.** If the CSPRNG is missing we throw. Every historical
disaster above involved code that quietly degraded to a weaker source.

### What principle does it depend on?

Uniquely in this document: a **systems** assumption, not a mathematical one —
that the host CSPRNG is properly seeded and unbroken. This is the most
load-bearing non-mathematical assumption Veyra makes.

### Design decisions

- **256-bit default, 128-bit floor.** secp256k1 offers ~128-bit security
  against Pollard's rho (≈√n operations), so entropy beyond 128 bits buys
  nothing against the best known curve attack. 128 is the honest minimum;
  256 is the conservative default.
- **`generateWalletEntropy()` takes no arguments.** There is no syntactic path
  for a caller to substitute a weak generator into wallet creation. The
  `RandomSource` injection point exists on `randomBytes` for tests only, and a
  test asserts the wallet function's arity is zero.
- **Upper size bound.** Not security — it stops an unvalidated length from an
  API request becoming a memory-exhaustion DoS.

### If implemented incorrectly

Total, silent, unrecoverable compromise. Note *silent*: a weak-entropy wallet
generates addresses, receives coins, and signs valid transactions perfectly.
The output is structurally correct; only the **distribution** is wrong. No test
of the wallet's own output can reveal this.

### How was it tested?

Because output tests cannot catch the real failure, the suite does three things:

1. **Structural** — length, policy bounds, non-integer rejection.
2. **Statistical sanity** — 1,000 draws with no duplicates, full byte-range
   coverage, bit balance within 48–52%. These catch a *broken* generator (stuck
   at zero, returning a counter, short period), not a subtly biased one.
   Detecting subtle bias needs Dieharder or the NIST STS and is out of scope
   for a unit test.
3. **Source-tree guard** — the suite reads `core/**/*.ts`, strips comments, and
   fails if `Math.random()` or a timestamp-as-seed pattern appears anywhere.
   *This is the most valuable test in the file*, because it is the only one
   that can catch the failure mode where everything works and nothing is safe.

### Attack surface

- Supply-chain substitution of this module or a shimmed `globalThis.crypto`
  (mitigation: zero third-party imports in this file; dependency auditing).
- VM-snapshot rollback forcing RNG state reuse.
- Timing or memory side channels on generated bytes.

### On `wipe()` — an honest limitation

Zeroing a buffer in a GC'd, JIT'd runtime is **best-effort, not a guarantee**:
GC may have copied the buffer; the OS may have paged it to swap. We do it
because it shrinks the window in which a heap dump contains live key material.
Claiming more than that would be the security theatre this project exists to
avoid.

---

## 2. Hashing

**Implementation:** [`core/crypto/hashes.ts`](../core/crypto/hashes.ts) ·
**Reference:** [`core/crypto/reference/sha256.ts`](../core/crypto/reference/sha256.ts) ·
**Tests:** [`tests/cryptography/hashes.test.ts`](../tests/cryptography/hashes.test.ts)

### The three properties, and what each one protects

| Property | Statement | Cost | What breaks in Veyra without it |
| --- | --- | --- | --- |
| Preimage resistance | Given `h`, find any `m` with `H(m)=h` | ~2²⁵⁶ | An address would reveal the public key it commits to |
| Second-preimage | Given `m₁`, find `m₂≠m₁` with equal hash | ~2²⁵⁶ | A signature could authorise a transaction you never approved |
| Collision resistance | Find *any* `m₁≠m₂` colliding | ~2¹²⁸ (birthday) | Distinct transactions could share a txid |

The birthday bound is why SHA-256 is rated at **128-bit** security, not 256 —
which happens to match secp256k1's 128-bit level exactly. Bitcoin's security
level is uniform by design, not by accident.

### Hashing is not encryption

Encryption is invertible with a key: `E(k,m)→c`, `D(k,c)→m`. Hashing has no key
and no inverse. `H` destroys information — a 1 GB file and a 3-byte string both
map to 32 bytes, so infinitely many inputs share every output. There is no
"decrypting a hash"; there is only guessing and checking.

**Bitcoin does not encrypt transactions.** Every transaction on the chain is
fully public. Bitcoin uses cryptography for *authentication* (proving the
spender held the key) and *commitment* (binding data against later alteration).
Confidentiality is not a goal of the protocol.

### The four compositions Veyra uses

| Function | Definition | Used for |
| --- | --- | --- |
| `sha256` | SHA-256 | Sighashes, BIP-32 internals, checksums |
| `hash256` | SHA-256(SHA-256(x)) | txids, block hashes, Base58Check checksum |
| `hash160` | RIPEMD-160(SHA-256(x)) | P2PKH / P2WPKH payment destinations |
| `taggedHash` | SHA256(SHA256(tag)‖SHA256(tag)‖msg) | BIP-340/341 domain separation |

**Why double SHA-256?** Merkle–Damgård constructions leak enough internal state
that an attacker knowing `H(m)` and `|m|` can compute `H(m ‖ pad ‖ suffix)`
without knowing `m` — length extension. Hashing the 32-byte digest again breaks
this, since the outer input length is fixed. Not obviously exploitable in
Bitcoin's specific constructions; belt-and-braces.

**Why RIPEMD-160 at all?** Size (20 bytes vs 32) and hedging — an entirely
different internal structure from SHA-2, so a break of one likely does not
imply a break of the composition. RIPEMD-160 alone offers only ~80-bit
collision resistance, which is exactly why Bitcoin never uses it alone: running
SHA-256 first means an attacker cannot attack that weak bound on chosen inputs.

**Why tagged hashes?** If two protocols both sign "SHA-256 of 32 bytes", a
value legitimate in one may be legitimate in the other, enabling cross-context
signature replay. Prefixing with a hashed tag makes the input spaces provably
disjoint. The tag is repeated so the prefix is exactly one 64-byte block, which
lets implementations cache the midstate.

### Library boundary

**@noble/hashes is responsible for:** correct, audited SHA-256 and RIPEMD-160.
**Veyra is responsible for:** composing them in the exact orders consensus
specifies, and never confusing one composition for another. A `hash160` where
`hash256` was required is a consensus bug, not a library bug — which is why the
test suite asserts each composition independently rather than trusting naming.

### Testing

NIST FIPS 180-4 vectors (empty, `abc`, the two-block vector), RIPEMD-160
reference vectors, a known Bitcoin `hash160` pair, an explicit test that
`hash160 ≠ hash256`, an avalanche test (a 2-bit input change flips 96–160 of
256 output bits), and a domain-separation test proving different tags never
collide on the same message.

---

## 3. Private keys

**Implementation:** [`core/keys/privateKey.ts`](../core/keys/privateKey.ts) ·
**Tests:** [`keys.test.ts`](../tests/cryptography/keys.test.ts), [`key-leakage.test.ts`](../tests/security/key-leakage.test.ts)

### What is it, actually?

**An integer.** Not a file, not a password, not an encrypted blob. Specifically
an integer in `[1, n−1]` where

```
n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
```

Every 32-byte string below `n` is already a valid Bitcoin private key with a
corresponding address that already exists on the blockchain. A key is not
*created* so much as *selected* from ~2²⁵⁶ possibilities. Ownership means
knowing the integer — nothing more. Anyone who learns it owns the coins equally
and irrevocably. There is no account, no registration, no revocation.

### Why the range `[1, n−1]`?

- `k = 0` → `0·G = O`, the point at infinity. Not a valid public key.
- `k ≥ n` → arithmetic wraps: `(k mod n)·G = k·G`. So `k` and `k−n` map to the
  **same** public key, breaking the one-to-one correspondence. Worse, some
  implementations reduce while others reject — an interoperability hazard that
  loses funds.

The excluded range is a fraction of roughly 2⁻¹²⁸ of the 32-byte space. A
uniform draw lands out of range essentially never. We check anyway, because
"never happens in practice" is how CVEs get written. The tests assert the exact
boundaries: `1` accepted, `n−1` accepted, `0` rejected, `n` rejected, `n+1`
rejected.

### Rejection sampling — and why `mod n` is the wrong shortcut

Reducing a uniform 256-bit draw modulo `n` is the obvious approach and is
subtly wrong. Since 2²⁵⁶ is not a multiple of `n`, values in `[0, 2²⁵⁶ mod n)`
have one extra preimage each and come out **twice as likely** as the rest.

For key generation that bias is ~2⁻¹²⁸ and unexploitable. **For ECDSA nonces
the identical mistake is catastrophic** — biased nonces let lattice attacks
recover the private key from a handful of signatures. Veyra uses the unbiased
method everywhere so that the pattern present in the codebase to copy is the
correct one.

The implementation draws, range-checks, and redraws on failure — with a 128-
attempt cap that converts a stuck RNG (say, one returning all-`0xFF`) into a
loud error rather than an infinite loop. A test injects a source returning
exactly `n` first, then `42`, and asserts the result is `42` after two draws: a
`mod n` implementation would return `0` and pass a naive test.

### Why knowing an address does not reveal the key

Two independent one-way functions stand between them:

```
 k ──[ EC scalar multiplication ]──► K ──[ HASH160 ]──► address
      inverting = discrete log            inverting = preimage
      ~2¹²⁸ operations                    ~2¹⁶⁰ operations
```

Before you spend from a P2WPKH output, the chain holds only the *hash* of your
public key — the key itself is not public at all. After you spend, the witness
reveals it and only the discrete-log barrier remains. This is the technical
basis for the "don't reuse addresses" guidance and for Veyra's fresh
change-address policy.

### Leak-resistance by construction

The most common way wallets lose funds is not a broken curve — it is a key
serialised into a log line or an API response. `PrivateKey` closes every
accidental path:

| Path | Behaviour |
| --- | --- |
| `String(key)`, `` `${key}` ``, `"" + key` | `PrivateKey<redacted>` |
| `JSON.stringify(key)` — including nested and in arrays | `"PrivateKey<redacted>"` |
| `console.log` / `util.inspect`, even `showHidden: true` | `PrivateKey<redacted>` |
| `Object.keys` / `entries` / `getOwnPropertyDescriptors` | empty — `#bytes` is a true private field, unreachable reflectively |
| Error messages and stacks | constant strings; **never** echo the rejected value |

Deliberate export requires `toHexUnsafe()` — named to read as alarming at a
call site and trivial to grep in review. `toBytes()` returns a **copy**, so
callers cannot mutate internal state and own wiping what they receive (a test
documents this trade-off explicitly rather than leaving it implicit).

Error messages never contain the offending value. A rejected key candidate in a
log is RNG-stream information at best and a live key at worst, and log
aggregators are exactly where an attacker looks.

---

## 4. secp256k1 and public keys

**Implementation:** [`core/keys/publicKey.ts`](../core/keys/publicKey.ts) ·
**Reference:** [`core/crypto/reference/secp256k1.ts`](../core/crypto/reference/secp256k1.ts)

### The curve

```
y² = x³ + 7   (mod p),    p = 2²⁵⁶ − 2³² − 977
```

Over a finite field this is not a smooth line but a scattered cloud of roughly
`p` discrete points, plus a special identity `O` (the point at infinity).

### The group law

Points form an abelian group under a geometric addition rule:

- **`P + Q`** — draw the line through them; it meets the curve at exactly one
  third point; reflect that point across the x-axis.
- **`P + P`** — same, but the "line through P and P" is the tangent at P.
- **`P + (−P) = O`**, where `−P` is `P` reflected across the x-axis.

Over a finite field the geometry vanishes but the algebra survives verbatim.
The test suite verifies the group axioms directly: identity, inverses,
commutativity, associativity, and `2P = P + P`.

### Scalar multiplication and the one-way property

`kG` means `G` added to itself `k` times. Computing it costs ~256 doublings
(double-and-add). Recovering `k` from `kG` is the **elliptic-curve discrete
logarithm problem**, with no known attack better than generic square-root
methods — Pollard's rho at ~√n ≈ 2¹²⁸ operations.

Two honest caveats:

1. Hardness is **conjectured, not proven**. No theorem forbids a better
   algorithm; we have only decades of failed attempts.
2. **Shor's algorithm** on a large fault-tolerant quantum computer solves ECDLP
   in polynomial time.

Both are recorded as explicit assumptions in the threat model.

### Why secp256k1 specifically

- `a = 0` permits the GLV endomorphism — roughly 25% faster multiplication.
- **Parameters are not random.** `p` and `n` have compact closed forms and `G`
  was published with the curve. Compared with NIST P-256, whose seeds are
  unexplained, secp256k1's structure is far easier to argue is backdoor-free.
- **Cofactor `h = 1`.** Every point except `O` has order `n`, so there are no
  small subgroups and small-subgroup confinement attacks do not apply.

### Compressed encoding — 33 bytes, not 64

Given `x`, the equation `y² = x³ + 7` has at most two solutions, `y` and `p−y`.
Since `p` is odd, exactly one is even — so a single parity bit recovers `y`
completely. The prefix encodes it: `0x02` for even `y`, `0x03` for odd.

Veyra **accepts** the legacy 65-byte uncompressed form when parsing (it appears
in old chain data) but **never produces** it:

- BIP-143 makes compressed keys mandatory for SegWit v0 spends; an
  uncompressed key in a P2WPKH witness is simply invalid.
- The same private key yields a **different address** under each encoding.
  Users have repeatedly "lost" funds by generating one way and restoring the
  other. A test asserts the two hash160s differ, so nobody assumes the
  encodings are interchangeable.

### Validation is not optional

An unvalidated point is an invalid-curve attack primitive: feed a chosen
off-curve point to an implementation that skips the check and the resulting
arithmetic can leak the other party's secret. Veyra performs no ECDH today, but
validating at every boundary is what prevents that from becoming a
vulnerability the day someone adds it. Parse errors deliberately discard the
library's message — it can echo caller-supplied bytes into logs — and
substitute a constant string. A test asserts a `deadbeef` marker never appears
in an error.

### Library boundary

**@noble/curves is responsible for:** constant-time scalar multiplication,
point validation, and rejecting infinity and off-curve points.
**Veyra is responsible for:** never handing it an unvalidated scalar, and never
treating a parsed point as trusted before validation passes.

---

## 5. The reference implementations

`core/crypto/reference/` contains dependency-free SHA-256 and secp256k1 point
arithmetic written to be **read**, not run.

### Why they exist

"The library hashed it" is not understanding. You should be able to open
`reference/sha256.ts` and see that SHA-256 is 64 rounds of additions,
rotations, and XORs over eight 32-bit words — and open `reference/secp256k1.ts`
and see that a public key is a chord-and-tangent construction repeated 256
times.

### Why they must never ship

`multiply()` is textbook double-and-add: it performs an addition only when a
scalar bit is 1, so runtime and power draw reveal the secret's bit pattern
directly. This is simple power analysis, and it recovers keys. JavaScript's
`BigInt` is not constant-time either — its operations branch on operand
magnitude.

The pattern of *"we wrote our own crypto to prove we understood it, then
shipped it"* is among the most reliable sources of catastrophic wallet bugs.

### How isolation is enforced

Correctness alone is not enough — a correct-but-unsafe implementation is
*more* dangerous, because it passes every functional test. So the suite
enforces isolation structurally:

- No module outside `core/crypto/reference/` may import from it (source scan).
- Reference modules import nothing at all, so they cannot entangle production code.
- Every reference file must carry the `NOT A SECURITY BOUNDARY` banner.

Correctness is proven by differential testing: FIPS vectors, agreement with
`@noble` across message lengths **including the 55/56 and 63/64 padding
boundaries** where naive implementations break, 300 random-input comparisons
for SHA-256, and 25 random-scalar comparisons for point derivation.

---

## 6. A note on how these tests were written

> While writing the off-curve validation test, the first attempt used `x = 1`
> on the assumption that a small `x` would obviously not lie on the curve. It
> does: `y² = 8` has a square root mod `p`, and the test failed. Roughly half
> of all `x` values are on the curve. `x = 5` (`y² = 132`, a quadratic
> non-residue by Euler's criterion) is a genuine off-curve point.
>
> The mistake is preserved in a comment in the test file, because it is exactly
> the sort of assumption that produces a validator which passes its own tests
> while checking nothing at all. **"Off-curve" must be computed, never
> assumed.**

---

## 7. Dependencies

| Dependency | Primitive | Purpose | Security assumption | Why selected |
| --- | --- | --- | --- | --- |
| `@noble/hashes` | SHA-256, RIPEMD-160 | All Bitcoin hash compositions | Implementations are correct and free of exploitable side channels | Independently audited, zero transitive dependencies, no native bindings, same code across Node/browser/RN |
| `@noble/curves` | secp256k1 | Public-key derivation; signing (planned) | Constant-time scalar multiplication; correct point validation | Same author and audit lineage; explicitly designed for constant-time operation, unlike BigInt-based alternatives |

Zero transitive dependencies is a deliberate criterion, not a nicety: every
transitive package is a supply-chain entry point into a process that holds
private keys.

---

## 8. BIP-39 — mnemonics

**Implementation:** [`core/mnemonic/`](../core/mnemonic/) ·
**Tests:** [`mnemonic.test.ts`](../tests/cryptography/mnemonic.test.ts)

### mnemonic ≠ private key

A mnemonic is not a key and not an encoding of one key. It encodes the
**entropy** from which an entire tree of keys descends. Anyone who reads your
12 words owns every key in that tree forever — including addresses you have not
generated yet.

### Why 2048 words

2^11, so each word carries exactly 11 bits. 128 bits entropy + 4 checksum bits
= 132 bits = 12 words. 256 + 8 = 264 = 24 words. The list is sorted, has no
duplicates, and every word is uniquely identified by its **first four
letters** — which is why hardware wallets let you stop typing after four
characters.

`core/mnemonic/wordlist.ts` is consensus-critical. One altered or reordered
word silently changes the mapping, and the wallet would work perfectly while
deriving different addresses than every other wallet on earth. The tests assert
the file's published SHA-256 (`2f5eed53…`) plus all four structural invariants.

### The checksum is not a security control

The final word carries 4–8 checksum bits over the entropy. For a 12-word phrase
that is 4 bits, so a randomly corrupted phrase passes with probability **1/16**.
It catches transcription errors. It cannot detect a deliberately crafted
valid-but-different phrase.

### PBKDF2 — being honest about the parameters

`PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048 rounds, 64 bytes)`

2048 iterations is **weak by modern standards** and trivially
GPU-parallelisable. Argon2id or scrypt would be far better. BIP-39 was
specified in 2013 and the parameter cannot change without breaking every wallet
in existence. Veyra follows the standard because interoperability of a *backup
phrase* is worth more than a stronger KDF nothing else can read. The real
defence is full-entropy mnemonics, which we always generate.

### The passphrase footgun

The optional passphrase is folded into the PBKDF2 salt. There is **no "wrong
passphrase" error** — every passphrase produces a valid, different,
empty-looking wallet, and a forgotten one is unrecoverable because there is
nothing to check against except finding funds. This is also the feature: a
coerced user can reveal the bare mnemonic and show a decoy wallet.

### NFKD normalisation

`é` can be one code point or `e` plus a combining accent — visually identical,
different bytes. Without NFKD, the same passphrase typed on two keyboards gives
two different wallets, with no error and no explanation. A test asserts both
forms produce identical seeds.

---

## 9. BIP-32 — hierarchical deterministic wallets

**Implementation:** [`core/derivation/bip32.ts`](../core/derivation/bip32.ts) ·
**Tests:** [`derivation.test.ts`](../tests/cryptography/derivation.test.ts)

### The additive structure that makes watch-only wallets possible

For a non-hardened child:

```
I = HMAC-SHA512(chainCode, serP(parentPub) ‖ ser32(i))
childKey = (IL + parentKey) mod n
```

The child is the parent **plus a tweak**. Therefore:

```
(IL + k)·G  =  IL·G + k·G  =  IL·G + K
```

The child *public* key is computable from the parent *public* key alone. A
server can generate fresh receive addresses forever while holding no spending
authority whatsoever.

### Hardening — and the attack it prevents

That same additive structure is a vulnerability in reverse. Given a parent
xpub (public key + chain code) and **any one** non-hardened child private key:

```
IL     = HMAC-SHA512(chainCode, serP(parentPub) ‖ ser32(i))   ← all public data
parent = (childKey − IL) mod n                                 ← RECOVERED
```

The parent private key falls out by subtraction, and with it the entire
subtree. `derivation.test.ts` implements this attack as an **executable test**
that recovers the parent key, because the arithmetic is more convincing than
prose.

Hardened derivation feeds the parent *private* key into the HMAC instead,
severing the relationship. This is why `m/84'/coin'/account'` are all hardened:
it contains the blast radius of a leaked xpub to a single account.

### The retry rule everyone misses

If `IL ≥ n` or the resulting child key is zero, BIP-32 requires **skipping to
index+1** — not reducing mod n, not failing. Probability ~2⁻¹²⁷, so it will
never execute, but an implementation that reduces would derive a different key
than every other wallet in that case.

### Test vectors

All three published BIP-32 vectors pass, including **vector 3**, which exists
specifically to catch implementations that strip leading zeros from a 32-byte
scalar — truncating `00ddb8…` to 31 bytes changes every derived child.

---

## 10. BIP-84 — addresses

**Implementation:** [`core/addresses/`](../core/addresses/) ·
**Tests:** [`derivation.test.ts`](../tests/cryptography/derivation.test.ts), [`bech32.test.ts`](../tests/cryptography/bech32.test.ts)

### An address is a script, not a public key

The on-chain output for P2WPKH is:

```
OP_0 <20-byte hash160(compressed pubkey)>
```

The address is that script's witness version and program, Bech32-encoded with a
network prefix. It commits to a **rule** — "whoever can produce a signature
matching the key with this hash may spend" — not to an identity.

```
public key (33 bytes) → HASH160 → witness program (20 bytes)
                      → + version 0 + HRP + Bech32 checksum → "tb1q…"
```

### The path

```
m / 84' / coin_type' / account' / change / index
```

`purpose = 84` makes address types self-describing. Restoring a BIP-84 seed
into a BIP-44-only wallet shows an empty balance — the funds are fine, the
wallet is looking down the wrong branch. This is a common panic worth
understanding *before* it happens.

### Bech32, and why there are two variants

Bech32's checksum is a BCH code with a **proven** guarantee: it detects any 4
or fewer character substitutions, and longer errors with probability ~1 in 10⁹.
Not "unlikely to miss" — the algebra guarantees the bound.

The original design had a real flaw: if a Bech32 string ends in `p`, inserting
or deleting `q` characters just before it leaves the checksum unchanged.
Harmless for SegWit v0 (fixed lengths, validated first) but a genuine risk for
variable-length future versions. BIP-350 therefore defines **Bech32m**, with
checksum constant `0x2bc830a3` instead of `1`:

| Witness version | Encoding |
| --- | --- |
| 0 (P2WPKH, P2WSH) | Bech32 |
| 1+ (Taproot) | Bech32m |

Veyra selects the variant **from the witness version**, never as a caller
option — making it configurable would invite exactly the mistake the second
variant exists to prevent.

### Why this one is implemented rather than imported

Bech32 is an error-detecting code, not a secret. The entire input is public by
definition, so there is no timing sensitivity and no side channel — the
constant-time argument that keeps `core/crypto/reference/` out of production
does not apply. It is also the best-specified algorithm in Bitcoin, with
published *invalid* vectors, which makes it genuinely testable.

The tests include an exhaustive check that **every single-character
substitution** in a real address is detected (>1000 mutations), and that every
adjacent transposition is caught.

### Network separation is enforced by the checksum

The HRP is folded into the checksum, so a mainnet address does not merely have
the wrong prefix when parsed as testnet — it **fails the checksum outright**.
Combined with distinct coin types (0 mainnet, 1 test networks), mainnet and
testnet key trees are entirely disjoint.

**Honest limitation:** signet and regtest share testnet's coin type, and signet
shares its HRP exactly. An address is indistinguishable between testnet and
signet. They are separate chains with separate UTXO sets, but no
encoding-level check catches the confusion.

---

## 11. Digital signatures — ECDSA

**Implementation:** [`core/signing/ecdsa.ts`](../core/signing/ecdsa.ts) ·
**Tests:** [`ecdsa.test.ts`](../tests/cryptography/ecdsa.test.ts)

### Signatures are not encryption

| | Encryption | Signature |
| --- | --- | --- |
| Purpose | Confidentiality | Authentication + integrity |
| Operation | `E(key, msg) → cipher` | `Sign(priv, msg) → sig` |
| Inverse | `D(key, cipher) → msg` | none — only `Verify(pub, msg, sig) → bool` |
| Hides content? | Yes | No |

Bitcoin transactions are entirely public. Signatures answer *"is this
authorised?"*, never *"what does it say?"*.

### The algorithm

```
sign:    n = nonce;  R = n·G;  r = R.x mod order
         s = n⁻¹(z + r·k) mod order        → (r, s)

verify:  u₁ = z·s⁻¹;  u₂ = r·s⁻¹;  R' = u₁·G + u₂·K;  accept iff R'.x ≡ r
```

### The nonce is the whole ballgame

Everything that has ever gone catastrophically wrong with ECDSA went wrong at
the nonce.

**Reused nonce → instant key recovery.** Two signatures under the same nonce:

```
n = (z₁ − z₂)/(s₁ − s₂)        k = (s₁·n − z₁)/r
```

Two signatures, some modular arithmetic, key recovered. No brute force. This
broke the **PlayStation 3** signing key (2010, fixed nonce) and drained
**Android Bitcoin wallets** (2013, broken `SecureRandom`).

**Biased nonce → lattice attack.** Even slight non-uniformity leaks a few bits
per signature; a few dozen signatures plus LLL/BKZ recovers the key. This is
why the rejection-sampling discussion in §3 matters far more here than for key
generation.

### RFC 6979 — removing the RNG from signing

Veyra never generates a random nonce. The nonce is derived by HMAC from
`(private key, message hash)`:

- Same key + same message → same signature, always.
- Different messages → unrelated nonces, so reuse is impossible **by
  construction**.
- **No RNG dependency at signing time.** A machine with a broken CSPRNG can
  still sign safely.
- Signatures are reproducible, so they can be tested against fixed vectors —
  something a randomised signer cannot offer.

### Low-S

If `(r, s)` verifies, so does `(r, order − s)` — the curve is symmetric. A
third party can flip S without invalidating the signature. Pre-SegWit this
changed the txid; now it only changes the wtxid, but BIP-146 made low-S a
**relay policy rule**, so a high-S signature simply will not propagate. The
signer asserts low-S before returning rather than trusting the library default
to stay put.

---

## 12. Transactions and the UTXO model

**Implementation:** [`core/transactions/`](../core/transactions/), [`core/bitcoin/serialization.ts`](../core/bitcoin/serialization.ts) ·
**Tests:** [`transaction.test.ts`](../tests/unit/transaction.test.ts), [`transaction-parser.test.ts`](../tests/fuzz/transaction-parser.test.ts)

### There are no balances

No account, no row, no `balance -= amount`. Only unspent outputs. A transaction
**consumes whole outputs** and **creates new ones**.

Holding one 1 BTC output and sending 0.1 means consuming the entire 1 BTC and
creating two outputs: 0.1 to the recipient, ~0.9 back to yourself. That second
output is **change**, and forgetting it means the remainder becomes fee. This
has happened for real, in amounts that made the news.

The fee is never written down. It is implicit:

```
fee = sum(input values) − sum(output values)
```

A transaction cannot state its own fee, so a wallet that miscalculates input
values silently overpays. Veyra requires every input to carry its value
explicitly and verifies the arithmetic before signing.

### txid vs wtxid — and why SegWit exists

```
txid  = HASH256(serialisation WITHOUT witness)
wtxid = HASH256(serialisation WITH witness)
```

Before SegWit, signatures lived in the scriptSig, inside the txid computation.
But a signature cannot commit to its own hash — so third parties could alter
signature encoding and **change the txid** without invalidating anything. This
is **transaction malleability**: it broke Mt. Gox's withdrawal system and made
Lightning impossible before 2017.

SegWit moves signatures outside the txid. The txid is now stable from the
moment of creation, *before signing* — demonstrated in `npm run demo`, where
the txid is byte-identical before and after. That stability is what makes
chained unconfirmed transactions safe.

### Non-minimal varints are a malleability vector

The value 1 can be encoded `01`, `fd0100`, or `fe01000000`. All decode to 1;
all are different bytes; all give one logical transaction different txids. The
parser rejects every non-minimal form, and rejects trailing bytes.

### Endianness

Bitcoin is little-endian — but **not uniformly**. Hashes appear in internal
order on the wire and **reversed** when displayed. The txid in a block explorer
is the reverse of the wire bytes. Veyra names these separately (`txidBytes()`
vs `txid()`) because silently mixing them produces transactions referencing
inputs that do not exist.

---

## 13. BIP-143 — what a signature commits to

**Implementation:** [`core/signing/sighash.ts`](../core/signing/sighash.ts) ·
**Tests:** [`sighash.test.ts`](../tests/cryptography/sighash.test.ts)

Spec §15 demands an exact answer. Here it is — the SIGHASH_ALL preimage:

| # | Field | Bytes | Commits to |
| --- | --- | --- | --- |
| 1 | nVersion | 4 | consensus rules |
| 2 | hashPrevouts | 32 | **every** input being spent |
| 3 | hashSequence | 32 | every input's sequence |
| 4 | outpoint | 36 | *this* input |
| 5 | scriptCode | var | the script being satisfied |
| 6 | **amount** | 8 | **this input's value** |
| 7 | nSequence | 4 | this input's sequence |
| 8 | hashOutputs | 32 | **every** output: amounts AND destinations |
| 9 | nLocktime | 4 | earliest valid time |
| 10 | sighash type | 4 | the algorithm itself |

`sighash = HASH256(preimage)`. Verified against the published BIP-143 vector:
digest `c37af311…` reproduced exactly.

### Field 6 is the critical SegWit fix

Legacy sighash did **not** include the value of the input being spent. A wallet
had to learn input values externally, and could be **lied to**.

The attack: a malicious node tells a hardware wallet an input is worth 0.01 BTC
when it is worth 10. The user approves a small-looking payment. The signature
is valid — the value was never signed. The other 9.99 BTC silently becomes
miner fee. This was a real, exploited class of vulnerability, and BIP-143
exists substantially to close it.

Now the amount is inside the preimage: a wrong stated value produces a
signature that does not verify. `sighash.test.ts` asserts that even a
**one-satoshi** difference changes the digest.

### Only SIGHASH_ALL

`NONE` signs no outputs (anyone can redirect the money). `SINGLE` signs one.
`ANYONECANPAY` lets others add inputs. They have legitimate uses in CoinJoin
and atomic swaps; every one is a foot-cannon in a normal wallet — a
SIGHASH_NONE signature is a **bearer instrument**. Veyra refuses to generate or
accept them.

### The scriptCode is deliberately odd

For P2WPKH the scriptCode is **not** the witness program — it is the equivalent
legacy P2PKH script (`76a914{hash}88ac`). Specified by BIP-143 so the SegWit
path reuses P2PKH semantics. Using the witness program instead produces a
valid-looking signature no node accepts.

### Why the three cached hashes

Legacy sighash re-serialised the whole transaction **per input** — O(n²), a DoS
vector against nodes. BIP-143 hoists three whole-transaction digests out so
they are computed once. `SighashCache` does exactly this.

---

## 14. What §15 tampering tests prove

[`tests/security/transaction-tampering.test.ts`](../tests/security/transaction-tampering.test.ts)
mutates a signed transaction and asserts verification fails. Each is an attack
a network adversary could attempt between approval and broadcast:

| Attack | Result |
| --- | --- |
| Redirect payment to attacker | ❌ rejected |
| Change amount by 1 satoshi | ❌ rejected |
| Steal the change output | ❌ rejected |
| Redirect change to attacker | ❌ rejected |
| Remove / add / **reorder** outputs | ❌ rejected |
| Change which UTXO is spent | ❌ rejected |
| Change sequence, version, locktime | ❌ rejected |
| Lie about the input value | ❌ rejected |
| Swap in attacker's public key | ❌ rejected |
| Corrupt **any single byte** of the signature | ❌ rejected (all positions) |

The parser is separately fuzzed: bit flips at every position of a valid
transaction, truncation at every length, and 5,500 random inputs. The invariant
is that it either parses correctly or throws a typed error — never crashes,
never allocates unboundedly, never silently mis-parses.

---

## 15. UTXOs, fees, and coin selection

**Implementation:** [`core/utxo/`](../core/utxo/) ·
**Tests:** [`coin-selection.test.ts`](../tests/cryptography/coin-selection.test.ts)

### A wallet has no balance — it has coins

The balance is a *derived* number. What exists is a set of fixed, indivisible
outputs, each locked to an address. Treating the balance as primary is what
makes Bitcoin wallets confusing, and it produces surprises:

- You can hold 1 BTC and be unable to send 0.6 without paying fees on many
  inputs, if that 1 BTC is a hundred 0.01 coins.
- You can have "enough" and still fail, because spending the small coins costs
  more than they are worth.

### The circular fee problem

Fees are per virtual byte, so you need the size to compute the fee — but the
fee determines how many inputs you need, which determines the size.

```
size → fee → inputs needed → size → …
```

Veyra breaks the loop by estimating from the transaction's *shape*, which is
exact for P2WPKH:

| Component | vsize |
| --- | --- |
| Input | 68 |
| Output | 31 |
| Overhead | 10.5 |

We assume the maximum 72-byte DER signature, **over**-estimating by up to a
byte per input. A stuck transaction is a far worse outcome than a few satoshis
of overpayment, so the rounding goes against us deliberately.

**Fee presets are static placeholders.** Real estimation needs live mempool
data. They are never presented as estimates — the caller must pass a rate
explicitly.

### Dust

An output worth less than the cost of eventually spending it is dust. Relay
policy rejects it, because it bloats the UTXO set every node holds in memory
forever. The P2WPKH threshold is **294 satoshis**. Below it, a transaction
simply does not propagate — which looks to the user like a wallet that silently
does nothing.

When change would fall below dust, it cannot become an output at all. Veyra
gives it to the miner as extra fee. That is not a bug; it is the only valid
option.

### What coin selection optimises

Three conflicting goals:

1. **Cost now** — fewer inputs, smaller transaction, lower fee.
2. **Cost later** — change is an output you must eventually spend, costing 68
   vbytes next time.
3. **Privacy** — spending five coins together tells an observer those five
   addresses share an owner. This is the *common input ownership heuristic*,
   the single most effective tool in blockchain analysis.

Optimising purely for goal 1 produces a wallet that fragments into dust and
leaks its whole address graph.

### Three strategies

| Strategy | Behaviour |
| --- | --- |
| **Branch and bound** | Searches for an exact, **changeless** match. Optimal when it succeeds. Bounded at 100,000 nodes — unbounded it is exponential, a self-inflicted DoS. |
| **Single random draw** | Fallback. Random is deliberate: deterministic strategies produce recognisable on-chain patterns that fingerprint the wallet software. |
| **Largest first** | Minimises input count and immediate fee, at the cost of destroying large coins. Available but **not default**, so the trade-off is visible and testable. |

A **changeless** transaction is ideal: it avoids the change output now and
later, and destroys the change-detection heuristic analysts rely on.

### §33 property testing

Example tests only prove the cases someone thought of. These invariants are
asserted across ~6,000 randomly generated scenarios:

- selection **never** covers less than `target + fee`
- value always balances: `inputs = target + fee + change`
- change is **never** dust
- no coin is selected twice, and none from outside the supplied set
- frozen, unconfirmed, and immature coinbase coins are never selected

Every strategy is tested independently, so a bug in one cannot hide behind
another. All checks are re-asserted at the single exit point of `selectCoins`
rather than trusted from each algorithm.

---

## 16. The wallet layer

**Implementation:** [`core/wallet/wallet.ts`](../core/wallet/wallet.ts) ·
**Tests:** [`wallet.test.ts`](../tests/unit/wallet.test.ts)

### The secrecy boundary

This is where secrets stop. Everything above — API, UI — deals in addresses,
amounts, and transaction hex. None of them can obtain key material, because
none is given a way to ask.

There is **no `getMnemonic()`** and **no `exportPrivateKey()`**. The mnemonic
is returned exactly once, at creation. If the caller discards it the funds are
unrecoverable — which is the honest behaviour for self-custody: *a copy the
wallet can retrieve is a copy an attacker can retrieve.*

### The gap limit

A restored wallet does not know how many addresses it used. Convention
(BIP-44) is to scan until 20 consecutive addresses show no history.

So handing out addresses far ahead of use is dangerous: receive at address 50
without using 0–29, and a restore scans to 20, finds nothing, and reports an
empty wallet. The funds are not lost — the scan stopped short. Veyra refuses to
generate beyond the gap limit.

### Change address rotation

Every transaction sends change to a **fresh** internal address. Reuse is a
privacy failure, not untidiness: change detection is one of the two pillars of
blockchain analysis, and a repeated change address links transactions with high
confidence.

### Order of operations

Everything that can fail is checked **before any signature exists**, so a
rejected send never leaves a partially-signed transaction behind:

1. Validate the destination address for **this network**
2. Reject dust and non-positive amounts
3. Select coins (may refuse — insufficient funds)
4. Build outputs, derive a fresh change address
5. Sign
6. **Verify what we just produced**
7. Confirm the actual fee matches the plan

Step 6 is not paranoia about the crypto library — it catches the far likelier
bug of signing with the wrong key or a wrong input value, both of which produce
a structurally perfect transaction the network silently rejects.

`send()` does **not** mutate wallet state. The user may review and decline;
only a confirmed broadcast should consume coins, via `markSpent()`.

### §16 in full

`PreparedTransaction` returns Amount, Fee, Total, and Remaining Balance as
data, not as UI strings — so an API client gets identical guarantees to the
interface. A UI-only check is bypassed by anything calling the core directly.

---

## 17. Chain connectivity — the untrusted boundary

**Implementation:** [`core/chain/`](../core/chain/) ·
**Tests:** [`chain-sync.test.ts`](../tests/unit/chain-sync.test.ts), [`esplora.test.ts`](../tests/unit/esplora.test.ts)

Everything before this section was arithmetic on data we produced ourselves.
From here, data arrives from a server we do not control.

### What a malicious chain source CAN do

| Attack | Effect |
| --- | --- |
| Report UTXOs that don't exist, or hide ones that do | Failed broadcasts; a user who thinks they are poorer |
| Claim a transaction is confirmed when it is not | A merchant delivers goods against a confirmation that never happened |
| Accept a broadcast and silently drop it | Payment never happens |
| **Learn your entire wallet** | See below — the one people underestimate |

### What it CANNOT do

| Attempt | Why it fails |
| --- | --- |
| Understate an input's value so the difference becomes miner fee | **BIP-143 signs the amount.** A wrong value produces a signature that does not verify. Closed by the protocol, not by us |
| Forge a signature | Never sees a private key |
| Redirect a payment | Destination is chosen locally and committed to by the signature |

So the realistic damage is **denial of service, misinformation, and privacy
loss — not theft.** Stating that precisely matters, because it determines how
much defensive machinery is justified.

### ⚠️ The privacy leak is the real cost

Querying a public server for your addresses tells it: every address in your
wallet, that they belong to *one* wallet, your IP, your balance, your full
history, and when you transact.

The blockchain is public — but *which addresses are yours* is not, and a light
wallet query hands over exactly that. **No cryptography prevents this.** It is
inherent to asking someone else about your coins.

Mitigations: run your own Esplora/Electrum against your own node; use Tor
(removes IP linkage, not address clustering); or use compact block filters
(BIP-157/158), where the client never reveals which addresses it cares about.

Veyra has **no chain source by default**. One must be passed explicitly to
`sync()` or `broadcast()`, and `privacyWarning` is surfaced for any non-local
server.

### The gap-limit scan

Walks each chain asking whether each address was ever used, stopping after 20
consecutive unused ones — matching BIP-44 convention. Scanning *differently*
from other wallets would be an interoperability failure that looks exactly like
lost money.

The scan continues **past** a used address, resetting the counter, so a wallet
with a gap in the middle is still found. It is bounded at index 1000 per chain
so a server claiming every address has history cannot drive an unbounded scan.

### Defences implemented

- **Responses are parsed defensively.** `response.json()` returns `any`, and
  `any` flowing into money arithmetic is how a malformed field becomes a wrong
  balance.
- **Amounts are BigInt, and unsafe integers are rejected.** JSON numbers are
  IEEE doubles; above 2⁵³ they round silently. The entire money supply
  (2.1×10¹⁵) fits below that, so anything larger is a bug or an attack.
- **A synced UTXO is structurally attributed to the address the wallet
  derived**, never to one the server names — there is no field for injection.
- **Broadcast responses are checked** against the locally-computed txid. A
  mismatch is treated as failure: the transaction's fate is unknown, so
  recording success would be a lie of our own. Coins stay unspent and the
  broadcast is retryable.
- **Bounded everything**: response size, entry counts, retries, timeouts. Only
  5xx is retried — a 4xx is a definitive answer, and retrying leaks extra
  requests.

### ⚠️ Verification status

The Esplora client has **not been tested against a live server.** It was built
without access to one and is tested against a controlled fake implementing the
documented API shape.

Verified: request paths, defensive parsing, error handling, retry logic,
timeouts, size caps. **Not verified:** that a real server's responses match the
documented shape. This must be run against a regtest Esplora instance before it
touches real funds.

`MemoryChainSource` is likewise **not a Bitcoin node**. It does not validate
transactions, enforce consensus, or check signatures. A broadcast succeeding
there means nothing about the real network. §36's "development on regtest"
requirement is *not* satisfied by it.

---

## 18. Consensus verification — the gap that unit tests cannot close

**Implementation:** [`core/chain/bitcoinRpc.ts`](../core/chain/bitcoinRpc.ts) ·
**Tests:** [`regtest.test.ts`](../tests/integration/regtest.test.ts) ·
**Setup:** [REGTEST.md](REGTEST.md)

### The problem with every test above this line

All 519 of them validate Veyra against *my reading of the specifications*. The
BIP-143 vector proves the sighash matches the document. The tampering tests
prove signatures break when they should.

**None of them prove a real Bitcoin node will accept a transaction Veyra
produces.**

Consensus rules are not fully written down anywhere — the implementation is
normative. A transaction can satisfy every rule I know about and still be
rejected for one I have never heard of. Unit tests can only check the rules
their author already knows, so no quantity of them closes this gap.

The only way to close it is to hand a transaction to `bitcoind` and see what it
says. That is why §36 requires regtest for development rather than treating a
mock as sufficient.

### Why regtest

A private chain where you mine on demand: coins are worthless, blocks are
instant, every variable is yours. It runs the **same consensus code as
mainnet**, which is the whole point.

### scantxoutset vs importdescriptors

| | Behaviour | Trade-off |
| --- | --- | --- |
| `importdescriptors` | Node watches and indexes addresses | Fast queries; mutates node state, needs a wallet, rescans are slow |
| `scantxoutset` | Scans the UTXO set on demand | Stateless, no wallet, no mutation; slower per query |

Veyra uses `scantxoutset`. For a test harness, not mutating node state is worth
more than query speed — a stateless source cannot leave one test's imports
behind to corrupt the next.

**This would be the wrong choice for a production mainnet wallet**, and it has
a real consequence: `scantxoutset` sees unspent outputs only, so a fully-spent
address looks *unused*. The gap-limit scan may therefore stop earlier against a
node than against Esplora. Recorded here rather than discovered later.

### Amounts: why the string round-trip

Core reports BTC as JSON numbers — IEEE doubles. `0.1 * 1e8` is
`10000000.000000002`; `4.35 * 1e8` is `434999999.99999994`. `Math.round` hides
this in most cases, and *"usually correct"* is not a property money arithmetic
may have.

`btcToSatoshis` therefore works on the decimal string, never the float, and
rejects anything with more than 8 decimal places.

### What the integration suite establishes

Core accepting a Veyra transaction; Core computing the same txid (proving
byte-exact serialisation); Core rejecting a tampered recipient; multi-input
correctness; that change is spendable after it returns; that a restored
mnemonic finds real funds; and that our `MIN_RELAY_FEE_RATE` matches Core's
actual policy rather than a number I picked.

### Status: PASSING as of 2026-08-20

All 10 integration tests passed against Bitcoin Core v29 on Windows/regtest.
Core accepted a Veyra transaction, computed an identical txid, and rejected a
tampered one. The gap described above is closed for regtest.

### The suite skips loudly

Without a node the tests report as **skipped**, with a warning. This is
deliberate: a skipped test honestly reports that verification did not happen. A
mock standing in for a node would report success while verifying nothing —
strictly worse than an admitted gap.

---

## 19. What is not yet built

Real fee estimation from mempool data, transaction history enrichment, the API
layer, and the UI.

The consensus caveat is now discharged for regtest: **Bitcoin Core has accepted
a transaction produced by this code**, and computed the same txid for it. What
remains true is that **none of it has handled real funds on any network**, and
that mainnet has never been exercised end to end.
