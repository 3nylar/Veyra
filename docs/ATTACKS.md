# Veyra — Attack and Defect Log

> **§31 is mandatory.** Every vulnerability, and every defect that weakened a
> defence, is recorded here with its root cause, fix, regression test, and
> lesson. Nothing is silently patched.
>
> **These are real findings from this codebase**, not illustrative examples.
> Each was discovered during development, most by a test failing. They are
> recorded whether or not they were exploitable, because a defect that
> *silently disabled a security control* is more dangerous than one that
> crashed loudly — it produces a green tick that nobody re-examines.

---

## Severity scale

Severity is **impact**, not category. An earlier version of this table defined
the levels by the kind of finding ("a test that checked nothing"), which
described one entry rather than measuring any of them — and consequently
mislabelled VEY-002, a self-inflicted denial of service, as though it were a
test defect.

| Level | Meaning |
| --- | --- |
| **Critical** | Funds could be lost or stolen |
| **High** | A security control was disabled, bypassed, or silently ineffective |
| **Medium** | Funds or the wallet could become unavailable; or a control was verified only in appearance |
| **Low** | Correctness, robustness, or process defect with no security or availability impact |

A defect that *silently* disables a control ranks above one that crashes: a
crash gets fixed, a green tick gets trusted.

---

## VEY-001 — Security guard silently stopped guarding on Windows

**Severity:** High · **Found:** increment 1, by a user running the suite on Windows

### Attack
Not an external attack. The failure mode: a developer on Windows would see a
fully green suite while two security guards checked nothing at all.

### Failure
`tests/cryptography/entropy.test.ts` crashed with
`ENOENT: scandir 'C:\C:\Veyra\core'`. Investigating that crash revealed a
second, worse defect in `reference-implementations.test.ts` that did **not**
crash.

### Root cause
Two distinct path bugs:

1. `new URL("../../core", import.meta.url).pathname` returns `/C:/Veyra/core`
   on Windows — leading slash, forward slashes. `join()` then produced
   `C:\C:\Veyra\core`. On Linux `.pathname` happens to be correct, so my
   container never saw it.

2. The isolation guard filtered files with
   `relative(coreRoot, f).startsWith("crypto/reference")`. Windows `relative()`
   returns `crypto\reference\sha256.ts` — **backslashes** — so the comparison
   was always `false`.

Bug 2 is the serious one. It did not crash. It made three tests iterate an
empty array and pass vacuously, disabling the §4 guarantee that the
timing-unsafe reference implementations never become the production security
boundary.

### Fix
`fileURLToPath()` instead of `.pathname`, and a `relativePosix()` helper that
normalises separators at the boundary.

### Regression test
Two layers, because fixing only the separator would leave the same trap for the
next platform:

- `relativePosix()` normalises separators.
- A **backstop** test asserts the reference-file filter matches *exactly* the
  two expected files. Asserted exactly rather than `> 0`, so deleting a file
  also trips it.

### Lesson
**A guard that can silently stop guarding needs its own assertion that it is
still guarding.** Any test whose body iterates a filtered collection should
assert the collection is non-empty — otherwise a filter bug converts the test
into a no-op that reports success.

Also: a second test platform found in one increment what a single platform
structurally could not.

---

## VEY-002 — Scan depth and ownership check disagreed about the wallet's own addresses

**Severity:** Medium (availability — the wallet refused its own funds) ·
**Found:** increment 5, by a test failing

### Attack
Self-inflicted denial of service. A wallet synced with a wider gap limit would
discover its own funds and then refuse them.

### Failure
`Wallet.sync(chain, { gapLimit: 40 })` discovered a UTXO at address index 30,
then `setUtxos` threw *"UTXO is for an address this wallet does not control"* —
about its own address.

### Root cause
`knownAddresses()` always derived exactly `GAP_LIMIT` (20) addresses, while
`sync()` accepted a caller-supplied depth. Two sources of truth about the same
question, allowed to disagree.

### Fix
One source of truth that grows: `knownAddresses(depth)` extends the cache and
never shrinks. `sync()` widens it to the scan depth before validating, and
widens it further whenever the scan runs past the limit on a used address.

### Regression test
`chain-sync.test.ts` — *"STOPS after the gap limit"* funds address 30, asserts
a default scan finds nothing, then asserts a `gapLimit: 40` scan finds it.

### Lesson
**Two pieces of code answering the same question will eventually disagree.**
The bug was not in either function; it was in there being two.

---

## VEY-003 — The fix for VEY-002 was quadratic

**Severity:** Low · **Found:** immediately after VEY-002, by the suite timing out

### Failure
The suite went from seconds to a 200-second timeout.

### Root cause
The first fix called `knownAddresses(index + 1)` on every discovered address,
and that function re-derived the **entire** set each time. Thirty discovered
addresses meant roughly 1,800 EC scalar multiplications.

### Fix
Derive only the new range, incrementally.

### Lesson
**A correctness fix can create a denial of service.** The fix needed the same
scrutiny as the bug. Worth noting the earlier instance of the same shape:
`setUtxos` re-derived 40 addresses on every call — invisible in normal use, but
seven seconds inside a property test. My first instinct there was to make the
*test* cheaper, which would have hidden a real inefficiency in production code.

---

## VEY-004 — Prototype-pollution test attacked nothing

**Severity:** Medium (a control verified only in appearance) ·
**Found:** increment 7, by the test failing for the wrong reason

### Failure
The test expected a 4xx and received a 200 — because the request it sent was
perfectly valid.

### Root cause
```js
JSON.stringify({ __proto__: { polluted: true } })   // → "{}"
```

In an **object literal**, `__proto__:` sets the prototype rather than creating
an own property. So the hostile field was dropped before the request was sent,
leaving a valid `{to, amount, feeRate}` body — which the API correctly accepted
with a 200. The test had never sent a pollution attempt at all.

(An earlier draft of this entry claimed the test "had been passing on an
earlier run for unrelated reasons". That was not observed — it failed on its
first execution. The claim was plausible reconstruction rather than record, and
is corrected here for the same reason VEY-005 exists.)

`JSON.parse`, by contrast, *does* create `__proto__` as an own property — so
the real attack shape is raw JSON text, which is exactly what an attacker
sends.

### Fix
Send the payload as a raw string. Added a second test for a nested variant.

### Regression test
`api-security.test.ts` — *"rejects prototype-pollution attempts"* and *"does
not pollute the prototype even via a deeply nested payload"*. Both assert
`Object.prototype` is unpolluted afterwards.

The defence itself was already correct: the unknown-key allowlist rejects
`__proto__` like any other unexpected field. The defect was entirely in the
test that claimed to verify it.

### Lesson
**A security test that passes without exercising the attack is worse than no
test**, because it is counted as coverage. When writing a test for a specific
attack, verify the payload actually reaches the code under test — here, by
confirming the serialised body contains the hostile field.

---

## VEY-005 — Fabricated data in a test fixture

**Severity:** Medium (verification only in appearance) ·
**Found:** increment 2, during self-review

### Failure
A BIP-39 vector table contained a seed value I could not source. I had filtered
that row out of the seed assertion and left the placeholder bytes in the file.

### Root cause
Wanting the table to look complete. The filtered assertion meant the value was
unused — but it sat in a fixture looking authoritative, and a later maintainer
could reasonably have re-enabled it.

### Fix
Split into `ENTROPY_VECTORS` and `SEED_VECTORS`. Every asserted value now
traces to the published specification. The unsourced vector appears only where
its entropy/mnemonic mapping is verifiable.

### Lesson
**A fabricated vector is worse than a missing one.** It looks like
verification while providing none. Five independently published seeds is ample;
a sixth invented one subtracts credibility from the other five.

---

## VEY-006 — "Off-curve" was assumed rather than computed

**Severity:** Low · **Found:** increment 1, by the test failing

### Failure
A test asserting that an off-curve point is rejected used `x = 1`, on the
assumption that a small `x` obviously would not lie on the curve. It does:
`y² = 8` has a square root mod `p`.

### Root cause
Intuition about a finite field. Roughly **half** of all `x` values lie on the
curve; smallness is unrelated.

### Fix
`x = 5` (`y² = 132`, a quadratic non-residue by Euler's criterion), computed
rather than guessed. Added the complementary test that `x = 1` **is** accepted.

### Lesson
**A validator test built on an assumption can pass while checking nothing.**
Had the point been on-curve *and* the validator broken, the test would have
gone green. Test inputs for negative cases must be computed, not assumed.

---

## VEY-007 — Packaging step destroyed the working tree

**Severity:** Low (process) · **Found:** increment 5 and again in increment 6

### Failure
Test runs failed with `Cannot find package 'vitest'` twice, in separate
increments.

### Root cause
The packaging step deleted `node_modules` in place before copying. I reinstalled
each time rather than fixing the cause — treating a recurring symptom as an
incident.

### Fix
A tar-based script that *excludes* rather than deletes, so the source tree is
never modified. Verified afterwards that `node_modules` survives packaging.

### Lesson
**A recurring failure is a defect, not an incident.** Fixing it the second time
took less effort than the two reinstalls, and the first reinstall had already
signalled the problem.

---

## VEY-008 — API unreachable from any browser (missing CORS preflight)

**Severity:** Low (availability) · **Found:** increment 9, by a user opening the UI

### Attack
Not an attack. A complete availability failure that every test missed.

### Failure
The interface loaded, rendered correctly, and showed *"Cannot reach the Veyra
API. Check that it is running."* — while the API was running and healthy.

### Root cause
A browser sends a `OPTIONS` **preflight** before any cross-origin request
carrying an `Authorization` header. The API had no `OPTIONS` route, so it
returned 404, and the real request was never sent.

The reason 55 API tests missed it is the instructive part: **they all called
`fetch` from Node, which does not enforce CORS.** Every request in the suite
succeeded because Node has no same-origin policy to violate. The test
environment differed from the real one in precisely the dimension under test.

### Fix
Handle `OPTIONS` before the auth check — the browser strips `Authorization`
from a preflight by design, so requiring it there means every browser request
fails. CORS headers are emitted for an explicit **allowlist** of origins, never
`*`.

Design points worth stating:

- **No wildcard.** The token is the real defence, but `*` would let any site
  probe this API from a victim's browser and read the replies, turning a stolen
  token into a usable one from anywhere.
- **No `Allow-Credentials`.** Auth is a bearer token set by our own client,
  never a cookie. Permitting credentialed requests would grant reach without
  granting any capability we need.
- **`Vary: Origin`** on every response, so a shared cache cannot serve an
  allowed origin's response to a disallowed one.
- **Preflights are rate-limited** and return an identical 204 for every path,
  so they cannot become a free channel or a route-enumeration oracle.

### Regression test
Eight tests in `api-security.test.ts` under *"CORS (regression: VEY-008)"*,
including that an unlisted origin gets no CORS headers, that the wildcard is
never used, and that a preflight does not exempt the following request from
authentication.

### Lesson
**A test environment that differs from the real one in the dimension under
test proves nothing about that dimension.** Node's `fetch` and a browser's
`fetch` are not the same client, and the difference is exactly the security
model this feature depends on.

The general form: when a component's behaviour is defined by a *policy the
runtime enforces* — CORS, CSP, cookie scoping, sandboxing — testing it in a
runtime without that policy tests something else. This is the same shape as
VEY-001, where a Linux-only test run could not see a Windows path bug.

---

## VEY-009 — A test measured the machine instead of the code

**Severity:** Low (test quality) · **Found:** increment 9, by a user running the
suite on their own hardware

### Failure
`AssertionError: expected 14122 to be less than 10000`

The bounded-scan test failed on a slower machine. **The bound it was testing
worked perfectly** — the scan terminated at exactly 2000 addresses, as
designed. What failed was the assertion.

### Root cause
Two separate problems, and only one of them was the test.

**The test asserted the wrong thing.** It measured elapsed wall-clock time,
which is a property of the hardware, the system load, and the runtime — not of
the code under test. A machine roughly 40% slower fails it while the security
property holds completely. In CI, under parallel load, or on any modest laptop,
it would flake.

**The code was also genuinely slow.** 2000 derivations took 14 seconds because
`Bip84Account.deriveAddress` recomputed two EC scalar multiplications and a
HASH160 every time, including for addresses it had already derived moments
earlier during the same scan.

### Fix
Both halves:

1. **The test now asserts the bound**, exactly: `expect(calls).toBe(2000)`.
   That is deterministic, machine-independent, and is the actual security
   property. Liveness is still covered — if the ceiling were removed the test
   would never return and vitest's own timeout would fail it.

2. **`Bip84Account` memoises derived addresses**, bounded at 4000 entries so
   the optimisation cannot itself become a memory-exhaustion vector. Sound
   because derivation is a pure function of the account node, chain, and index.
   The cache holds public data only.

Result: that test went from 14.1s to 1.45s, and the file from 26.9s to 3.2s.

### Sweep
Five further wall-clock assertions were found in the fuzz and coin-selection
suites. These guard against *catastrophic* blowup — unbounded allocation,
exponential search — where the failure mode is exhausting memory or never
returning, not being marginally slower. They were kept but their thresholds
raised substantially, with a comment stating they are catastrophe detectors
rather than performance targets.

### Regression test
`chain-sync.test.ts` — *"bounds the scan…"* asserts the exact call count, and
*"re-scanning is fast, because derivation is cached"* asserts object identity
from the memo rather than timing anything.

### Lesson
**A timing assertion tests the machine unless the failure mode it guards is
catastrophic.** Distinguish the two cases: guarding against "unbounded" can use
a loose ceiling, because the difference between bounded and unbounded is not
40%. Guarding against "slow" with a wall-clock number encodes the author's
hardware into the test suite.

Where a deterministic property exists — a call count, a cache hit, an
allocation bound — assert that instead. The property is what you meant; the
duration was only ever a proxy for it.

Worth noting this is the third finding from the same source: running the suite
on hardware and an operating system unlike mine (VEY-001, VEY-008, VEY-009). A
single machine cannot find bugs whose cause is that there is only one machine.

---

## VEY-010 — Setup guide pointed at the wrong config directory on Windows

**Severity:** Low (documentation) · **Found:** increment 6 setup, by a user
following REGTEST.md

### Failure
`ChainError: RPC authentication failed — check the username and password`

The node was running and answering — a 401 means it responded — but with
credentials that did not match. The username and password were correct in both
places.

### Root cause
`docs/REGTEST.md` told the user to write `bitcoin.conf` to
`%APPDATA%\Bitcoin` (i.e. `AppData\Roaming`). Recent Bitcoin Core builds on
Windows default their data directory to `%LOCALAPPDATA%\Bitcoin`
(`AppData\Local`). The config file was written to a directory the node never
read, so it started with no `rpcuser` at all and rejected every request.

The installer's own welcome screen displayed the correct path —
`C:\Users\<user>\AppData\Local\Bitcoin` — which is how it was diagnosed.

### Fix
`docs/REGTEST.md` now writes the config to **both** locations, and adds a
verification step that prints the file back and confirms the node reports
`"chain": "regtest"` before the tests are run.

### Lesson
**A 401 from a service you configured usually means the configuration was
never read.** The instinct is to re-check the credentials; the more productive
check is whether the file is where the program looks.

More generally: setup instructions are code that runs on someone else's
machine, and they inherit the same portability problems as code. This is the
fourth Windows-specific finding in the log (VEY-001, VEY-008, VEY-009,
VEY-010), and the second where a path differed from the author's platform.

---

## VEY-011 — Float arithmetic overcharged fees by up to 100%

**Severity:** Medium (funds — overpayment, capped and non-catastrophic) ·
**Found:** increment 11, by a test written at the same time as the code

### Failure
`expected 3 to be 2` — a fee estimate of 2 sat/vB was reported as 3.

### Root cause
Bitcoin Core reports fee rates in **BTC per kvB**. The conversion to sat/vB
was written the obvious way:

```js
Math.ceil((feerate * 1e8) / 1000)
```

In IEEE 754, `(0.00002 * 1e8) / 1000` is **2.0000000000000004**, and
`Math.ceil` promotes that to **3** — a 50% overcharge. `0.00001` is worse: the
true value is 1, the computed value 2, a **100% overcharge**.

These are ordinary fee rates, not contrived edge cases. Checked across six
common values, two were wrong.

The bug is doubly embarrassing in context: this same file already contains
`btcToSatoshis`, written specifically to avoid float money arithmetic, with a
comment explaining that `4.35 * 1e8` is `434999999.99999994`. I then wrote the
identical mistake forty lines below it.

### Fix
Convert through the existing decimal-string path, then divide with BigInt:

```js
const satPerKvb = btcToSatoshis(result.feerate, …);   // exact: 2000n
const satPerVb  = (satPerKvb + 999n) / 1000n;          // exact ceiling: 2n
```

Rounding up is deliberate — under-paying risks a stuck transaction, which is a
far worse outcome than a satoshi of overpayment.

### Regression test
`bitcoin-rpc.test.ts` — *"REGRESSION (VEY-011): float conversion overcharges by
up to 100%"* asserts seven common rates including both values the float path
got wrong.

### Lesson
**Establishing a rule is not the same as following it.** The project had
already identified float money arithmetic as a hazard, written a helper to
avoid it, and documented why — and the bug still appeared in the same file,
because the new code path did not *look* like currency conversion. It looked
like unit conversion.

The generalisable check: any expression combining a float with `1e8`,
`Math.ceil`, or `Math.round` in a money path is suspect regardless of what it
appears to be converting. Grep for the shape, not the intent.

Worth noting how it was caught: the test asserted a specific expected value
rather than a range. `toBeGreaterThan(0)` would have passed.

---

## VEY-012 — A Taproot address encoder accepted anyone-can-spend outputs

**Severity:** Medium (funds — would create outputs anyone could take) ·
**Found:** increment 12, by a test written alongside the code

### Failure
`expected [Function] to throw an error` — `p2trAddress()` happily encoded a
20-byte output key.

### Root cause
`p2trAddress` delegated length validation to `encodeSegwitAddress`, which
correctly implements BIP-350: witness programs may be **2 to 40 bytes** for
version 1, because future upgrades may define other lengths.

But a version-1 output that is not exactly 32 bytes **is not Taproot**. Under
current consensus rules such an output is unencumbered — *anyone can spend it*.
Encoding one produces an address that looks entirely valid, passes checksum
validation, and gives the coins to whoever notices first.

The generic validator was right; the Taproot-specific constraint simply was not
its job, and I had assumed the layer below would catch it.

### Fix
`p2trAddress` now enforces exactly 32 bytes itself, with an error that states
the consequence rather than only the rule:

> `A version-1 output of any other length is spendable by anyone.`

### Regression test
`taproot.test.ts` — *"REFUSES a non-32-byte output key — such an output is
anyone-can-spend"* checks lengths 2, 20, 31, 33 and 40, and confirms 32 passes.

### Lesson
**A general validator being correct does not mean a specific one is
unnecessary.** BIP-350's range is right for what it validates; Taproot's
constraint is narrower and lives a layer up. Delegating validation downward is
only safe when the lower layer knows the same invariant — and here it
deliberately did not, because its job was to remain open to future versions.

The shape to watch for: a permissive check that exists to allow future
extension, relied upon by a caller that needs a present-day restriction.

---

## VEY-013 — The test runner's default timeout was an unnoticed wall-clock assertion

**Severity:** Low (test quality) · **Found:** increment 15, by a user running
the suite on their own hardware

### Failure
```
Error: Test timed out in 5000ms.
  tests/unit/wallet.test.ts > value conservation across a spend
```

The property held. 200 randomised sends all satisfied
`inputs = amount + fee + change`. The test simply took longer than five
seconds on that machine — about 2 s here.

### Root cause
Two things, and the first is the interesting one.

**Vitest's 5-second default timeout is a wall-clock assertion applied to every
test, and I never wrote it.** VEY-009 taught me not to assert elapsed time —
and I then left the runner asserting it implicitly on all 843 tests. The lesson
had been learned about explicit assertions and missed entirely about the
default.

**The send path was also genuinely slow.** `send()` called
`master.derivePath(...)` once **per input**, and that path costs ~2.6 ms — three
hardened levels of HMAC-SHA512 plus EC multiplication. A twenty-input
transaction paid it twenty times.

### Fix
1. **`testTimeout: 30_000` in `vitest.config.ts`**, with a comment explaining
   that these are correctness tests rather than benchmarks: there is no number
   here that means "fast enough", only one that means "did not hang".
2. **A bounded cache of derived signing nodes.** 10.6 ms → 8.1 ms per send.

The remaining cost is ECDSA signing plus verification. `send()` verifies its own
output *after* `signTransaction` already verified each signature, which doubles
the verify cost — and that redundancy was **kept deliberately**: it validates
the assembled witness, not just the signatures, which is a different failure
class.

### The trade-off in the cache, stated rather than assumed
Caching derived nodes keeps private key material resident longer, which looks
like a security regression. Materially it is not: the master key is already
resident for the process lifetime, and anyone who can read this process's memory
can derive every child from it in microseconds. The cache grants no capability
an attacker did not already have.

It *would* matter for a wallet that unloaded its master between operations. This
one does not, and A5 of the threat model already places that attacker out of
reach — but the comment on the cache says so, so the assumption is visible if it
ever changes.

### Lesson
**Defaults are assertions you did not write.** A framework's timeout, a
linter's threshold, a default retry count — each encodes a decision, and one
you did not make is one you have not checked.

The narrower form: after fixing a class of bug, search for the *implicit*
instances. VEY-009 removed the explicit wall-clock assertions; the default
survived because it was not in the code I was reading.

Worth noting the profile step here mattered. The reflex was to raise the
timeout, which would have hidden a real 24% inefficiency in the signing path —
the same instinct I caught myself having in VEY-003.

---

## VEY-014 — The architecture documented a portability claim that was false

**Severity:** Low (documentation, but it blocked a real feature) ·
**Found:** increment 17, while building the client-side signer

### Failure
`docs/ARCHITECTURE.md` stated:

> `core/` must never import from `api/` or `app/`. That is what makes it
> testable without a server **and portable into a mobile UI unchanged**.

The first half was true and guarded. The second half was **false**, and had
been for months. Four modules used Node-only APIs:

| Module | Node dependency |
| --- | --- |
| `wallet/keystore.ts` | `node:crypto` — scrypt, AES-GCM |
| `psbt/psbt.ts` | `Buffer` — base64 |
| `addresses/bip84.ts` | `Buffer` — hex |
| `derivation/bip32.ts` | `Buffer` (via helpers) |

A single `node:` import poisons the whole dependency graph: importing the
wallet pulls in the keystore, so *nothing* in `core/` would load in a browser.

### Root cause
Every test ran in Node, so nothing exercised the claim. The guard tests that
protect the other structural invariants — no `Math.random()`, no reference-code
imports — exist because those failures are invisible to behavioural testing.
Portability is exactly the same shape, and I had not written the equivalent
guard.

The claim was also load-bearing in a way I had not noticed. It is the
justification for the whole client-side signing architecture, and that
architecture was impossible to build until this was fixed.

### Fix
- `bytesToBase64` / `base64ToBytes` in `core/crypto/bytes.ts`. `Buffer` is
  Node-only and `btoa`/`atob` are browser-only, so implementing it removes the
  question entirely.
- The keystore now uses **`@noble/hashes` scrypt** and **WebCrypto AES-GCM**,
  both identical across Node, browsers, and React Native. (WebCrypto offers
  only PBKDF2 as a KDF, which is precisely the thing being avoided — hence
  noble for the KDF and WebCrypto for the cipher.)
- `SubtleCrypto` is declared structurally rather than importing `lib.dom`,
  so naming one interface does not make every browser global visible to code
  that must not rely on them.

### Regression test
`tests/cryptography/portability.test.ts` — a source scan asserting no `node:`
import, no `Buffer`, no Node globals, **and** no DOM globals, since portable
means both directions. `chain/bitcoinRpc.ts` is allowlisted narrowly, with a
backstop asserting the allowlisted file exists so the guard cannot cover
nothing (the VEY-001 lesson).

Plus a differential test proving the hand-written base64 matches `Buffer`
across 200 random inputs and every padding case.

### Lesson
**A claim in documentation is an assertion nobody is running.** The invariants
that survived — no `Math.random()`, reference isolation — survived because each
had a test. This one had a paragraph.

Anything stated as a structural guarantee should either have a guard or be
rewritten as an intention. "core/ is portable" was the former in tone and the
latter in fact.

---

## VEY-015 — The "self-contained" wallet file was not self-contained

**Severity:** Medium (availability — the wallet would not load at all) ·
**Found:** increment 18, by noticing a file size

### Failure
`veyra-sign.html` built at **15 KB**. A page containing secp256k1, SHA-256,
BIP-32 and BIP-39 cannot be 15 KB, and the size was the only symptom — the
build reported success and every assertion passed.

### Root cause
Vite code-splits shared code across multiple entry points. The signer and the
watch page both use the crypto, so it went into a common chunk, and the
"self-contained" file contained:

```js
import{s as X,a as Q,…}from"./ecdsa-C-EmpbL1.js"
```

A file that does not exist beside it. Opened from `file://`, the page would
have loaded **blank**.

My `assertSelfContained` check scanned for `<script src>`, `<link href>`, CSS
`@import`, and source maps — all HTML-level references. The import was inside
JavaScript, where no HTML-tag scan reaches.

### Fix
Two parts:

1. **One Vite build per page**, with `inlineDynamicImports: true` — which
   forces a single bundle and is only legal with a single input. The crypto is
   duplicated in each file, and that is the cost of both files standing alone.
2. **The missing assertion.** `assertSelfContained` now also fails on any
   `import … from "./…"` or `import("./…")` remaining in the output.

Result: 15 KB → 105 KB, which is the size a wallet's cryptography actually
takes.

### Regression test
`tests/unit/standalone-flow.test.ts` exercises the full air-gapped round trip —
watch builds a PSBT, signer signs it, watch broadcasts it — so a break at any
seam fails the suite rather than producing a blank page a user discovers.

The build itself now refuses to emit a file with an unresolved import.

### Lesson
**A guard checks the layer it is written at.** Mine scanned HTML for external
references and was correct about HTML; the reference that mattered was one
layer down, in the JavaScript, and was invisible to it.

The generalisable question: *for each thing this guard is meant to prevent,
what representations can it take?* "Fetches something external" has an HTML
form and a JavaScript form, and I had checked one.

Worth noting what actually caught it: a file size that did not match what the
file was supposed to contain. Not an assertion — a number that looked wrong.
Which is an argument for printing sizes in build output at all.

---

## VEY-016 — A security guard was reading its own explanatory comment

**Severity:** Medium (the control it protected could be removed silently) ·
**Found:** increment 19, by testing whether the guard actually fired

### Failure
None visible. The build passed, and would have passed on a wallet with no
protection at all.

### Root cause
`veyra.html` holds keys **and** reaches the network. Its only defence against
exfiltration is a **pinned `connect-src`** — an explicit allowlist of chain
endpoints, so injected script cannot POST a seed anywhere else. Replace that
with `connect-src https:` and the defence is gone.

So the build asserts the allowlist is pinned:

```ts
const match = /connect-src ([^;"]+)/.exec(html);
```

Run against the whole document, the first match was the **HTML comment above
the tag** — the paragraph explaining why the allowlist must be pinned. That
text contains no wildcard, so the check passed on prose and never examined the
directive.

Planting `connect-src https:` confirmed it: the build emitted the file without
complaint.

### Fix
Parse the actual `<meta>` `content` attribute, then the `connect-src`
directive within it, then check each source token against `*`, `https:`,
`http:`, `data:` and `blob:`.

Verified in **both** directions, which is the part that matters:

- normal build → passes, emits `veyra.html`
- `connect-src https:` planted → `Error: veyra.html has a WILDCARD connect-src: https:. Refusing to emit it.`

### Lesson
**A guard that has never been seen to fail has not been tested.** This one was
written, read carefully, and looked right. It was verified only when I planted
the failure it existed to catch — and it did not catch it.

The specific trap is worth naming: **regexes over a whole document match
documentation about the thing before they match the thing.** The better the
comment explaining a security control, the more likely a naive scan finds the
comment first. Parse the structure, not the text.

This is the third guard-quality finding (VEY-001 vacuous filter, VEY-015 wrong
layer, VEY-016 wrong target). The pattern across all three: *the guard ran, the
guard passed, and the guard checked nothing.* A green build is evidence only if
the check has been observed to go red.

---

## VEY-017 — Every standalone wallet shipped blank

**Severity:** High (the product did not function at all) ·
**Found:** increment 20, by a user opening the deployed page

### Failure
The wallet loaded a blank page. All three standalone files were affected.

### Root cause
The pages declare:

```
script-src 'self'
```

which permits scripts **fetched from this origin** and forbids **inline** ones.
The whole point of the standalone build is to inline the bundle — so the page's
own policy blocked its only script. The HTML rendered, the JavaScript never
ran, and the result was an empty page with no error a user would see.

### Why nothing caught it
Every check I had **read the file**:

- `assertSelfContained` — no external references ✓
- `assertPinnedConnectSrc` — no wildcard ✓
- `assertSignerIsOffline` — `connect-src 'none'` present ✓
- manual greps — CSP present, crypto inlined, no stray imports ✓

All correct, and all irrelevant. **A CSP violation is a runtime refusal by the
browser.** It is not visible in the bytes; the bytes are exactly what was
intended. I verified the file was correct and never verified that it worked.

### Fix
A **SHA-256 hash of each inline script**, computed from the final content and
inserted into `script-src`.

Not `'unsafe-inline'`, which would have fixed the blank page and destroyed the
protection: it permits *any* inline script, including an injected one. A hash
permits exactly this script and nothing else, so the policy still blocks
injection — which is the entire point of having it on a page holding keys. The
build refuses to emit a file using `'unsafe-inline'`.

### Regression test
`tests/unit/standalone-render.test.ts` — **executes** each page in jsdom and
asserts something rendered. Also asserts each inline script is hash-authorised,
that `'unsafe-inline'` is absent, and that the onboarding screen appears.

That test exists because it makes the one assertion the other seven could not:
*did it run?*

### Lesson
**Verifying an artifact is correct is not verifying it works.** Every static
check I wrote examined the output's *content*; the failure was in the output's
*behaviour under a policy the browser enforces*. Those are different questions,
and I had only been asking the first.

This is the same shape as VEY-008, where 55 API tests missed a CORS failure
because Node's `fetch` does not enforce CORS. Both times: a browser-enforced
policy, verified in an environment that does not enforce it.

The rule that would have caught both: **if a control is enforced by a runtime,
it must be tested in that runtime.** Reading the configuration proves you wrote
it, not that it permits what you need.

---

## VEY-018 — The documentation site's root 404'd

**Severity:** Low (availability) · **Found:** increment 20, same report

### Failure
The docs domain returned 404 at `/`.

### Root cause
`build-site.ts` emitted only a `docs/` directory. Reaching the introduction
depended on a `redirects` rule in `vercel.json` — which stops applying the
moment a dashboard setting overrides the file, leaving nothing at the root at
all.

Depending on host-specific configuration for "what is at `/`" is fragile: the
config lives outside the build, so the build can succeed while producing a site
that does not work.

### Fix
Emit a real `index.html` that redirects, plus a styled `404.html`. Both are
plain files, so they work on Vercel, Netlify, GitHub Pages, S3, nginx, and from
a local filesystem — depending on nothing but their own existence.

The build now **fails** if `index.html` or `docs/introduction.html` is missing,
rather than deploying a site whose root 404s.

### Lesson
**Build output should be complete on its own.** If a deployment needs
host-specific rules to be navigable, the build has produced a fragment and the
rest lives somewhere the build cannot verify.

---

## VEY-019 — The test for VEY-017 tested a stale artifact

**Severity:** Medium (a green suite over a broken build) ·
**Found:** increment 20, by a user running the suite after the VEY-017 fix

### Failure
```
AssertionError: expected 'default-src 'none'; script-src 'self'; …'
  to contain ''sha256-P2p3O/KEjp5wjHPragffqonihmg4…''
```

The build was fixed. The test failed anyway — and on a different machine it
would have *passed* while the fix was absent.

### Root cause
Two defects in one test, both mine.

**1. It rebuilt only when the output was missing.**

```ts
if (!existsSync(join(standalone, "veyra.html"))) {
  execSync("npx tsx scripts/build-standalone.ts", …);
}
```

So it tested whatever happened to be on disk. A `standalone/` left over from a
previous run was checked against the *current* expectations — reporting on a
build that no longer existed. Depending on which stale copy was present, the
same commit could pass or fail.

**2. The render assertions passed spuriously.**

jsdom does not provide `TextEncoder`, so the bundle threw immediately on load.
The assertion was `textContent.length > 100`, and the page's *static markup*
already exceeded that — so a page whose script had crashed on line one still
counted as "renders". The failure surfaced only in the one test that used an
empty `<div id="root">` and therefore had nothing static to fall back on.

### Fix
- **Always rebuild.** The output directory is removed and regenerated before
  every run. ~20 seconds, and the assertions now describe the code rather than
  the filesystem.
- **Supply the missing globals** (`TextEncoder`, `TextDecoder`, `crypto`) so
  the bundle can actually run.
- **Assert no script errors**, before asserting anything rendered. Errors
  first, because a page can look populated from static markup while its script
  has thrown — which is precisely how this passed.

### Lesson
Two, and the second is the sharper one.

**A test whose result depends on leftover artifacts is not testing the code.**
Caching build output in a test is an optimisation that trades correctness for
seconds.

**An assertion that a *page rendered* must exclude what was already there.**
`length > 100` measured the static HTML, not the script's output. The fix is to
start from an empty container, so everything asserted had to be produced by the
code under test — the same principle as VEY-001's backstop, where a filter
matching nothing passed a test that iterated it.

This is now the fourth finding in the family *the check ran, passed, and
verified nothing* (VEY-001, VEY-015, VEY-016, VEY-019). The recurring cause is
never the assertion being wrong — it is the assertion being satisfiable without
the property holding.

---

## VEY-020 — The stored `fetch` was called as a method

**Severity:** High (the deployed wallet could not sync at all) ·
**Found:** increment 21, by a user clicking Sync on the live site

### Failure
```
Chain: network error: Failed to execute 'fetch' on 'Window': Illegal invocation
```

Every Sync click failed, on every deployed copy, on both `veyra.html` and
`veyra-watch.html`. No balance could ever be loaded. 919 tests were green.

### Root cause
Both chain sources accept an injectable `fetchImpl` and default it to the global
`fetch`. The default was stored bare on the instance:

```ts
this.fetchImpl = options.fetchImpl ?? globalThis.fetch;   // ← here
...
const response = await this.fetchImpl(url, init);         // ← and here
```

`globalThis.fetch` is a *method of the global object*. `this.fetchImpl(...)` is
a method call, so `this` inside native `fetch` was the `EsploraChainSource`
rather than the `Window`. WebIDL brand-checks the receiver and rejects a foreign
one. `request()` then wrapped that `TypeError` into a `ChainError`, producing
the message above.

Neither line is wrong alone. The defect is the pair: storing a method
detached from its receiver, then re-attaching it to the wrong one.

### Why 919 tests missed it
Two independent reasons, and **both** had to be defeated for any test to catch
this:

**1. The broken branch was never executed.** Every Esplora and RPC test injects
a `fetchImpl`. The `?? globalThis.fetch` default — the only defective path —
had no test at all. The one place a real default was reachable,
`tests/integration/regtest.test.ts`, runs under Node.

**2. Node cannot observe the bug.** `vitest.config.ts` sets
`environment: "node"`, and undici's `fetch` performs no receiver brand check.
Even executing the default branch under Node passes with the defect present.

jsdom would not have helped either: jsdom 25 ships no `fetch` at all.

### Fix
Two halves, because each closes a different hole:

- **Bind the default** in the constructor —
  `globalThis.fetch.bind(globalThis)`, behind a `typeof` guard so a runtime with
  no `fetch` still yields the explanatory `ChainError` rather than a raw
  `TypeError` from `.bind`. An injected `fetchImpl` is a public option and is
  left exactly as the caller supplied it.
- **Call without a receiver** — `const doFetch = this.fetchImpl; await
  doFetch(...)`. WebIDL substitutes the relevant global when `this` is
  `undefined` and rejects only a foreign object, so this also protects a caller
  who injects a raw `window.fetch`.

Applied to `core/chain/esplora.ts` and `core/chain/bitcoinRpc.ts`. The RPC
source was latent rather than live — it is only constructed under Node today —
but it is the same defect and would have failed identically in a browser.

### Regression tests
`tests/unit/fetch-binding.test.ts`. The suite could not catch this by using the
runtime's `fetch`, so it **supplies the missing brand check itself**: a non-arrow
stand-in that throws `Illegal invocation` for any foreign receiver. Against the
unfixed code, 5 of its 10 assertions fail with the exact production string.

It covers the default path, the injected path, a receiver-recording spy, the
no-`fetch` runtime, and both chain sources — plus a source-tree guard asserting
`this.fetchImpl(` appears nowhere in `core/`, to catch the third copy somebody
adds later. Per VEY-016, that guard ships *alongside* the behavioural tests and
never instead of them, and asserts it scanned a plausible number of files so an
empty pass cannot be vacuous.

### Lesson
**A suite that runs in one runtime cannot verify behaviour in another. Supply
the missing check rather than assuming the runtime provides one.** The browser
enforced a rule Node does not, and no amount of Node testing was ever going to
find it — but a fifteen-line fake of that rule found it instantly.

The narrower lesson is worth stating too: **a defaulted dependency needs a test
of the default.** Dependency injection made every one of these tests easy to
write and, by making injection the habit, ensured the shipped configuration was
the only one never exercised.

---

## VEY-021 — Two tests that failed at random

**Severity:** Low (no wallet defect) but corrosive ·
**Found:** increment 21, while running the suite repeatedly during the UI rework

### Failure
Two tests in `tests/unit/browser-wallet.test.ts` failed intermittently on
unchanged code. One of them announced a seed leak that had not happened.

### Root cause
Both generated a fresh random mnemonic and then asserted a property that is
only *probably* true.

**1. `a restored phrase with a typo is REJECTED`**

```ts
const good = generateMnemonic(12).split(" ");
good[0] = "zoo";
expect(validateMnemonic(good.join(" "))).toBe(false);
```

A 12-word phrase carries 128 bits of entropy and a **4-bit** checksum.
Substituting a random word changes the entropy, and the recomputed checksum
matches by chance **one time in sixteen**. The test failed about 6% of runs.

**2. `the stored keystore contains no trace of the phrase`**

```ts
for (const word of mnemonic.split(" ")) expect(stored).not.toContain(word);
```

`stored` is JSON containing base64. Base64's alphabet includes every lowercase
letter, and BIP-39 has three-letter words — `ice`, `add`, `art`, `age`, `arm`,
`ask`. Across a few hundred random base64 characters one of them appears often
enough to fail regularly. The failure message claimed the mnemonic was stored in
the clear.

### Fix
- **The typo test uses a fixed vector.** The standard all-`abandon` phrase with a
  known-bad substitution. Deterministic, and it tests the same property.
- **A second test states the real bound honestly.** The 12-word checksum catches
  about 15 of every 16 single-word typos — *not* all of them. That is now
  written down rather than left as folklore, and it is the strongest concrete
  argument for a 24-word phrase, whose 8-bit checksum does roughly 16× better.
- **The leak test reads the decoded bytes**, not the base64 text. In the
  underlying bytes a three-character coincidence has probability 2⁻²⁴ per
  position, so the check is exact for the property it claims. The encoded form
  is still searched for words of six characters or more, which keeps the test
  able to catch a plaintext field added to the JSON later.

### Lesson
**A test that fails one run in sixteen does not teach people to read it — it
teaches them to re-run the suite.** After that, a real failure in the same file
is indistinguishable from the usual noise, and the most alarming possible
message ("the seed is stored in the clear") is the one people learn to ignore.

The narrower rule: **when a test generates random input, the assertion has to
hold for *all* of that input, not merely most of it.** Both of these asserted a
property with a known failure rate against a fresh sample each run. Where the
underlying property really is probabilistic, say so and test the bound — which
is what the replacement does.

---

## Findings that were NOT defects

Recorded because their absence is itself informative.

### The isolation and entropy guards work
Once VEY-001 was fixed, both source-tree guards have held. No production module
imports `core/crypto/reference/`, and `Math.random()` appears nowhere in
`core/` — including in `coinSelection.ts`, where a shuffle would have been the
natural place to reach for it. The CSPRNG is used there instead, specifically
so no exception exists to spread.

### BIP-143 matched on the first attempt
The sighash implementation reproduced the published digest `c37af311…` without
iteration. Given the number of fields, orderings, and endianness choices
involved, this was more luck than it should have been, and is exactly why the
vector was run before anything was built on top of it.

### The value-conservation property has never failed
Across roughly 6,000 randomised coin-selection scenarios and 200 randomised
sends, `inputs = amount + fee + change` has held without exception.

---

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
