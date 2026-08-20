# Veyra — Threat Model

> **Scope.** This describes what Veyra defends against, what it does not, and
> what it assumes. It is written to be falsifiable: every claim below should be
> checkable against the code, and anything that cannot be checked is marked as
> an assumption rather than a guarantee.

---

## 1. What is being protected

In priority order:

1. **Private key material** — the seed, the master key, and every derived key.
   Compromise is total and irreversible.
2. **Transaction integrity** — that a broadcast transaction sends exactly what
   the user approved, to exactly whom they approved.
3. **Availability of funds** — that the user can spend what they own.
4. **Privacy** — that an observer cannot trivially link addresses to one
   another or to a person.

Note the ordering. Veyra will refuse to operate rather than risk (1) or (2),
and accepts degraded (3) and (4) to protect them. A refused transaction is
recoverable; a stolen one is not.

---

## 2. Assumptions

These are the load-bearing beliefs. If any is false, the guarantees below fail.

| # | Assumption | If false |
| --- | --- | --- |
| A1 | The host OS CSPRNG is properly seeded and unbroken | Total compromise, silently — see §1 of CRYPTOGRAPHY.md |
| A2 | ECDLP on secp256k1 is computationally infeasible | All keys derivable from public data |
| A3 | SHA-256 and RIPEMD-160 are preimage- and collision-resistant | Addresses forgeable, signatures replayable |
| A4 | `@noble/curves` and `@noble/hashes` are correct and side-channel resistant | Keys extractable via timing; wrong signatures |
| A5 | The host is not compromised | Keys readable from process memory |
| A6 | The Node.js runtime is not compromised | Everything |

**A1 is the only non-mathematical assumption and the most load-bearing.** A2
is *conjectured*, not proven, and falls entirely to a sufficiently large
quantum computer running Shor's algorithm.

**A5 deserves emphasis.** Veyra holds keys in process memory with no HSM, no
enclave, and no at-rest encryption. Against a local attacker with the ability
to read process memory, there is no defence — only the reduced window that
`wipe()` provides, which is best-effort in a garbage-collected runtime.

---

## 3. Attackers

### 3.1 External attacker

**Can:**
- Read all source code (the repository is public by design)
- Send arbitrary input to any exposed API endpoint
- Construct arbitrary transactions and offer them to the wallet
- Observe all public blockchain data
- Attempt authentication with arbitrary credentials

**Cannot:**
- Read process memory
- Read the seed, mnemonic, or any private key
- Observe the CSPRNG output

**Defences:** Bearer authentication with timing-safe comparison; strict input
validation with unknown-field rejection; body-size limits enforced during
streaming; rate limiting applied before authentication; identical responses for
all authentication failures and all 404s; no endpoint that can reach key
material.

**Residual risk:** Rate limiting is in-memory and per-process, so a distributed
attacker or a restart resets it. Denial of service by resource exhaustion at
the network layer is not addressed and requires a reverse proxy.

---

### 3.2 Malicious recipient

**Can:**
- Supply a malformed, wrong-network, or hostile destination address
- Supply an address that is valid but unspendable (a burn)
- Refuse to acknowledge receipt

**Cannot:**
- Cause more to be sent than the user approved
- Alter the fee
- Learn the sender's other addresses from the transaction alone (though change
  detection weakens this — see §3.5)

**Defences:** Bech32 checksums catch corrupted addresses with a proven bound;
the HRP is inside the checksum, so a mainnet address fails outright when parsed
as testnet; dust amounts are refused; the amount is fixed at prepare time and
the confirming call cannot alter it.

**Residual risk:** Veyra cannot distinguish a legitimate address from a
hostile-but-valid one. Sending to the wrong recipient is unrecoverable, and no
software can prevent it. Address verification is the user's responsibility.

---

### 3.3 Network attacker

Includes a malicious chain source, a compromised ISP, and anyone on the path.

**Can:**
- Read all API traffic (no TLS is implemented)
- Modify chain source responses
- Report false balances and confirmations
- Withhold or drop broadcasts
- Replay captured requests

**Cannot:**
- **Steal funds by understating an input's value.** BIP-143 puts the amount
  inside the signature preimage, so a lie produces a signature that does not
  verify. This is closed by the protocol, not by Veyra.
- Forge a signature
- Redirect a payment — the destination is committed to by the signature

**Defences:** Broadcast responses are checked against the locally-computed
txid, and a mismatch is treated as failure with the coins left unspent;
prepared-transaction ids are consumed before the network call so a retry cannot
double-broadcast; every response field is validated before use; amounts are
parsed as BigInt with unsafe integers rejected.

**Residual risk — significant:**
- **No TLS.** API traffic is readable and modifiable on the wire. Anything
  beyond localhost requires a reverse proxy.
- **A chain source that omits a UTXO cannot be detected.** The wallet looks
  poorer and produces an unexplained "insufficient funds". This is inherent to
  not running a full node.
- **False confirmation counts cannot be detected** without validating headers,
  which Veyra does not do.

---

### 3.4 Local attacker

**Can:**
- Read files the wallet process can read
- Read process memory, core dumps, and swap
- Read logs and terminal scrollback
- Read shell history

**Cannot:**
- Be defended against, once they have this access

**Defences (mitigation only, not prevention):** `PrivateKey` redacts on
`toString`, `JSON.stringify`, `util.inspect` (even with `showHidden`), and
reflection — so an accidental log line does not become a key disclosure; error
messages never interpolate secret material; `wipe()` zeroes buffers after use;
`.gitignore` excludes `.env`, `*.seed`, `*.mnemonic`, and similar.

**Residual risk:** `wipe()` is **best-effort**. In a garbage-collected, JIT'd
runtime the buffer may have been copied during GC compaction or paged to swap.
It shrinks the window during which a heap dump contains live key material; it
does not eliminate it. Claiming otherwise would be security theatre.

---

### 3.5 Passive observer (privacy)

**Can:**
- Read the entire blockchain
- Apply the **common input ownership heuristic**: inputs spent together are
  almost certainly one owner
- Apply **change detection**: identify which output returns to the sender
- If they operate the chain source: learn every address in the wallet, the
  balance, the full history, and the IP address — in a single sync

**Defences:** Fresh change addresses on every transaction; branch-and-bound
coin selection that prefers changeless transactions, which destroys the
change-detection signal; random coin selection rather than a deterministic
strategy that would fingerprint the wallet software; no chain source configured
by default; a privacy warning surfaced for any non-local source.

**Residual risk — this is the weakest area:**
- **A light wallet query leaks the whole wallet to the server.** No
  cryptography prevents this; it is inherent to asking someone else about your
  coins. Only running your own node, or using compact block filters
  (BIP-157/158), avoids it.
- **The common input ownership heuristic cannot be defeated** by a single-party
  wallet. It requires CoinJoin or PayJoin, neither implemented.
- **No Tor support**, so the IP linkage is unmitigated.

---

## 4. Out of scope

Explicitly not defended against, per §39:

- Social engineering and phishing of the user or the creator
- Physical theft or coercion of the user
- Compromise of the user's operating system or hardware
- Malicious dependencies beyond auditing and lockfile pinning
- Supply-chain compromise of Node.js itself
- Denial of service that does not compromise funds
- Attacks on unrelated infrastructure

---

## 5. Trust boundaries

```
   ┌───────────────────────────────────────────────┐
   │  UNTRUSTED                                    │
   │    external clients, chain sources,           │
   │    the network, the blockchain                │
   └────────────────────┬──────────────────────────┘
                        │  validated at every crossing
   ┌────────────────────▼──────────────────────────┐
   │  api/        no key material reachable        │
   │              validation, auth, rate limits    │
   └────────────────────┬──────────────────────────┘
                        │
   ┌────────────────────▼──────────────────────────┐
   │  core/wallet    ← THE SECRECY BOUNDARY        │
   │                 holds the seed and keys       │
   │                 no export method exists       │
   └────────────────────┬──────────────────────────┘
                        │
   ┌────────────────────▼──────────────────────────┐
   │  core/crypto, keys, signing                   │
   │  audited primitives; reference code isolated  │
   └───────────────────────────────────────────────┘
```

Two boundaries are enforced structurally rather than by convention, and both
have tests that fail the build if violated:

1. **No production module may import `core/crypto/reference/`.** The
   educational implementations are timing-unsafe by construction.
2. **No `Math.random()` anywhere in `core/`.** A weak-entropy wallet works
   perfectly and is worthless, so only a source scan can catch it.

---

## 6. What has NOT been verified

Stated here because §47 requires it and because the tick-marks elsewhere could
imply more than is true:

- **The Esplora client has never spoken to a live server.** It is tested
  against a controlled fake. (The Bitcoin Core RPC client *has* been verified
  live — see below.)
- **No code here has handled real funds** on any network.
- **Mainnet has never been exercised end to end.** Only regtest.
- **No independent security review has been performed.**
- **No formal cryptographic audit** of the composition of primitives.
- **No side-channel analysis.** We rely on `@noble`'s constant-time claims.

### What HAS been verified against consensus

On **2026-08-20**, all 10 regtest integration tests passed against Bitcoin Core
v29. Core accepted a Veyra-built transaction, computed an identical txid
(proving byte-exact serialisation), rejected a transaction whose recipient was
altered after signing, and confirmed that change is spendable and a restored
mnemonic recovers real funds.

This closes the largest previously-open assumption: that the signing path
satisfied the specification *as read* but had never been checked against the
implementation that defines it.

---

## 7. Known unresolved weaknesses

| Weakness | Severity | Status |
| --- | --- | --- |
| No TLS on the API | High for non-local use | Requires a reverse proxy; not implemented |
| Keys in process memory | High | Inherent to the design; no HSM support |
| Rate limiter is per-process and fixed-window | Medium | Needs a shared store for real deployment |
| `scantxoutset` misses spent-address history | Medium | Gap-limit scan may stop early against a node |
| No CoinJoin/PayJoin | Medium (privacy) | Not planned for Phase 1 |
| No Tor support | Medium (privacy) | Not implemented |
| Esplora client unverified against a live server | Medium | Use the Bitcoin Core RPC source, which is verified |
| BIP-39 uses 2048 PBKDF2 rounds | Low | Fixed by the standard; cannot change without breaking compatibility |
| Fee estimates are static placeholders | Low | Needs live mempool data |
