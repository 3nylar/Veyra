# Security Policy

Veyra is an educational security project. Its purpose is to be inspected,
questioned, and broken — so a vulnerability report is the most useful thing you
can send.

---

## Current status

**The security challenge is funded.** Its terms are final and published
in [the README](README.md#the-security-challenge); the address and encrypted
keystore appear there at funding, and the challenge opens the moment they do.
Until then there is nothing to attack for reward — only a codebase to improve.

**Nothing here has handled real funds** on any network.

A transaction Veyra built and signed **has** been accepted by Bitcoin Core, on
regtest, on 2026-08-20, computing the same txid — so the serialisation is
byte-exact and the signing path satisfies real consensus rules. Reproduce it
with `npm run test:regtest`. (An earlier version of this file said no such
transaction existed. That was stale, and it had contradicted the README for
several increments.)

### Two things are deliberately separate

**The challenge** is a withdrawal. If you can spend the coins from the published
keystore, they are yours — no report, no permission, nothing to disclose.

**A vulnerability report** is everything below. It covers the whole codebase,
including flaws that have nothing to do with the challenge wallet, and it is
the more useful of the two to the project.

---

## Reporting

Please report privately first. Open a **GitHub Security Advisory** on the
repository (Security → Report a vulnerability), which keeps the report private
until a fix exists.

Please do **not** open a public issue for anything that could lead to loss of
funds.

### What helps

- A description of the vulnerability and the component affected
- Reproduction steps, ideally as a failing test
- The technical mechanism — *why* it works, not only *that* it does
- Impact: what an attacker gains
- A proof of concept, **where it is safe to share one**

A failing test is the single most useful artefact. It becomes the regression
test under §31, and it removes any ambiguity about whether the issue is real.

### What is not required

You are **not** required to publicly disclose before a fix exists, and you are
not required to wait indefinitely either. If a report goes unanswered for 90
days, publishing is reasonable and expected.

---

## Scope

### In scope

- Cryptographic implementation weaknesses
- Key generation, derivation, or entropy weaknesses
- Private key or seed extraction by any route
- Transaction signing or construction vulnerabilities
- Wallet authorization bypass
- API vulnerabilities permitting unauthorized spending
- Wallet logic errors that lose or misdirect funds
- Anything that compromises control of funds

Also welcome, though lower severity: privacy weaknesses, denial of service
against the wallet itself, and **defects that silently disable a security
control**. That last category has already produced real findings — see
[docs/ATTACKS.md](docs/ATTACKS.md), VEY-001.

### Out of scope

- Social engineering or phishing
- Physical attacks or coercion
- Compromise of a user's machine or operating system
- Attacks on unrelated infrastructure or third-party services
- Denial of service that does not compromise funds
- Missing TLS, missing HSM support, and the other limitations already
  documented in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) §7 — these are
  known and recorded, so reporting them adds nothing

Please read the threat model before reporting. If a weakness is already listed
there as unresolved, a report explaining how to *exploit* it concretely is
valuable; a report merely restating it is not.

---

## What happens to a report

Following §31, every accepted finding gets:

1. A failing test reproducing it
2. An entry in [docs/ATTACKS.md](docs/ATTACKS.md) with root cause and lesson
3. A fix
4. The test made to pass, and kept permanently

Reporters are credited unless they prefer otherwise.

---

## Safe harbour

Testing against your own regtest or testnet instance is unambiguously
encouraged. Please do not attack infrastructure you do not own, and do not
access data that is not yours.
