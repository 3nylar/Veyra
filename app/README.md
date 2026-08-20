# Veyra — Interface

A calm, dark wallet interface. It holds no keys and performs no cryptography.

---

## Running it

Two processes. The API holds the wallet; the UI talks to it.

```powershell
# terminal 1 — the wallet
$env:VEYRA_NETWORK = "regtest"
npm run api          # prints an API token once

# terminal 2 — the interface
npm run app          # http://127.0.0.1:5173
```

Paste the token into the connect screen. It is kept in memory for that tab
only — never `localStorage`, which would leave a credential readable by any
injected script and outliving your intent to be connected.

---

## Why this is not hosted

Only the documentation is deployed publicly. The interface must run on your own
machine, for a reason that is not merely preference:

- It talks to an API on `127.0.0.1`, which exists only on your machine.
- A page served over **HTTPS cannot call `http://127.0.0.1`** — browsers block
  it as mixed content. A hosted wallet UI would fail for every visitor, and the
  obvious "fix" would be pointing it at a hosted API, which means holding
  strangers' private keys.

Self-custodial software is distributed as source you run yourself.

## What the UI cannot do

It cannot sign, cannot derive a key, and cannot see the mnemonic. A browser is
a hostile place for key material, and an interface that cannot sign cannot leak
a signing key. Every value it shows came from the API.

---

## Design

**Palette (§27).** Space Black `#0A0C0E`, surface `#12161A`, muted graphite,
off-white `#E9EEF1`, with teal `#14B8A6` as an accent — never the interface.
Colour is semantic only: teal is a primary action, red is danger, amber is a
warning, graphite is information. Nothing is coloured decoratively.

**Type.** IBM Plex Sans for interface, IBM Plex Mono for every value that is
*data* — addresses, amounts, txids, paths. The typeface tells you whether
you are reading something the wallet computed or something it is saying.
Tabular figures throughout, so a changed digit is visible rather than merely
different.

**The signature element.** A Bech32 address has three parts, and every wallet
renders them as one undifferentiated string:

```
bcrt1  qcl3pgzqcez3wwyp8n4am48qt55y99n6l  k439d8
─────  ────────────────────────────────  ──────
HRP    witness program                    BCH checksum
```

Those last six characters are an error-detecting code with a *proven* bound:
any four or fewer mistyped characters are guaranteed to be caught. It is the
single most user-protective property of the format and it is invisible
everywhere. Veyra underlines it and says what it does.

---

## Screens

**Wallet (§22)** — spendable balance, broken into total, unconfirmed,
unavailable, and coin count. A single number would be a claim the user
discovers is false when a send fails.

**Receive (§23)** — QR, address with its checksum shown, derivation path, and
the network stated in words. "bcrt1q…" means regtest to someone who already
knows; the person who doesn't is exactly the one who needs telling.

**Send (§24)** — Compose → Review → Broadcast → Result. The review is not a
summary the UI composes from what was typed; it is the *server's* account of a
transaction it has already built and signed. A UI-composed summary shows what
you asked for. A server-authored one shows what will happen — and the
difference is where a bug would hide.

Confirming sends only the prepared transaction's id. There is no field through
which the broadcast could differ from what was displayed.

**Security (§26)** — verifiable facts, and no score. "92% secure" implies a
measurement nobody performed, and its real effect is to make people stop
reading.

---

## Responsive (§28)

Mobile is not the desktop layout shrunk. Navigation moves to a bottom bar
within thumb reach, and the priority order is balance, send, receive, activity.
Safe-area insets are respected.

---

## Accessibility

Visible keyboard focus everywhere — a wallet is the wrong place to remove focus
rings for tidiness. `prefers-reduced-motion` respected. Semantic landmarks,
`aria-current` on navigation and the send steps, and `role="alert"` on errors
that matter. Contrast meets WCAG AA against Space Black.

---

## Dependencies

| Package | Why |
| --- | --- |
| `react`, `react-dom` | Component model for a multi-screen flow with real state |
| `qrcode` | A QR code is a Reed–Solomon-coded 2D symbol. Hand-rolling it would risk an address that scans as something else |
| `vite` | Dev server and bundler; already present via vitest |

There is deliberately **no** `@vitejs/plugin-react`. It exists for Fast
Refresh, and it pinned a Vite major that conflicted with vitest's. Vite
compiles JSX through esbuild natively, so the plugin bought a development
convenience at the cost of a dependency conflict in a tree that holds wallet
code. §46 asks for a reason for every dependency; "hot reload" did not survive
the question.
