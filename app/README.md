# Veyra — the browser pages

Three self-contained HTML files. Each one is a complete wallet interface with
its bundle inlined, so it can be served from anywhere, opened from a USB stick,
or checked against a published hash before you trust it.

| File | Holds keys? | Reaches the network? | For |
| --- | --- | --- | --- |
| `wallet.html` | **Yes** — encrypted in `localStorage` | Yes — a pinned allowlist | Everyday use |
| `signer.html` | **Yes** — your seed, in memory | **No.** `connect-src 'none'` | Air-gapped signing |
| `watch.html` | No — an xpub only | Yes | Watching, and building unsigned payments |

`wallet.html` is the product. `npm run standalone` builds all three into
`standalone/`, and `npm run build:public` puts `veyra.html` at the site root.

---

## Running it

```powershell
npm run app          # http://127.0.0.1:5173/wallet.html
```

The dev server binds to `127.0.0.1` deliberately. These pages hold key material,
and exposing them on a LAN should never be something you get by accident.

There is no API to start. `wallet.html` imports `core/` directly and talks to an
Esplora server itself — there is no server in the middle holding anything.

> The Node API in `api/` still exists and is still documented. It is a separate,
> localhost-only tool for scripting a wallet over HTTP, not a backend for these
> pages.

---

## What secures `wallet.html`

This page holds keys **and** reaches the network — the combination the
air-gapped `signer.html` + `watch.html` split deliberately avoids. That is a
real trade-off, made because a wallet requiring a second machine is a wallet
nobody uses. Four things make it defensible:

1. **A pinned `connect-src`.** The CSP names the exact endpoints the page may
   contact — not `https:`, not a wildcard. Injected script cannot POST a seed
   anywhere, because the browser refuses the request. This is the single most
   important line in the file, and `scripts/build-standalone.ts` fails the build
   if it is ever widened to a wildcard.
2. **No third-party code.** No CDN, no analytics, no hosted fonts, no tag
   manager. Every byte ships in one file, so there is no upstream to compromise.
3. **Encrypted at rest.** scrypt (N=2¹⁷) + AES-256-GCM. Reading `localStorage`
   without the passphrase yields nothing.
4. **Auto-lock.** The decrypted seed is dropped after ten minutes of inactivity.

**What it cannot do:** protect against a compromised browser, a malicious
extension with page access, or malware reading process memory. A hardware wallet
keeps the key in a chip that never exposes it; a browser cannot. Anyone holding
more than they would shrug at losing should use `signer.html` on an offline
machine.

---

## How the code is arranged

No framework. Each page is plain TypeScript that renders by assigning
`innerHTML`, with one delegated click listener dispatching on `data-act` and
`data-nav`. That is a deliberate choice for a shipped artifact under a strict
CSP: a framework would add bytes, a supply chain, and a runtime that four
screens do not need.

> A React interface lived here until increment 21. It talked to the localhost
> API, was never deployed, and had drifted into a second design system whose
> stylesheet had no effect on the shipped page. It was removed rather than
> maintained.

**The rule that governs every feature:** a render destroys the DOM. Anything
that must survive a sync, an auto-lock tick, or a navigation lives in module
state or in `prefs` — never in an element. The flip card and the activity paging
are both built that way.

| File | What it is |
| --- | --- |
| `src/wallet-app.ts` | The wallet: onboarding, unlock, balance, activity, receive, send, settings |
| `src/watch.ts` | Watch-only: xpub in, unsigned PSBT out, signed hex broadcast |
| `src/signer.ts` | Offline signer: seed in memory, zero network calls |
| `src/chain-cache.ts` | Drops a sync from ~126 requests to ~47 by never asking a question twice |
| `src/price.ts` | The USD figure — live or absent, never remembered |

---

## Design

**Palette.** Space Black `#0A0C0E`, surface `#12161A`, muted graphite, off-white
`#E9EEF1`, teal `#14B8A6` as an accent — never as the interface. Colour is
semantic only: teal is a primary action, red is danger, amber is a warning,
graphite is information. Nothing is coloured decoratively, and variants live on
data attributes rather than modifier classes.

**Type.** IBM Plex Mono for every value that is *data* — addresses, amounts,
txids, paths — and the system sans for everything that is interface. The
typeface tells you whether you are reading something the wallet computed or
something it is saying. Tabular figures throughout, so a changed digit is
visible rather than merely different.

**The signature element.** A Bech32 address has three parts, and every wallet
renders them as one undifferentiated string:

```
bc1q   cl3pgzqcez3wwyp8n4am48qt55y99n6l   k439d8
────   ───────────────────────────────   ──────
HRP    witness program                    BCH checksum
```

Those last six characters are an error-detecting code with a *proven* bound: any
four or fewer mistyped characters are guaranteed to be caught. It is the single
most user-protective property of the format and it is invisible everywhere else.
Veyra underlines it and says what it does.

---

## Screens

**Wallet** — a flip card. One face shows the wallet's name, network and
fingerprint; the other shows the balance, its USD value, and the breakdown into
total, unconfirmed and coin count. A balance is the one number on screen that is
nobody else's business, and wallets get opened on trains.

The hidden state persists across reloads and is remembered per browser. When it
is on, **every amount in the activity list is masked too** — a card that
conceals the balance while the rows beneath it show `+0.00310000` has hidden
nothing, and is worse than showing the balance outright because the user
believes it worked.

**Activity** — direction as a word *and* a sign, so meaning survives greyscale;
the amount with its fiat value; a relative and absolute date; confirmation
state; the fee, shown only for sends. The txid links to the block explorer
belonging to *the chain source already in use* — deriving the link rather than
hardcoding a favourite means clicking it tells nobody anything they did not
already know.

A failed history lookup is shown as a failure, never as "no transactions yet".
Those are different facts, and only one of them is alarming.

**Receive** — a QR code, the address with its checksum marked, and the network
stated in words. "tb1q…" means testnet to someone who already knows; the person
who doesn't is exactly the one who needs telling.

**Send** — Compose → Review → Broadcast. The review describes a transaction that
is *already built and signed*; confirming broadcasts exactly those bytes. There
is no field through which the broadcast could differ from what was displayed.

**Settings** — display preferences, network, the security facts (with no
"security score", which implies a measurement nobody performed), and a privacy
statement naming every server this page talks to and what each one learns.

---

## Amounts and fiat

Bitcoin amounts are `bigint` satoshis end to end. `parseBtc` does string and
BigInt arithmetic and never `parseFloat(x) * 1e8` — see `docs/ATTACKS.md`
VEY-011, where exactly that produced a doubled fee.

The USD figure is the one place a float touches an amount, and it gets exactly
one float operation — converting the rate to integer cents — after which
everything is BigInt again. The rate is fetched from mempool.space, which is
already in the pinned `connect-src`, so no policy change was needed to add it.

**It is never remembered.** If the price request fails, the interface shows an
em dash and says so. A stale dollar figure tells the user something false about
how much money they have, and the moment it matters is the moment the network
was down.

Non-mainnet networks show no price and make no request. Signet and testnet coins
have no market value, so quoting one would be a lie.

---

## Accessibility

Visible keyboard focus everywhere — a wallet is the wrong place to remove focus
rings for tidiness. The flip card is a real `<button>`, so it is keyboard
operable without any extra code, and the hidden face is `visibility: hidden`
rather than merely rotated away, so it is neither announced by a screen reader
nor found by Ctrl-F.

`prefers-reduced-motion` is respected, and the flip still *works* under it — it
simply happens instantly. Note the trap that cost a debugging session: the
media query zeroes transition *duration* but not *delay*, and the face swap is
delay-driven, so the delay has to be zeroed explicitly.

Contrast meets WCAG AA against Space Black.

---

## Responsive

Mobile is not the desktop layout shrunk. Navigation moves to a bottom bar within
thumb reach, the priority order is balance, send, receive, activity, and
safe-area insets are respected.

---

## Dependencies

| Package | Why |
| --- | --- |
| `qrcode` | A QR code is a Reed–Solomon-coded 2D symbol. Hand-rolling it would risk producing an address that scans as something else. It only ever encodes a public address, never key material. |
| `vite` | Dev server and bundler; already present via vitest |

Everything else is `core/`, which depends only on `@noble/curves` and
`@noble/hashes`.
