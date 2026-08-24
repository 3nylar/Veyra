# Veyra — Standalone Client-Side Wallet

Two self-contained HTML files. No server, no build step to run them, no
external requests. Download once, verify the hash, keep them forever.

```powershell
npm run standalone
```

Output lands in `standalone/`:

| File | Holds keys | Network access |
| --- | --- | --- |
| `veyra.html` | **Yes — your seed** | Pinned allowlist |
| `veyra-sign.html` | **Yes — your seed** | **None.** `connect-src 'none'` |
| `veyra-watch.html` | No | Yes — the Esplora you name |
| `SHA256SUMS` | — | — |
| `VERIFY.md` | — | — |

---

## Which file do I give people?

**`veyra.html`** — for almost everyone. One file, open it, use it. Keys are
generated in the browser, encrypted with a passphrase, and stored locally.
There is no signup and no server holding funds.

**`veyra-sign.html` + `veyra-watch.html`** — for someone holding an amount they
would mind losing. Splits keys and network access across two machines. More
secure, more friction.

Ship the first. Mention the second exists.

---

## What secures the single-page wallet

It holds keys **and** reaches the network — the combination the two-file setup
deliberately avoids. That trade-off is made because a wallet requiring a second
machine is a wallet nobody uses. Four things make it defensible:

### 1. A pinned `connect-src` — the important one

```
connect-src https://blockstream.info https://mempool.space
            http://localhost:3002 http://127.0.0.1:3002;
```

The exact endpoints this page may contact. **Not** `https:`, not a wildcard.

Injected script cannot POST your seed to an attacker's server — the browser
refuses the request before it leaves. An attacker would have to exfiltrate
through Blockstream or mempool.space, who are not helping them.

The build **refuses to emit the file** if this becomes a wildcard. That check
was itself broken for a while, matching its own explanatory comment instead of
the directive — see [ATTACKS.md](ATTACKS.md) VEY-016.

Adding a chain endpoint means editing that line and rebuilding. Each origin
added is one more place data could theoretically be smuggled to.

### 2. No third-party code

No CDN, no analytics, no fonts, no tag manager. Every byte ships in one file,
so there is no upstream to compromise.

### 3. Encrypted at rest

The seed in `localStorage` is scrypt (N=2¹⁷) + AES-256-GCM. localStorage is
readable by any script on the origin — acceptable **only** because what is
there is ciphertext.

### 4. Auto-lock after 10 minutes

The decrypted seed is dropped. This shortens the window in which a memory read
succeeds; it does not prevent one.

### What it cannot do

A compromised browser, a malicious extension with page access, or malware
reading process memory all defeat this. A hardware wallet keeps the key in a
chip that never exposes it; a browser cannot. That is why the two-file path
still exists.

---

## Why the OTHER two are separate files

This is the central design decision, and it is not caution — it is the only
arrangement in which either guarantee is real.

A page that **connects to the chain** must be permitted to make network
requests. A page that **holds your seed** must be forbidden from making them.

If one page did both, its Content-Security-Policy would have to allow network
access — and a page that can reach Esplora can reach an attacker's server. The
exfiltration guarantee would be gone. There would be nothing stopping injected
code from POSTing your seed anywhere.

So: the signer is forbidden from all network access, and holds keys. The watch
page is permitted network access, and holds none.

---

## Why a single file is the tamper-resistant shape

The realistic attack on a browser wallet is not the cryptography. It is the
**delivery** — whoever serves the page can serve a different page. A hosting
compromise, a hijacked domain, a malicious CDN, or a coerced operator all
produce the same outcome: a page that looks identical and steals your seed.

Nothing *inside* the page defends against that, because the attacker controls
the page.

The defence is to stop fetching it. A file with no external references can be
downloaded once, checked against a published hash, and opened from `file://`
forever after. The attack then requires modifying a file already on your disk —
a far higher bar, and one you can detect by re-checking the hash.

The build **asserts** this rather than assuming it: it fails on any external
`<script>`, `<link>`, CSS `@import`, source map, or unresolved JavaScript
import. That last check exists because its absence produced a 15 KB "wallet"
that would have loaded blank — see [ATTACKS.md](ATTACKS.md) VEY-015.

---

## Verify before opening

**Windows**

```powershell
Get-FileHash standalone\veyra-sign.html -Algorithm SHA256 | Format-List
```

**macOS / Linux**

```bash
cd standalone && sha256sum -c SHA256SUMS
```

If a hash does not match, do not open the file.

---

## Using it

### One-time setup

1. Open `veyra-sign.html` **on a machine with no network**. An old laptop with
   the Wi-Fi disabled is enough.
2. Create or paste a seed. Encrypt it with a passphrase and save the keystore.
3. Copy the account xpub it shows to your online machine.

### Receiving

Open `veyra-watch.html`, paste the xpub, choose a network and an Esplora
endpoint, and press **Load wallet**. Addresses and balances appear. This page
cannot spend.

### Sending

1. **Watch page** — enter recipient, amount, fee rate. Press **Build PSBT**.
2. Copy the PSBT to the offline machine.
3. **Signer** — unlock the seed, review the amounts and recipient, sign.
4. Copy the signed hex back.
5. **Watch page** — paste it and press **Broadcast**.

At no point does a machine hold both your seed and a network connection.

---

## What the signer can verify without trusting the watch page

The PSBT carries `witness_utxo` for every input. BIP-143 puts the input value
**inside the signature preimage**, so a watch page that lied about an amount
produces a signature that does not verify. The signer is not trusting the
builder on the number that matters most.

It also checks that the key it derives at the PSBT's stated path matches the
public key the PSBT names. A mismatch means the input is not yours.

**What it cannot verify: the recipient.** A compromised watch page could
substitute a destination address. Read the address on the signer screen and
confirm it out of band. That is the one check no cryptography performs for you.

---

## Honest limits

A browser is not a hardware wallet:

- **No memory protection.** The seed is in the heap; anything that can read the
  process reads it.
- **No secure element.** A hardware wallet keeps the key in a chip that never
  exposes it. A browser cannot.
- **Extensions** can read page content on many browsers.
- **A compromised browser or OS** defeats everything above.

The CSP removes the *exfiltration channel*, which is the most likely attack by
a wide margin. An air-gapped machine removes most of the rest. Neither turns a
browser into a secure enclave.

**And the largest limit is not technical:** this code has never been
independently reviewed. The same person wrote the implementation and its tests.
892 tests do not fix that — it is a structural gap, not a coverage gap.

Use signet or testnet. Use mainnet only with an amount you would shrug at
losing, and only after someone else has read the code.

---

## Privacy

A public Esplora learns every address in your wallet, that they belong to one
wallet, your balance, your full history, and your IP — in a single session. No
cryptography prevents this; it is inherent to asking someone else about your
coins.

Running your own Esplora or Bitcoin Core removes it entirely. The watch page
says which situation you are in when you connect.
