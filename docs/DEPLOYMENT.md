# Veyra — Deployment

> **The rule.** Never host a process that holds a seed. A hosted signing wallet
> is a custodial service whether or not anyone calls it that: compromise of the
> host is total loss for every user on it.
>
> Veyra deploys as a **watch-only** service. It holds an account xpub, shows
> balances, and builds unsigned PSBTs. Signing happens where your seed lives.

---

## The split

```
   HOSTED (this)                        LOCAL (your machine)
   ─────────────                        ────────────────────
   derive addresses
   track balances
   select coins
   build unsigned PSBT   ── PSBT ──►
                                        open it, verify the amounts
                                        sign with your seed
                          ◄── hex ──
   broadcast
```

The PSBT carries `witness_utxo` for every input, so the local signer verifies
the amount it commits to **without trusting the server**. BIP-143 puts the
input value inside the signature preimage — a server lying about it produces a
signature that does not verify. The signer is not trusting the host on the
number that matters most.

The entrypoint **refuses to start** if `VEYRA_WATCH_ONLY` and `VEYRA_MNEMONIC`
are both set. Not a warning — a hard failure. That combination happens by
accident, through a copied `.env` or a leftover variable, and it is exactly the
mistake that turns a safe deployment into a custodial one.

---

## ⚠️ What a watch-only host still learns

Being unable to steal is **not** the same as being harmless.

A hosted watch-only server sees every address, every balance, and every
transaction in the account, linked to whatever IP connects to it. That is the
complete financial history of the wallet.

Run your own instance and this costs nothing. Use someone else's and you have
handed them exactly what a third-party Esplora would get. The `/wallet/security`
endpoint says so in its warnings, and so does this page, because it is the part
most likely to be skipped.

---

## 1. Get your account xpub

On your local machine, never on the server:

```powershell
npm run xpub          # prints the account-level xpub for your network
```

The xpub must be at the **account level** (`m/84'/coin'/account'`, depth 3). A
key from the wrong level derives addresses nobody else finds — which is
indistinguishable from lost funds, and the API refuses it for that reason.

---

## 2. Deploy

### Docker (anywhere)

```bash
docker build -t veyra-api .
docker run -p 127.0.0.1:3000:3000 \
  -e VEYRA_WATCH_ONLY=true \
  -e VEYRA_XPUB="tpub..." \
  -e VEYRA_API_TOKEN="$(openssl rand -hex 32)" \
  -e VEYRA_NETWORK=testnet \
  veyra-api
```

The image runs as a non-root user, with a read-only filesystem, all
capabilities dropped, and `no-new-privileges`. If the process is compromised,
the attacker inherits an account that owns nothing.

### Fly.io

```bash
fly launch --no-deploy --copy-config --config deploy/fly.toml
fly secrets set VEYRA_XPUB="tpub..." VEYRA_API_TOKEN="$(openssl rand -hex 32)"
fly deploy
```

### Render

Point at `deploy/render.yaml`. The secret variables are marked `sync: false`,
so Render prompts for them in the dashboard rather than reading them from the
committed file.

### Local, to try the shape first

```bash
VEYRA_XPUB=tpub... VEYRA_API_TOKEN=$(openssl rand -hex 32) \
  docker compose -f deploy/docker-compose.yml up
```

---

## 3. TLS is not optional

The API speaks **plain HTTP**. Fly and Render terminate TLS for you. On your
own host, put nginx or Caddy in front of it and never expose port 3000
directly.

Without TLS the bearer token crosses the network in cleartext, and anyone on
the path can read every balance and substitute a recipient address in a PSBT
before it reaches you.

---

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `VEYRA_WATCH_ONLY` | yes | Must be `true` for a hosted deployment |
| `VEYRA_XPUB` | yes | Account-level extended public key |
| `VEYRA_API_TOKEN` | recommended | Generated and printed once if unset |
| `VEYRA_NETWORK` | | `regtest` (default), `testnet`, `signet`, `mainnet` |
| `VEYRA_ESPLORA_URL` | | Chain source. Prefer your own instance |
| `VEYRA_RPC_URL` + user/password | | Bitcoin Core, better for privacy |
| `VEYRA_ALLOWED_ORIGINS` | | Browser origins permitted by CORS |
| `VEYRA_MNEMONIC` | **never** | Refused when `VEYRA_WATCH_ONLY` is set |

---

## Endpoints that change in watch-only mode

| Endpoint | Signing wallet | Watch-only |
| --- | --- | --- |
| `POST /transactions/prepare` | Signed transaction, held by id | **Unsigned PSBT** |
| `POST /transactions/send` | Broadcasts by id | **422** — cannot sign |
| `POST /transactions/broadcast` | not present | Accepts signed hex |
| `POST /transactions/bump` | Replaces a stuck tx | **422** — cannot sign |

Every input of a broadcast transaction is checked against the UTXOs this wallet
watches. Without that, the endpoint would be an open relay for anyone holding
the token.

---

## Securing the local signing wallet

The hosted side holds nothing. The local side holds everything, so:

### Encrypt the seed at rest

```ts
const store = encryptMnemonic(mnemonic, passphrase);   // scrypt + AES-256-GCM
```

**scrypt, not PBKDF2.** A human-chosen passphrase has far less entropy than a
key, so the KDF is the only thing between a leaked file and the funds. PBKDF2
parallelises cheaply on a GPU; scrypt is memory-hard — N=2¹⁷ needs ~128 MB per
guess, which is expensive to replicate thousands of times.

**GCM, not CBC.** Tampering is *detected* rather than producing garbage
plaintext. A corrupted mnemonic that still parses derives the wrong addresses
silently. The KDF parameters are authenticated too, so an attacker cannot edit
the header to claim a cheap N and hand the file back.

### Auto-lock

```ts
new UnlockedKeystore(store, 15 * 60 * 1000);   // lock after 15 minutes
```

Honest about what this does: it **shortens the window** during which a memory
read succeeds. It does not prevent one. Once unlocked, the seed is in the heap
and at-rest encryption is irrelevant to that.

### The controls, and what each actually covers

| Control | Defends against | Does **not** defend against |
| --- | --- | --- |
| Watch-only hosting | Host compromise, malicious operator | The host seeing your balances |
| Encrypted keystore | Stolen drive, leaked backup, shared machine | Memory read while unlocked |
| Auto-lock | A long-lived unlocked process | A read during the window |
| Spending policy | Stolen API token, client bug, fat finger | Local attacker — they sign outside Veyra |
| Multisig | **A single seed compromise** | A quorum of compromised holders |
| Hardware wallet | Malware on the signing machine | Physical coercion |

Multisig is the only row that changes the *shape* of the risk rather than its
probability. Everything else narrows a window.

---

## The client-side signer

`app/signer.html` completes the split. The hosted API holds an xpub and cannot
sign; this page holds the seed and **cannot reach the network**.

```
npm run app     →  http://127.0.0.1:5173/signer.html
```

Or build it and copy `dist/signer.html` plus its asset to an air-gapped
machine — it is self-contained.

### The one line that matters

```html
Content-Security-Policy: default-src 'none'; connect-src 'none'; ...
```

`connect-src 'none'` means the page **cannot make a network request of any
kind** — no fetch, no XHR, no beacon, no image ping. Even if an attacker
achieved script execution there, no channel exists to send a key out through.
No external origin is permitted for scripts or styles either, so there is no
third-party code in scope at all.

### What a browser still cannot give you

Stated because "sign in your browser" is routinely sold as more than it is:

- **No memory protection.** The seed is in the heap; anything that can read the
  process reads it.
- **No secure element.** A hardware wallet keeps the key in a chip that never
  exposes it. A browser cannot.
- **Extensions** can read page content on many browsers.
- **A compromised browser or OS** defeats all of the above.

The CSP removes the *exfiltration* channel, which is the most likely attack by
a wide margin. It does not make a browser a secure enclave. An air-gapped
machine closes the rest.

### The full flow

1. Hosted API builds an unsigned PSBT — it cannot sign
2. Copy the PSBT to the signer (offline)
3. Unlock a keystore or paste a mnemonic — neither is stored
4. Review the outputs, fee, and txid
5. Sign, and copy the hex back
6. `POST /transactions/broadcast` on the online machine

The signer checks that the key it derives at the PSBT's stated path **matches
the public key the PSBT names**. A mismatch means the input belongs to someone
else, and signing anyway would produce a useless signature.

## What is still missing

- **No mTLS or IP allowlist.** The bearer token is the only authentication.
- **No shared rate limiter.** In-memory and per-process; it resets on restart
  and does not coordinate across instances.
- **No audit log.** Errors are logged; successful operations are not.
- **`X-Forwarded-For` is ignored**, so behind a proxy every client looks like
  one address to the rate limiter. Configuring a trusted proxy is not
  implemented.
