# Veyra API

> **There is a full documentation site.** Run `npm run docs:build` then
> `npm run app`, and open <http://127.0.0.1:5173/docs/> — fourteen pages
> covering concepts, guides, and a complete reference with a console that sends
> real requests to your running API. This file is the condensed version.

An HTTP boundary in front of the wallet core. It exposes balances, addresses,
and a two-step spending flow — and deliberately exposes nothing else.

> ⚠️ **This process holds private keys in memory.** Anyone who can read the
> process, or the host it runs on, can extract them. It speaks plain HTTP and
> binds to localhost by default. It has not been audited and has never handled
> real funds.

---

## The one design decision that matters

Sending is **two steps**, and the second takes only an id:

```
POST /transactions/prepare   { to, amount, feeRate }   →  a review, plus an id
POST /transactions/send      { id }                    →  broadcasts THOSE bytes
```

`send` has no `to`, no `amount`, no `feeRate`. It cannot rebuild the
transaction, re-select coins, or re-derive anything. **There is no parameter
through which the broadcast could differ from what was reviewed.**

The alternative — `send` accepting `{to, amount}` again — would build the
transaction twice. Coin selection is random, so even an honest server would
produce something different the second time. §14 requires that transaction
information is never silently altered after confirmation; the only reliable way
to guarantee that is for the confirming call to be incapable of altering it.

---

## Setup

```powershell
npm install
$env:VEYRA_NETWORK = "regtest"
npm run api
```

The token and (if generated) the mnemonic are printed **once** at startup.
There is no default credential to forget to change.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `VEYRA_NETWORK` | `regtest` | `regtest`, `testnet`, `signet`, `mainnet` |
| `VEYRA_PORT` | `3000` | Listen port |
| `VEYRA_HOST` | `127.0.0.1` | Listen address |
| `VEYRA_API_TOKEN` | *generated* | Bearer token. Generated and printed if unset |
| `VEYRA_MNEMONIC` | *generated* | Restore an existing wallet |
| `VEYRA_PASSPHRASE` | *(empty)* | BIP-39 passphrase |
| `VEYRA_RPC_URL` | — | Bitcoin Core RPC endpoint |
| `VEYRA_RPC_USER` / `VEYRA_RPC_PASSWORD` | — | RPC credentials |
| `VEYRA_ESPLORA_URL` | — | Esplora base URL (used if no RPC configured) |
| `VEYRA_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated browser origins permitted by CORS |
| `VEYRA_I_UNDERSTAND_MAINNET_RISK` | — | Must be `yes` to start on mainnet |

**Never put a mnemonic in a shell command.** Shell history persists. Use a
`.env` file that is gitignored, or a secrets manager.

The server **refuses to start on mainnet** without the explicit acknowledgement
variable. Starting a key-holding server against real funds must never be the
result of a default or a forgotten setting.

---

## Endpoints

All require `Authorization: Bearer <token>` except `/health`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness. Public, and deliberately reports nothing else |
| GET | `/wallet` | Network, derivation path, fingerprint |
| GET | `/wallet/address` | Current receive address |
| POST | `/wallet/address/next` | Advance to a fresh receive address |
| GET | `/wallet/balance` | Total, spendable, unconfirmed, unavailable |
| GET | `/wallet/utxos` | Unspent outputs (no derivation paths) |
| GET | `/wallet/security` | Verifiable security state and warnings |
| GET | `/wallet/fees` | Fee estimates, with `isLive` telling you whether they are real |
| GET | `/transactions` | Transaction history with direction and net value |
| GET | `/transactions/replaceable` | Transactions from this session that can still be fee-bumped |
| POST | `/transactions/bump` | Replace a stuck transaction with a higher-fee version (BIP-125) |
| POST | `/wallet/sync` | Rescan from the chain source |
| POST | `/transactions/prepare` | Build and sign; returns a review |
| GET | `/transactions/:id` | Re-read a pending review |
| POST | `/transactions/send` | Broadcast a prepared transaction |
| DELETE | `/transactions/:id` | Cancel before sending |

### Endpoints that do not exist, by design (§20)

`/private-key` · `/seed` · `/mnemonic` · `/secrets` · `/wallet/export` ·
`/wallet/backup`

Not guarded, not admin-only, not behind a flag — **absent**. The most reliable
way to guarantee an endpoint cannot leak a secret is for the code path not to
exist. A test asserts by reflection that the service class has no method whose
name suggests otherwise, so adding one fails the suite.

---

## Amounts

Always **satoshis**, always **strings** in responses.

JSON numbers are IEEE doubles and lose precision above 2⁵³. Bitcoin's supply is
2.1×10¹⁵ satoshis — below that, but not by enough margin to be relaxed about
intermediate arithmetic. Requests accept either a number or a decimal string;
responses always use strings so no client can lose precision by accident.

```jsonc
// prepare request
{ "to": "bcrt1q...", "amount": "100000", "feeRate": 5 }

// prepare response — §16: amount, fee, total, remaining, never hidden
{
  "id": "3f2a...",
  "expiresAt": "2026-08-19T12:34:56.000Z",
  "recipient": "bcrt1q...",
  "amount": "100000",
  "fee": "705",
  "total": "100705",
  "change": "899295",
  "remainingBalance": "899295",
  "feeRate": 5.0,
  "vsize": 141,
  "inputCount": 1,
  "txid": "a1b2..."
}
```

Prepared transactions **expire after 5 minutes**. They hold UTXOs that may be
spent elsewhere and a fee rate that ages; expiry bounds both, and bounds memory.

---

## Errors

```json
{ "error": { "code": "UNPROCESSABLE", "message": "insufficient funds" } }
```

| Code | Status |
| --- | --- |
| `BAD_REQUEST` | 400 |
| `UNAUTHORIZED` | 401 |
| `NOT_FOUND` | 404 |
| `CONFLICT` | 409 |
| `PAYLOAD_TOO_LARGE` | 413 |
| `UNPROCESSABLE` | 422 |
| `RATE_LIMITED` | 429 |
| `INTERNAL` | 500 |

Errors carry two messages internally: a **public** one (constant strings, no
interpolated state) and an **internal** one that is logged server-side only.
They are separate fields, so the serialiser cannot send the wrong one.

Deliberate ambiguities, each of which would otherwise be an oracle:

- **Every auth failure is identical.** Missing header, wrong scheme, and wrong
  token all return the same 401. Distinguishing them tells an attacker how far
  along they are.
- **Every 404 is identical.** Nonexistent, expired, already-sent, and unknown
  path all look the same. Distinguishing them lets an attacker probe for valid
  ids.
- **Wrong method returns 404, not 405.** A 405 confirms the path exists.

---

## Security controls (§21)

| Control | Implementation |
| --- | --- |
| Authentication | Bearer token, compared with `timingSafeEqual` over SHA-256 digests — so neither content nor **length** leaks through timing |
| Rate limiting | Fixed window, applied **before** auth so tokens cannot be brute-forced at full speed |
| Body limits | 64 KB, enforced **during** streaming, not after — a lied-about `Content-Length` does not help |
| Input validation | Hand-written strict parsers; unknown fields rejected rather than ignored |
| Replay | A prepared id is consumed before the network call, so a retry cannot double-broadcast |
| Tampering | `send` accepts only an id |
| IDOR | 128-bit random ids from the CSPRNG |
| Enumeration | Identical 404s; no 405 |
| Secret leakage | No endpoint or service method can reach key material |
| Headers | `no-store`, `nosniff`, `DENY`, CSP `default-src 'none'`, no `X-Powered-By` |
| CORS | Explicit origin allowlist, never `*`; no `Allow-Credentials`; `Vary: Origin` |

Run them: `npm run test:api` — 55 tests, each written as an attack.

---

## Known limitations

Stated plainly, because §47 forbids claiming more than was verified.

- **No TLS.** Plain HTTP. Anything beyond localhost needs a reverse proxy.
- **The rate limiter is in-memory, per-process, and fixed-window.** It resets on
  restart, does not coordinate across instances, and permits a brief 2× burst
  at a window boundary. It addresses casual abuse, not a determined attacker.
- **`X-Forwarded-For` is ignored** — it is client-controlled, and honouring it
  would let an attacker mint a fresh identity per request. Behind a trusted
  proxy you must configure that proxy's address explicitly; not implemented.
- **Single wallet per process.** No multi-tenancy, so no cross-tenant
  authorization model exists to get wrong.
- **Keys live in process memory** for the server's lifetime. There is no HSM,
  no enclave, and no at-rest encryption.
- **CORS protects browsers, not the API.** `curl` and any non-browser client
  ignore it entirely; the token is what actually guards the endpoints.
- **No CSRF protection**, because there are no cookies — auth is a bearer token
  only. Adding cookie auth later would require adding CSRF defence.
- **No request logging** beyond errors. Useful for privacy; unhelpful for
  forensics.
