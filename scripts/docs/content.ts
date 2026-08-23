/**
 * DOCS CONTENT
 *
 * One entry per page. Order here is the sidebar order and the prev/next order,
 * so a reader who starts at the top and presses Next reaches the end having
 * been told things in a sequence that makes sense.
 */

import type { Page } from "./layout.js";

/** A code block with a language label and a copy button. */
const code = (lang: string, body: string) =>
  `<div class="code-block"><span class="code-lang">${lang}</span><pre>${body}</pre></div>`;

/** A callout. */
const note = (tone: "teal" | "warning" | "danger", body: string) =>
  `<div class="callout" data-tone="${tone}">${body}</div>`;

/** An expandable endpoint card with a live request runner. */
function endpoint(spec: {
  method: string;
  path: string;
  auth?: boolean;
  summary: string;
  detail?: string;
  fields?: Array<[string, string, string]>;
  body?: unknown;
  response: unknown;
}): string {
  const auth = spec.auth !== false;
  const hasParam = spec.path.includes("{id}");
  const pretty = (value: unknown) =>
    JSON.stringify(value, null, 2)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/"([^"]+)":/g, '<span class="tok-key">"$1"</span>:')
      .replace(/: "([^"]*)"/g, ': <span class="tok-str">"$1"</span>')
      .replace(/: (\d+|true|false|null)/g, ': <span class="tok-num">$1</span>');

  return `
    <article class="endpoint">
      <button class="endpoint-head" aria-expanded="false">
        <span class="method" data-m="${spec.method}">${spec.method}</span>
        <span class="ep-path">${spec.path}</span>
        <span class="ep-summary">${spec.summary}</span>
        <span class="ep-auth">${auth ? "auth" : "public"}</span>
      </button>
      <div class="endpoint-body">
        ${spec.detail ? `<p style="color:var(--muted);font-size:14px;margin-top:14px">${spec.detail}</p>` : ""}
        ${
          spec.fields
            ? `<h3>Parameters</h3><table><tr><th>Field</th><th>Type</th><th>Notes</th></tr>${spec.fields
                .map(([f, t, n]) => `<tr><td><code>${f}</code></td><td><code>${t}</code></td><td>${n}</td></tr>`)
                .join("")}</table>`
            : ""
        }
        ${spec.body !== undefined ? `<h3>Request</h3>${code("json", pretty(spec.body))}` : ""}
        <h3>Response</h3>${code("json", pretty(spec.response))}
        <h3>Try it</h3>
        <div class="console-row">
          ${hasParam ? `<label class="f"><span>id</span><input class="param" placeholder="prepared transaction id" spellcheck="false" /></label>` : ""}
          ${spec.body !== undefined ? `<label class="f"><span>Body</span><textarea class="reqbody" spellcheck="false">${JSON.stringify(spec.body, null, 2)}</textarea></label>` : ""}
          <button class="run" data-run data-method="${spec.method}" data-path="${spec.path}" data-auth="${auth}">Send request</button>
        </div>
        <p class="result">Not sent yet.</p>
      </div>
    </article>`;
}

/** The credential panel, included on any page with runnable endpoints. */
const CONSOLE = `
  <div class="console">
    <div class="console-row">
      <label class="f"><span>API base URL</span><input id="baseUrl" value="http://127.0.0.1:3000" spellcheck="false" /></label>
      <label class="f"><span>Bearer token</span><input id="token" type="password" placeholder="printed by npm run api" spellcheck="false" /></label>
      <button class="run" data-run data-method="GET" data-path="/wallet">Test</button>
    </div>
    <p class="result">Kept in this browser session only. Never written to disk.</p>
  </div>
  <div class="callout" data-tone="warning" id="fileWarn" style="display:none">
    <strong>Opened from the filesystem.</strong> Live requests will be blocked: a
    <code>file://</code> page has origin <code>null</code>, which the API's CORS
    allowlist excludes deliberately. Serve these docs with <code>npm run app</code>.
  </div>`;

export const PAGES: Page[] = [
  // ══════════════════════════════════════════════ GET STARTED
  {
    slug: "introduction",
    group: "Get started",
    title: "Introduction",
    lede: "A self-custodial Bitcoin wallet, exposed as a JSON API.",
    body: `
<p>
  Veyra is a Bitcoin wallet built from first principles as an educational
  security project. This API is the boundary in front of it: balances,
  addresses, and a two-step spending flow, over HTTP.
</p>

${note("danger", `<strong>Read this before anything else.</strong> This process holds private
keys in memory. It speaks plain HTTP, has never been independently audited, and
has never handled real funds. It exists to be inspected and attacked, not to
secure savings.`)}

${note("teal", `<strong>Consensus-verified.</strong> On 2026-08-20 Bitcoin Core
accepted a transaction Veyra built and signed, on regtest, and computed an
identical txid — so the serialisation is byte-exact and the signing path
satisfies real consensus rules, not just a reading of them. Reproduce with
<code>npm run test:regtest</code>.`)}

<h2 id="the-rule">The one rule that shapes this API</h2>
<p>
  <strong>The wallet holds the keys, and nothing above it can reach them.</strong>
</p>
<p>
  There is no endpoint that returns a private key, a seed, or a mnemonic. Not
  guarded, not admin-only, not behind a flag — <em>absent</em>. The most
  reliable way to guarantee an endpoint cannot leak a secret is for the code
  path not to exist, and a test asserts by reflection that the service class
  has no method whose name suggests otherwise.
</p>
<p>
  That has a consequence you will feel immediately: <strong>signing happens
  server-side</strong>. You do not receive an unsigned transaction to sign
  yourself. The trade-off is that this process is a custodian of your keys for
  as long as it runs, which is why it binds to localhost and why the security
  page says so in the first paragraph.
</p>

<h2 id="architecture">Architecture</h2>
<div class="diagram">
<svg viewBox="0 0 760 340" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Browser to API to wallet core to chain source">
  <defs><marker id="a" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" fill="currentColor" opacity=".5"/></marker></defs>
  <g fill="none" stroke="currentColor" stroke-opacity=".18">
    <rect x="20" y="24" width="180" height="62" rx="8"/>
    <rect x="20" y="139" width="180" height="62" rx="8"/>
    <rect x="20" y="254" width="180" height="62" rx="8"/>
    <rect x="540" y="139" width="196" height="62" rx="8"/>
    <rect x="540" y="254" width="196" height="62" rx="8"/>
  </g>
  <g fill="currentColor" font-family="IBM Plex Sans, sans-serif" font-size="13" font-weight="600">
    <text x="36" y="50">Browser UI</text><text x="36" y="165">API</text>
    <text x="36" y="280">Wallet core</text><text x="556" y="165">Chain source</text>
    <text x="556" y="280">Bitcoin network</text>
  </g>
  <g fill="currentColor" opacity=".6" font-family="IBM Plex Mono, monospace" font-size="11">
    <text x="36" y="68">holds no keys</text><text x="36" y="183">auth · limits · validation</text>
    <text x="36" y="298">seed · keys · signing</text><text x="556" y="183">bitcoind or Esplora</text>
    <text x="556" y="298">regtest / testnet</text>
    <text x="120" y="116">HTTP + bearer token</text><text x="120" y="231">in-process call</text>
    <text x="250" y="276">sync · broadcast</text>
  </g>
  <g stroke="currentColor" stroke-opacity=".45" stroke-width="1.2" marker-end="url(#a)">
    <line x1="110" y1="88" x2="110" y2="135"/><line x1="110" y1="203" x2="110" y2="250"/>
    <line x1="202" y1="285" x2="536" y2="285"/><line x1="638" y1="250" x2="638" y2="205"/>
  </g>
  <rect x="8" y="242" width="204" height="86" rx="10" fill="none" stroke="#14b8a6" stroke-dasharray="4 4" opacity=".6"/>
  <text x="14" y="238" fill="#14b8a6" font-family="IBM Plex Mono, monospace" font-size="10" letter-spacing="1">SECRECY BOUNDARY</text>
</svg>
</div>

<h2 id="what-you-get">What you get</h2>
<ul>
  <li><strong>Addresses</strong> derived from a BIP-84 tree, fresh on request, capped at the gap limit.</li>
  <li><strong>Balances</strong> broken into spendable, unconfirmed, and unavailable — never one number that might be a lie.</li>
  <li><strong>A two-step spend</strong>: prepare returns a signed transaction and a review; send broadcasts it by id, and cannot alter it.</li>
  <li><strong>Coin selection</strong> that prefers changeless transactions, with a documented privacy rationale.</li>
  <li><strong>Chain sync</strong> against your own <code>bitcoind</code>, or an Esplora instance if you accept the privacy cost.</li>
</ul>

<h2 id="conventions">Two conventions to read before you write code</h2>
<p>
  <strong>Amounts are strings, in satoshis.</strong> <code>"100000"</code>, not
  <code>0.001</code>. JSON numbers are IEEE doubles and lose integer precision
  above 2<sup>53</sup>. Bitcoin's supply is 2.1×10<sup>15</sup> satoshis — under
  that ceiling, but not by a margin worth being relaxed about. Requests accept a
  number or a string; responses are always strings.
</p>
<p>
  <strong>A prepared transaction expires in five minutes.</strong> It holds
  specific coins and a fee rate that ages. If you show a user a review and they
  go and make a cup of tea, handle the 404.
</p>

<h2 id="start">Start here</h2>
<p>Get a token, make a call, and send a regtest transaction: <a href="quickstart.html"><strong>Quickstart →</strong></a></p>`,
  },

  {
    slug: "quickstart",
    group: "Get started",
    title: "Quickstart",
    lede: "From nothing to a broadcast transaction on your own private chain.",
    body: `
<p>
  Everything below runs on <strong>regtest</strong> — a private Bitcoin network
  where you mine blocks on demand and the coins are worthless. It runs the same
  consensus code as mainnet, which is what makes it a real test rather than a
  simulation.
</p>

<h2 id="run">1. Start the API</h2>
${code("powershell", `$env:VEYRA_NETWORK = <span class="tok-str">"regtest"</span>
npm run api`)}
<p>It prints a token and, if no mnemonic was supplied, a freshly generated one:</p>
${code("text", `Veyra API — regtest
  listening   http://127.0.0.1:3000
  wallet      m/84'/1'/0'  (854f45e9)

  API token (generated, shown once):
    9f2c4e...`)}

${note("warning", `The mnemonic is shown <strong>once</strong>. There is no
<code>getMnemonic()</code> and no endpoint that returns it. A copy the wallet
can retrieve is a copy an attacker can retrieve.`)}

<h2 id="call">2. Make a call</h2>
${code("powershell", `curl http://127.0.0.1:3000/health

curl -H <span class="tok-str">"Authorization: Bearer &lt;token&gt;"</span> http://127.0.0.1:3000/wallet`)}

<h2 id="address">3. Get an address</h2>
${code("json", `<span class="tok-key">"address"</span>: <span class="tok-str">"bcrt1qcl3pgzqcez3wwyp8n4am48qt55y99n6lk439d8"</span>,
<span class="tok-key">"path"</span>:    <span class="tok-str">"m/84'/1'/0'/0/0"</span>`)}

<h2 id="fund">4. Fund it and sync</h2>
<p>With a regtest node running (see <a href="environments.html">Environments</a>):</p>
${code("powershell", `$cli = <span class="tok-str">"C:\\Program Files\\Bitcoin\\daemon\\bitcoin-cli.exe"</span>
&amp; $cli -regtest -rpcwallet=veyra-test sendtoaddress &lt;address&gt; 0.01
&amp; $cli -regtest generatetoaddress 1 &lt;any-address&gt;`)}
${code("powershell", `curl -X POST -H <span class="tok-str">"Authorization: Bearer &lt;token&gt;"</span> http://127.0.0.1:3000/wallet/sync`)}

<h2 id="send">5. Send</h2>
<p>Two calls. The first builds and signs; nothing is broadcast.</p>
${code("powershell", `curl -X POST http://127.0.0.1:3000/transactions/prepare \\
  -H <span class="tok-str">"Authorization: Bearer &lt;token&gt;"</span> \\
  -H <span class="tok-str">"Content-Type: application/json"</span> \\
  -d <span class="tok-str">'{"to":"bcrt1q...","amount":"100000","feeRate":5}'</span>`)}
<p>Read the review, then broadcast <em>that exact transaction</em> by id:</p>
${code("powershell", `curl -X POST http://127.0.0.1:3000/transactions/send \\
  -H <span class="tok-str">"Authorization: Bearer &lt;token&gt;"</span> \\
  -H <span class="tok-str">"Content-Type: application/json"</span> \\
  -d <span class="tok-str">'{"id":"3f2a..."}'</span>`)}

<h2 id="ui">6. Or use the interface</h2>
${code("powershell", `npm run app   <span class="tok-com"># http://127.0.0.1:5173</span>`)}
<p>Paste the token into the connect screen. These docs are served alongside it.</p>`,
  },

  {
    slug: "authentication",
    group: "Get started",
    title: "Authentication",
    lede: "One bearer token. No sessions, no cookies, no refresh flow.",
    body: `
${code("http", `Authorization: Bearer &lt;token&gt;`)}

<p>
  Every endpoint except <code>/health</code> requires it. The token is 256 bits
  from the OS CSPRNG, generated at startup and printed once, or supplied via
  <code>VEYRA_API_TOKEN</code>.
</p>

<h2 id="timing">Comparison is timing-safe</h2>
<p>
  The token is compared with <code>timingSafeEqual</code> over SHA-256 digests
  of both sides. Two reasons, and the second is the one people miss:
</p>
<ul>
  <li>String comparison short-circuits at the first differing byte, so response
      time leaks how many leading bytes matched. Enough samples and a token is
      recoverable one byte at a time.</li>
  <li><code>timingSafeEqual</code> <em>throws</em> on differing lengths — and
      that throw is itself an oracle revealing the token's length. Hashing both
      sides to a fixed 32 bytes removes the length signal entirely.</li>
</ul>

<h2 id="identical">Every failure looks the same</h2>
${code("json", `{ <span class="tok-key">"error"</span>: { <span class="tok-key">"code"</span>: <span class="tok-str">"UNAUTHORIZED"</span>, <span class="tok-key">"message"</span>: <span class="tok-str">"Authentication required"</span> } }`)}
<p>
  Missing header, wrong scheme, malformed header, and wrong token all produce
  this exact body with a 401. Telling an attacker "wrong scheme" confirms they
  found the right header name; "invalid token" confirms the format is right.
  A malformed header still runs a comparison, so it is not measurably faster to
  reject than a well-formed one.
</p>

<h2 id="ratelimit-order">Rate limiting runs first</h2>
<p>
  Before authentication, deliberately. If failed auth did not consume an
  allowance, tokens could be brute-forced at full speed.
</p>

<h2 id="cors">CORS</h2>
<p>
  Browser origins must be allowlisted — never <code>*</code>. The token is the
  real defence, but a wildcard would let any site probe this API from a
  victim's browser and read the replies, turning a stolen token into one usable
  from anywhere.
</p>
${code("powershell", `$env:VEYRA_ALLOWED_ORIGINS = <span class="tok-str">"http://127.0.0.1:5173"</span>`)}
${note("teal", `<strong>CORS protects browsers, not the API.</strong>
<code>curl</code> and every non-browser client ignore it entirely.`)}`,
  },

  {
    slug: "environments",
    group: "Get started",
    title: "Environments",
    lede: "Four networks. Only one of them costs money to get wrong.",
    body: `
<table>
  <tr><th>Network</th><th>Prefix</th><th>Coin type</th><th>Use</th></tr>
  <tr><td><code>regtest</code></td><td><code>bcrt1</code></td><td>1</td><td>Development. Private chain, instant blocks. <strong>Default.</strong></td></tr>
  <tr><td><code>signet</code></td><td><code>tb1</code></td><td>1</td><td>Integration. Public, stable, faucet-funded.</td></tr>
  <tr><td><code>testnet</code></td><td><code>tb1</code></td><td>1</td><td>Integration. Public, occasionally chaotic.</td></tr>
  <tr><td><code>mainnet</code></td><td><code>bc1</code></td><td>0</td><td>Real bitcoin. Irreversible.</td></tr>
</table>

<h2 id="separation">Separation is enforced by the address format</h2>
<p>
  The human-readable prefix is folded <em>into</em> the Bech32 checksum. So a
  mainnet address does not merely look wrong when parsed as testnet — it
  <strong>fails the checksum outright</strong>. There is no code path where a
  wrong-network address is quietly accepted.
</p>
<p>
  Key trees are also disjoint: mainnet derives at coin type 0, every test
  network at 1. The same mnemonic produces entirely unrelated addresses.
</p>

${note("warning", `<strong>Signet and testnet are indistinguishable at the
address layer.</strong> They share a prefix and a coin type. They are separate
chains with separate UTXO sets, but no encoding-level check catches the
confusion. This is a real limitation of the format, not of Veyra.`)}

<h2 id="mainnet">Mainnet requires an explicit acknowledgement</h2>
${code("powershell", `$env:VEYRA_NETWORK = <span class="tok-str">"mainnet"</span>
$env:VEYRA_I_UNDERSTAND_MAINNET_RISK = <span class="tok-str">"yes"</span>`)}
<p>
  Without it the server refuses to start. Launching a key-holding process
  against real funds must never be the result of a default or a forgotten
  variable.
</p>

<h2 id="regtest-setup">Setting up regtest</h2>
${code("ini", `<span class="tok-com"># %APPDATA%\\Bitcoin\\bitcoin.conf</span>
regtest=1
server=1
fallbackfee=0.0001

[regtest]
rpcuser=veyra
rpcpassword=veyra
rpcport=18443`)}
<p>
  <code>fallbackfee</code> is required — without it a fresh chain has no fee
  estimates and wallet calls fail with a confusing error.
</p>
${code("powershell", `$env:VEYRA_RPC_URL = <span class="tok-str">"http://127.0.0.1:18443"</span>
$env:VEYRA_RPC_USER = <span class="tok-str">"veyra"</span>
$env:VEYRA_RPC_PASSWORD = <span class="tok-str">"veyra"</span>`)}`,
  },

  // ══════════════════════════════════════════════ CORE CONCEPTS
  {
    slug: "custody-model",
    group: "Core concepts",
    title: "The custody model",
    lede: "Where the keys are, what can reach them, and what that costs you.",
    body: `
<h2 id="boundary">The secrecy boundary</h2>
<p>
  Secrets stop at <code>core/wallet/</code>. Everything above it — the API, the
  UI — deals in addresses, amounts, and transaction hex.
</p>
<table>
  <tr><th>Layer</th><th>Can reach a key</th></tr>
  <tr><td>Browser UI</td><td>No</td></tr>
  <tr><td>HTTP API</td><td>No</td></tr>
  <tr><td>Wallet core</td><td><strong>Yes</strong></td></tr>
</table>

<h2 id="absent">The absent endpoints</h2>
<p>
  <span class="pill">/private-key</span><span class="pill">/seed</span><span class="pill">/mnemonic</span><span class="pill">/secrets</span><span class="pill">/wallet/export</span><span class="pill">/wallet/backup</span>
</p>
<p>
  These return 404 because they do not exist. A test enumerates the service
  class by reflection and fails if any method name matches
  <code>/priv|seed|mnemonic|secret|export|backup|xprv/</code>, so adding one
  breaks the build.
</p>

<h2 id="backup">Backup is the mnemonic, shown once</h2>
<p>
  Returned at wallet creation and never again. If it is lost the funds are
  unrecoverable — which is the honest behaviour for self-custody rather than a
  missing feature. A copy the wallet can retrieve is a copy an attacker can
  retrieve.
</p>

<h2 id="redaction">Keys refuse to serialise</h2>
<p>
  Even inside the core, <code>PrivateKey</code> redacts itself. The most common
  way wallets lose funds is not a broken curve — it is a key that ended up in a
  log line.
</p>
${code("javascript", `String(key)                    <span class="tok-com">// "PrivateKey&lt;redacted&gt;"</span>
JSON.stringify({ key })        <span class="tok-com">// {"key":"PrivateKey&lt;redacted&gt;"}</span>
util.inspect(key, {showHidden: true})  <span class="tok-com">// redacted</span>
Object.keys(key)               <span class="tok-com">// []</span>`)}

<h2 id="cost">What this costs you</h2>
${note("danger", `<strong>This process is a custodian for as long as it runs.</strong>
Keys are in ordinary process memory. There is no HSM, no enclave, and no
at-rest encryption. Anyone who can read the process, a core dump, or swap can
extract them. Zeroing buffers after use is best-effort in a garbage-collected
runtime — it narrows the window, it does not close it.`)}
<p>
  The alternative design — returning unsigned transactions for a client to sign
  — would remove this, at the cost of every client needing key handling. Veyra
  chose server-side signing because the project's purpose is to make the
  cryptography legible in one place. That is a trade-off, and this page is
  where it is written down rather than glossed over.
</p>`,
  },

  {
    slug: "transaction-lifecycle",
    group: "Core concepts",
    title: "Transaction lifecycle",
    lede: "Why sending is two calls, and why the second one takes only an id.",
    body: `
${code("text", `POST /transactions/prepare   →   builds, signs, returns a review + id
                                 (nothing is broadcast)
                     ↓
              user reviews
                     ↓
POST /transactions/send      →   broadcasts THOSE bytes, by id`)}

<h2 id="why">Why two steps</h2>
<p>
  <code>send</code> has no <code>to</code>, no <code>amount</code>, no
  <code>feeRate</code>. It cannot rebuild the transaction, re-select coins, or
  re-derive an address. <strong>There is no parameter through which the
  broadcast could differ from what was reviewed.</strong>
</p>
<p>
  The alternative fails even with an honest server: if <code>send</code>
  accepted <code>{to, amount}</code> again, the transaction would be built
  twice — and coin selection is random, so the second build would differ from
  the one the user approved.
</p>

<h2 id="review">The review is server-authored</h2>
<p>
  It is not a summary composed from what you typed. It is the server's account
  of a transaction it has <em>already built and signed</em>: the fee it actually
  computed, the coins it actually selected, the change it actually created.
</p>
<p>
  A client-composed summary shows what was asked for. A server-authored one
  shows what will happen — and the gap between them is exactly where a bug
  would hide.
</p>

<h2 id="guards">What runs before a signature exists</h2>
<ol>
  <li>Address validity <em>for this network</em></li>
  <li>Amount above the 294-satoshi dust threshold</li>
  <li>Coin selection — may refuse with insufficient funds</li>
  <li>Fee sanity: an implied fee above 0.01 BTC is refused as a likely mistake</li>
</ol>
<p>Then it signs, verifies its own signature, and checks the realised fee rate against the requested one.</p>

<h2 id="expiry">Expiry and replay</h2>
<p>
  A prepared transaction lives for <strong>five minutes</strong>. It holds
  specific coins and a fee rate that ages.
</p>
<p>
  The id is consumed <em>before</em> the network call, so a retry after a
  timeout cannot double-broadcast. The trade-off is deliberate: if broadcast
  fails transiently you must prepare again. Preferring a failed send over a
  possible double send is the right way round when money is involved.
</p>

${note("teal", `Nonexistent, expired, and already-sent ids all return an
identical 404. Distinguishing them would let an attacker probe for valid ids.`)}`,
  },

  {
    slug: "amounts",
    group: "Core concepts",
    title: "Amounts and precision",
    lede: "Satoshis, as strings, always. And why that is not pedantry.",
    body: `
<h2 id="strings">Responses are always strings</h2>
${code("json", `{ <span class="tok-key">"spendable"</span>: <span class="tok-str">"1500000"</span>, <span class="tok-key">"unconfirmed"</span>: <span class="tok-str">"0"</span> }`)}
<p>
  JSON numbers are IEEE 754 doubles. Integers above 2<sup>53</sup> round
  silently — <code>JSON.parse</code> turns
  <code>1000000000000000001</code> into <code>1000000000000000000</code> with no
  error. Bitcoin's total supply is 2.1×10<sup>15</sup> satoshis, under that
  ceiling, but intermediate fee arithmetic does not reliably stay there.
</p>

<h2 id="requests">Requests accept either</h2>
${code("json", `{ <span class="tok-key">"amount"</span>: <span class="tok-str">"100000"</span> }   <span class="tok-com">// preferred</span>
{ <span class="tok-key">"amount"</span>: <span class="tok-num">100000</span> }     <span class="tok-com">// accepted below 2^53</span>`)}
<p>
  A number above <code>Number.MAX_SAFE_INTEGER</code> is <strong>rejected</strong>,
  not truncated, with a message telling you to send a string.
</p>

<h2 id="btc">Converting to BTC</h2>
${note("danger", `<strong>Never <code>parseFloat(btc) * 1e8</code>.</strong>
<code>4.35 * 1e8</code> is <code>434999999.99999994</code> in floating point.
<code>Math.round</code> hides it in most cases — and "usually correct" is not a
property money arithmetic may have.`)}
${code("javascript", `<span class="tok-com">// String arithmetic. Exact for every representable amount.</span>
function btcToSats(input) {
  const [whole = <span class="tok-str">"0"</span>, frac = <span class="tok-str">""</span>] = input.trim().split(<span class="tok-str">"."</span>);
  <span class="tok-key">if</span> (frac.length &gt; 8) <span class="tok-key">throw new</span> Error(<span class="tok-str">"8 decimal places maximum"</span>);
  <span class="tok-key">return</span> BigInt(whole) * 100000000n + BigInt((frac + <span class="tok-str">"00000000"</span>).slice(0, 8));
}`)}

<h2 id="dust">The dust threshold</h2>
<p>
  Outputs below <strong>294 satoshis</strong> are refused. Relay policy rejects
  them because they cost more to spend than they are worth and bloat the UTXO
  set every node keeps in memory forever.
</p>
<p>
  When <em>change</em> would fall below dust it cannot become an output at all,
  so it is given to the miner as extra fee. That is not a bug — it is the only
  valid option, and the review shows the realised fee so you can see it happen.
</p>`,
  },

  {
    slug: "errors",
    group: "Core concepts",
    title: "Errors",
    lede: "A stable code, a safe message, and three deliberate ambiguities.",
    body: `
${code("json", `{ <span class="tok-key">"error"</span>: { <span class="tok-key">"code"</span>: <span class="tok-str">"UNPROCESSABLE"</span>, <span class="tok-key">"message"</span>: <span class="tok-str">"insufficient funds"</span> } }`)}
<p>Branch on <code>code</code>, never on <code>message</code>. A copy edit should not change your behaviour.</p>

<h2 id="codes">Codes</h2>
<table>
  <tr><th>Code</th><th>Status</th><th>Meaning</th></tr>
  <tr><td><code>BAD_REQUEST</code></td><td>400</td><td>Malformed body, wrong type, or an unknown field</td></tr>
  <tr><td><code>UNAUTHORIZED</code></td><td>401</td><td>Missing or wrong token</td></tr>
  <tr><td><code>NOT_FOUND</code></td><td>404</td><td>Unknown path, or a prepared transaction that is gone</td></tr>
  <tr><td><code>CONFLICT</code></td><td>409</td><td>Too many transactions awaiting confirmation</td></tr>
  <tr><td><code>PAYLOAD_TOO_LARGE</code></td><td>413</td><td>Body above 64 KB</td></tr>
  <tr><td><code>UNPROCESSABLE</code></td><td>422</td><td>Valid request the wallet refuses — insufficient funds, dust, wrong network</td></tr>
  <tr><td><code>RATE_LIMITED</code></td><td>429</td><td>Above the request allowance</td></tr>
  <tr><td><code>INTERNAL</code></td><td>500</td><td>Unexpected failure; detail logged server-side only</td></tr>
</table>

<h2 id="two-messages">Every error has two messages</h2>
<p>
  A <strong>public</strong> one, sent to you, built from constant strings with
  no interpolated server state. And an <strong>internal</strong> one, logged
  server-side, which may contain anything useful. They are separate fields, so
  the serialiser cannot send the wrong one.
</p>
<p>Errors never contain: stack traces, file paths, derivation paths, or your own submitted values echoed back.</p>

<h2 id="ambiguities">Three deliberate ambiguities</h2>
<table>
  <tr><th>Behaviour</th><th>Why</th></tr>
  <tr><td>All auth failures identical</td><td>Otherwise the response reveals how close a guess was</td></tr>
  <tr><td>All 404s identical</td><td>Nonexistent, expired, and already-sent are indistinguishable, so ids cannot be probed</td></tr>
  <tr><td>Wrong method returns 404, not 405</td><td>A 405 confirms the path exists — free reconnaissance</td></tr>
</table>

<h2 id="unknown-fields">Unknown fields are rejected</h2>
${code("json", `{ <span class="tok-key">"to"</span>: <span class="tok-str">"bcrt1q..."</span>, <span class="tok-key">"amount"</span>: <span class="tok-str">"100000"</span>, <span class="tok-key">"feeRate"</span>: <span class="tok-num">5</span>, <span class="tok-key">"ammount"</span>: <span class="tok-str">"999"</span> }
<span class="tok-com">// 400 — Unexpected field: ammount</span>`)}
<p>
  Ignoring unknown fields turns a typo into a confusing downstream failure, and
  is how mass-assignment bugs appear when a field later gains meaning.
</p>`,
  },

  {
    slug: "rate-limits",
    group: "Core concepts",
    title: "Rate limits",
    lede: "120 requests per minute, and an honest account of what that protects.",
    body: `
<p>
  A fixed window of <strong>120 requests per minute</strong> per client address.
  Exceeding it returns <code>429 RATE_LIMITED</code>.
</p>

<h2 id="before-auth">Applied before authentication</h2>
<p>
  Deliberately. If failed auth did not consume an allowance, an attacker could
  brute-force tokens at full speed while never appearing to use the API.
  Preflight <code>OPTIONS</code> requests are counted too, so they cannot become
  a free channel.
</p>

<h2 id="identity">Identity is the socket address only</h2>
${note("warning", `<code>X-Forwarded-For</code> is <strong>deliberately
ignored</strong>. It is client-controlled: honouring it would let an attacker
mint a fresh identity per request and bypass the limiter entirely. Behind a
trusted proxy you must configure that proxy's address explicitly — which is
<strong>not implemented</strong>.`)}

<h2 id="limitations">What this does not do</h2>
<p>Stated plainly, because a limiter presented as stronger than it is produces false confidence.</p>
<ul>
  <li><strong>Fixed windows permit a burst.</strong> A client can send the full
      allowance at the end of one window and again at the start of the next,
      briefly achieving twice the intended rate. A sliding window or token
      bucket avoids this.</li>
  <li><strong>In-memory and per-process.</strong> It resets on restart and does
      not coordinate across instances. Anything facing the real internet needs
      a shared store.</li>
  <li><strong>Not a defence against a distributed attacker.</strong> It
      addresses casual abuse and runaway clients.</li>
</ul>
<p>
  The buckets are evicted once the map exceeds a thousand entries, so the
  limiter cannot itself become a memory-exhaustion vector — a defence becoming
  the vulnerability is a common enough pattern to guard against explicitly.
</p>`,
  },

  // ══════════════════════════════════════════════ GUIDES
  {
    slug: "guide-receive",
    group: "Guides",
    title: "Guide: receive bitcoin",
    lede: "Get an address, understand the gap limit, and see the funds arrive.",
    body: `
<h2 id="get">Get the current address</h2>
${code("http", `GET /wallet/address`)}
${code("json", `{
  <span class="tok-key">"address"</span>: <span class="tok-str">"bcrt1qcl3pgzqcez3wwyp8n4am48qt55y99n6lk439d8"</span>,
  <span class="tok-key">"path"</span>: <span class="tok-str">"m/84'/1'/0'/0/0"</span>,
  <span class="tok-key">"network"</span>: <span class="tok-str">"regtest"</span>
}`)}
<p>Stable until you advance it. Calling repeatedly returns the same address.</p>

<h2 id="fresh">Advance to a fresh one</h2>
${code("http", `POST /wallet/address/next`)}
<p>
  A fresh address per payment stops an observer linking your payments to one
  another. It is the cheapest privacy measure available and it costs nothing.
</p>

<h2 id="gap">The gap limit will stop you at 20</h2>
${note("warning", `<strong>Requesting a 21st unused address returns 422.</strong>
This is not a quota — it is protection. A wallet restored from a mnemonic
scans forward until it sees 20 consecutive unused addresses, then stops. Funds
received beyond that point are <em>not lost</em>, but no standard wallet will
find them on restore, and the user will conclude their money is gone.`)}

<h2 id="verify">Verify the address before sharing it</h2>
<p>
  The last six characters of a Bech32 address are a BCH checksum with a proven
  bound: <strong>any four or fewer mistyped characters are guaranteed to be
  caught</strong>, and longer errors escape with probability around one in a
  billion.
</p>
${code("text", `bcrt1  qcl3pgzqcez3wwyp8n4am48qt55y99n6l  k439d8
─────  ────────────────────────────────  ──────
HRP    witness program                    checksum`)}
<p>Veyra's interface renders that final group underlined, because it is the part that protects the recipient.</p>

<h2 id="watch">Watch it arrive</h2>
${code("http", `POST /wallet/sync
GET  /wallet/balance`)}
${code("json", `{ <span class="tok-key">"spendable"</span>: <span class="tok-str">"0"</span>, <span class="tok-key">"unconfirmed"</span>: <span class="tok-str">"1000000"</span>, <span class="tok-key">"utxoCount"</span>: <span class="tok-num">1</span> }`)}
<p>
  Zero-confirmation funds appear as <code>unconfirmed</code> and are
  <strong>not spendable</strong>. They can still vanish — replaced, evicted, or
  reorganised out. Mine or wait a block and sync again.
</p>`,
  },

  {
    slug: "guide-send",
    group: "Guides",
    title: "Guide: send bitcoin",
    lede: "Prepare, review, broadcast — and handle the four ways it can refuse.",
    body: `
<h2 id="prepare">1. Prepare</h2>
${code("http", `POST /transactions/prepare
{ "to": "bcrt1q...", "amount": "100000", "feeRate": 5 }`)}
<p>Builds and signs. <strong>Nothing is broadcast.</strong></p>

<h2 id="review">2. Show the review</h2>
${code("json", `{
  <span class="tok-key">"id"</span>: <span class="tok-str">"3f2a4c8e..."</span>,
  <span class="tok-key">"expiresAt"</span>: <span class="tok-str">"2026-08-20T12:34:56.000Z"</span>,
  <span class="tok-key">"amount"</span>: <span class="tok-str">"100000"</span>,
  <span class="tok-key">"fee"</span>: <span class="tok-str">"705"</span>,
  <span class="tok-key">"total"</span>: <span class="tok-str">"100705"</span>,
  <span class="tok-key">"remainingBalance"</span>: <span class="tok-str">"899295"</span>,
  <span class="tok-key">"change"</span>: <span class="tok-str">"899295"</span>,
  <span class="tok-key">"feeRate"</span>: <span class="tok-num">5</span>,
  <span class="tok-key">"vsize"</span>: <span class="tok-num">141</span>,
  <span class="tok-key">"txid"</span>: <span class="tok-str">"a1b2c3..."</span>
}`)}
${note("teal", `Show <strong>total</strong>, not just amount. It is the number
that leaves the wallet, and hiding the fee is how users are surprised.`)}

<h2 id="send">3. Broadcast by id</h2>
${code("http", `POST /transactions/send
{ "id": "3f2a4c8e..." }`)}
<p>No other field is accepted. The bytes were fixed at prepare time.</p>

<h2 id="refusals">The four refusals</h2>
<table>
  <tr><th>Response</th><th>Cause</th><th>What to tell the user</th></tr>
  <tr><td><code>422</code> insufficient funds</td><td>Amount plus fee exceeds spendable balance</td><td>Show spendable, not total — the difference is usually unconfirmed coins</td></tr>
  <tr><td><code>422</code> dust threshold</td><td>Amount below 294 sat</td><td>The network will not relay it</td></tr>
  <tr><td><code>422</code> invalid address</td><td>Wrong network, or a failed checksum</td><td>Re-paste; do not retype</td></tr>
  <tr><td><code>404</code> on send</td><td>Expired, cancelled, or already sent</td><td>Prepare again</td></tr>
</table>

<h2 id="fees">Choosing a fee rate</h2>
<table>
  <tr><th>Rate</th><th>Expectation</th></tr>
  <tr><td>1 sat/vB</td><td>The relay minimum. Below this it will not propagate at all.</td></tr>
  <tr><td>2 sat/vB</td><td>Hours to a day</td></tr>
  <tr><td>8 sat/vB</td><td>Within a few blocks</td></tr>
  <tr><td>20 sat/vB</td><td>Next block or two</td></tr>
</table>
${note("warning", `<strong>These are static figures, not live estimates.</strong>
Real estimation needs mempool data, which Veyra does not yet fetch. During
congestion they will be too low.`)}

<h2 id="rbf">Replace-by-fee is on</h2>
<p>
  Transactions are built with sequence <code>0xfffffffd</code>, signalling
  BIP-125. A transaction stuck at too low a fee can otherwise be unspendable
  for days with no recourse. (Fee bumping is not yet exposed as an endpoint.)
</p>

<h2 id="cancel">Cancelling</h2>
${code("http", `DELETE /transactions/{id}`)}
<p>Releases the held coins immediately rather than waiting for expiry. Nothing was broadcast, so there is nothing to undo.</p>`,
  },

  {
    slug: "guide-sync",
    group: "Guides",
    title: "Guide: sync with a chain",
    lede: "Discovering your own coins, and what it tells the server about you.",
    body: `
<h2 id="sources">Two sources</h2>
<table>
  <tr><th>Source</th><th>Configure</th><th>Privacy</th></tr>
  <tr><td>Bitcoin Core RPC</td><td><code>VEYRA_RPC_URL</code> + credentials</td><td><strong>Best.</strong> Your own node learns nothing you did not already know.</td></tr>
  <tr><td>Esplora HTTP</td><td><code>VEYRA_ESPLORA_URL</code></td><td>Poor unless self-hosted — see below.</td></tr>
</table>
<p>Neither is configured by default. Nothing contacts a third party unless you ask it to.</p>

<h2 id="scan">How the scan works</h2>
${code("http", `POST /wallet/sync`)}
${code("json", `{ <span class="tok-key">"utxos"</span>: <span class="tok-num">2</span>, <span class="tok-key">"addressesScanned"</span>: <span class="tok-num">46</span> }`)}
<p>
  Walks the receive chain, then the change chain, asking whether each address
  has ever been used, and stops after <strong>20 consecutive unused</strong>.
  It continues <em>past</em> a used address, so a gap in the middle is still
  found.
</p>
<p>
  This matches BIP-44 convention deliberately. Scanning differently from other
  wallets would find funds they report as missing, or miss funds they find —
  an interoperability failure that looks exactly like lost money.
</p>

<h2 id="privacy">The privacy cost of a public server</h2>
${note("danger", `<strong>A sync tells the server your entire wallet.</strong>
Every address you own, that they belong to one wallet, your balance, your full
history, and your IP address — in a single session. No cryptography prevents
this. It is inherent to asking someone else about your coins.`)}
<p>The blockchain is public. <em>Which addresses are yours</em> is not, and a light-wallet query hands over exactly that. Mitigations:</p>
<ul>
  <li>Run your own node or Esplora instance — removes the leak entirely.</li>
  <li>Tor — removes the IP linkage, not the address clustering.</li>
  <li>Compact block filters (BIP-157/158) — the client never reveals which addresses it cares about. Not implemented.</li>
</ul>
<p><code>GET /wallet/security</code> reports whether your configured source is third-party, and returns a warning string you should surface.</p>

<h2 id="limits">What sync cannot verify</h2>
<p>
  A source that <em>omits</em> a UTXO cannot be detected. The wallet simply
  looks poorer and produces an unexplained "insufficient funds". This is
  inherent to not running a full node.
</p>
<p>
  Note also that the Bitcoin Core source uses <code>scantxoutset</code>, which
  sees <strong>unspent outputs only</strong> — a fully-spent address looks
  unused, so the gap-limit scan may stop earlier against a node than against
  Esplora.
</p>`,
  },

  // ══════════════════════════════════════════════ REFERENCE
  {
    slug: "api-reference",
    group: "Reference",
    title: "API reference",
    lede: "Every endpoint, with a console that sends real requests to your API.",
    body: `
${CONSOLE}

<h2 id="health">Health</h2>
${endpoint({
  method: "GET",
  path: "/health",
  auth: false,
  summary: "Liveness",
  detail:
    "Reachable without authentication, so it deliberately reports nothing else. Version, network, or balance here would be free reconnaissance.",
  response: { status: "ok" },
})}

<h2 id="wallet">Wallet</h2>
${endpoint({
  method: "GET",
  path: "/wallet",
  summary: "Summary",
  response: {
    network: "regtest",
    derivationPath: "m/84'/1'/0'",
    fingerprint: "854f45e9",
    addressType: "P2WPKH (BIP-84)",
    gapLimit: 20,
  },
})}
${endpoint({
  method: "GET",
  path: "/wallet/address",
  summary: "Current receive address",
  response: { address: "bcrt1qcl3pgz…", path: "m/84'/1'/0'/0/0", network: "regtest" },
})}
${endpoint({
  method: "POST",
  path: "/wallet/address/next",
  summary: "Fresh receive address",
  detail: "Capped at the gap limit; the 21st unused address returns 422.",
  body: {},
  response: { address: "bcrt1q…", path: "m/84'/1'/0'/0/1", network: "regtest" },
})}
${endpoint({
  method: "GET",
  path: "/wallet/balance",
  summary: "Balance, broken into parts",
  detail:
    "Never one number. 'Your balance is X' when part of X is unconfirmed or frozen is a claim the user discovers is false when a send fails.",
  response: {
    total: "1500000",
    spendable: "1500000",
    unconfirmed: "0",
    unavailable: "0",
    utxoCount: 2,
  },
})}
${endpoint({
  method: "GET",
  path: "/wallet/utxos",
  summary: "Unspent outputs",
  detail:
    "Derivation paths are omitted. Not secret in the way a key is, but they describe wallet structure and the client has no use for them — signing happens server-side.",
  response: {
    utxos: [
      { txid: "11…11", vout: 0, value: "1000000", address: "bcrt1q…", confirmations: 6, frozen: false },
    ],
  },
})}
${endpoint({
  method: "GET",
  path: "/wallet/security",
  summary: "Security state",
  detail: "Verifiable facts and warnings. No score — a number like '92% secure' implies a measurement nobody performed.",
  response: {
    network: "regtest",
    isMainnet: false,
    walletType: "self-custodial HD (BIP-84)",
    keysHeldBy: "this server process, in memory only",
    chainSource: null,
    chainSourceIsThirdParty: null,
    privacyWarning: null,
    pendingTransactions: 0,
    warnings: ["Private keys are held in this process's memory. …"],
  },
})}
${endpoint({
  method: "POST",
  path: "/wallet/sync",
  summary: "Rescan from the chain source",
  detail: "Returns 422 if no chain source is configured.",
  body: {},
  response: { utxos: 2, addressesScanned: 46 },
})}

<h2 id="transactions">Transactions</h2>
${note("teal", `<strong>Two steps, and the second takes only an id.</strong>
<code>send</code> cannot rebuild the transaction — see
<a href="transaction-lifecycle.html">Transaction lifecycle</a>.`)}
${endpoint({
  method: "POST",
  path: "/transactions/prepare",
  summary: "Build and sign; nothing is broadcast",
  detail:
    "Every spending guard runs before a signature exists: address validity for this network, the dust threshold, sufficient funds, and a fee-sanity ceiling.",
  fields: [
    ["to", "string", "Destination address. Must match this wallet's network."],
    ["amount", "string | number", "Satoshis. Must exceed the 294 sat dust threshold."],
    ["feeRate", "number", "sat/vB, between 1 and 10000."],
    ["strategy", "string?", "branch-and-bound · single-random-draw · largest-first"],
  ],
  body: { to: "bcrt1q…", amount: "100000", feeRate: 5 },
  response: {
    id: "3f2a4c8e…",
    expiresAt: "2026-08-20T12:34:56.000Z",
    recipient: "bcrt1q…",
    amount: "100000",
    fee: "705",
    total: "100705",
    change: "899295",
    remainingBalance: "899295",
    feeRate: 5,
    vsize: 141,
    inputCount: 1,
    txid: "a1b2c3…",
  },
})}
${endpoint({
  method: "POST",
  path: "/transactions/send",
  summary: "Broadcast by id",
  detail:
    "The id is consumed before the network call, so a retry after a timeout cannot double-broadcast.",
  fields: [["id", "string", "From prepare. 32 hex characters."]],
  body: { id: "3f2a4c8e…" },
  response: { txid: "a1b2c3…", broadcast: true },
})}
${endpoint({
  method: "GET",
  path: "/transactions/{id}",
  summary: "Re-read a pending review",
  detail: "Identical 404 whether the id never existed, expired, or was already sent.",
  response: { id: "3f2a4c8e…", amount: "100000", fee: "705", total: "100705" },
})}
${endpoint({
  method: "DELETE",
  path: "/transactions/{id}",
  summary: "Cancel before sending",
  detail: "Releases the held coins. Nothing was broadcast, so there is nothing to undo.",
  response: { cancelled: true },
})}`,
  },

  {
    slug: "changelog",
    group: "Reference",
    title: "Changelog",
    lede: "What was built, in order, and what is still missing.",
    body: `
${note("warning", `<strong>Pre-release.</strong> No version is published, no
endpoint is stable, and no compatibility is promised. The one thing that will
not change is that no endpoint will ever return key material.`)}

${note("teal", `<strong>2026-08-20 — consensus verified.</strong> Bitcoin Core
accepted a transaction built and signed by this code, and computed the same
txid for it.`)}

<h2 id="unreleased">Unreleased</h2>
<h3>Added</h3>
<ul>
  <li><strong>Taproot (BIP-86 / BIP-341)</strong> — P2TR addresses matching all three published BIP-86 vectors, and Schnorr key-path signing. The sighash commits to <em>every</em> input's amount and script, closing a gap BIP-143 leaves open.</li>
  <li><strong>RBF fee bumping</strong> — <code>POST /transactions/bump</code> replaces a stuck transaction, taking the extra fee from change and enforcing BIP-125 rules 2, 3 and 4 locally so the network's rejection message is never the first sign of a problem.</li>
  <li><strong>Transaction history</strong> — <code>GET /transactions</code>, with direction and net value, folded so a send and its change are one entry.</li>
  <li><strong>Live fee estimation</strong> — <code>GET /wallet/fees</code>, from <code>estimatesmartfee</code> or Esplora, with an <code>isLive</code> flag so a static fallback is never mistaken for a network rate.</li>
  <li>Documentation site with a live request console.</li>
  <li>CORS with an explicit origin allowlist.</li>
  <li>Wallet interface: balance, receive, send flow, and security centre.</li>
  <li>HTTP API with 63 security tests covering every §21 attack category.</li>
  <li>Bitcoin Core RPC chain source and a regtest integration suite.</li>
  <li>Esplora chain source with defensive response validation.</li>
  <li>Wallet layer: gap-limit scan, coin selection, fee estimation, spending guards.</li>
  <li>Transactions: BIP-143 sighash, ECDSA with RFC 6979, low-S enforcement.</li>
  <li>BIP-39 mnemonics, BIP-32 derivation, BIP-84 addresses, Bech32/Bech32m.</li>
  <li>Entropy, hashing, and key generation with source-tree security guards.</li>
</ul>

<h3>Fixed</h3>
<p>Nine defects are recorded in <code>docs/ATTACKS.md</code> with root cause, fix, and lesson. Three were found by running on hardware and a runtime unlike the author's:</p>
<ul>
  <li><strong>VEY-001</strong> — a security guard silently stopped guarding on Windows, passing vacuously.</li>
  <li><strong>VEY-008</strong> — the API was unreachable from any browser; 55 tests missed it because Node's <code>fetch</code> does not enforce CORS.</li>
  <li><strong>VEY-009</strong> — a test asserted wall-clock time, so it measured the machine rather than the code.</li>
  <li><strong>VEY-012</strong> — a Taproot address encoder accepted non-32-byte output keys, which under current consensus are spendable by anyone.</li>
  <li><strong>VEY-011</strong> — float arithmetic overcharged fee estimates by up to 100%: <code>(0.00002 * 1e8) / 1000</code> is 2.0000000000000004, which <code>Math.ceil</code> makes 3.</li>
</ul>

<h2 id="verified">Consensus verification — 2026-08-20</h2>
${note("teal", `<strong>Bitcoin Core accepted a Veyra transaction.</strong>
All 10 regtest integration tests passed against Bitcoin Core v29: Core accepted
a transaction Veyra built and signed, computed an identical txid, rejected a
tampered recipient, and confirmed change is spendable and a restored mnemonic
finds real funds.`)}
<p>
  This was the last open item. Every other test in the project validates
  against the specification as read; this one validates against the
  implementation that defines it. Reproduce with <code>npm run test:regtest</code>.
</p>

<h2 id="missing">Not yet built</h2>
<table>
  <tr><th>Missing</th><th>Consequence</th></tr>
  <tr><td>Fee-bump persistence</td><td>Replaceable transactions are remembered in memory only; a restart loses the ability to bump them.</td></tr>
  <tr><td>TLS</td><td>Plain HTTP; needs a reverse proxy beyond localhost.</td></tr>
  <tr><td>Lightning</td><td>Not started. Will not be claimed until real infrastructure exists.</td></tr>
</table>

<h2 id="verification">Verification status</h2>
<table>
  <tr><th>Component</th><th>Verified against</th></tr>
  <tr><td>SHA-256</td><td>NIST FIPS 180-4 vectors</td></tr>
  <tr><td>BIP-39</td><td>Trezor reference vectors</td></tr>
  <tr><td>BIP-32</td><td>Published vectors 1–3, including the leading-zero case</td></tr>
  <tr><td>BIP-84</td><td>Published mainnet addresses</td></tr>
  <tr><td>Bech32 / Bech32m</td><td>BIP-173 and BIP-350, valid <em>and invalid</em> vectors</td></tr>
  <tr><td>BIP-143</td><td>Official native-P2WPKH sighash</td></tr>
  <tr><td><strong>Consensus</strong></td><td><strong>✅ Bitcoin Core v29, regtest, 2026-08-20</strong></td></tr>
  <tr><td>Esplora client</td><td>Not verified against a live server</td></tr>
  <tr><td>Mainnet</td><td>Never exercised end to end</td></tr>
</table>`,
  },
];
