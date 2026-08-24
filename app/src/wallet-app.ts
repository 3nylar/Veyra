/**
 * VEYRA — SINGLE-PAGE BROWSER WALLET
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  WHAT THIS IS, AND WHAT SECURES IT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A self-custodial wallet anyone can open and use. Keys are generated in the
 * browser, encrypted with a passphrase, stored locally, and never transmitted.
 * There is no account, no server holding funds, and no signup.
 *
 * This holds keys AND reaches the network — the combination the two-file
 * air-gapped setup deliberately avoids. That is a real trade-off, made because
 * a wallet requiring a second machine is a wallet nobody uses. Four things
 * make it defensible:
 *
 *   1. **A PINNED `connect-src`.** The CSP names the exact chain endpoints
 *      this page may contact. Injected script cannot POST a seed to an
 *      attacker's server — the browser refuses the request. This is the
 *      single most important control here.
 *
 *   2. **No third-party code.** No CDN, no analytics, no fonts, no tag
 *      manager. Every byte ships in one file, so there is no upstream to
 *      compromise.
 *
 *   3. **Encrypted at rest.** The seed in localStorage is scrypt + AES-256-GCM.
 *      Reading the storage without the passphrase yields nothing.
 *
 *   4. **Auto-lock.** The decrypted seed is discarded after inactivity,
 *      shortening the window in which a memory read succeeds.
 *
 * ─── What this cannot do ───────────────────────────────────────────────────
 * It cannot protect against a compromised browser, a malicious extension with
 * page access, or malware reading process memory. A hardware wallet keeps the
 * key in a chip that never exposes it; a browser cannot. Anyone holding more
 * than they would shrug at losing should use `veyra-sign.html` on an offline
 * machine instead — that path still exists and is documented.
 */

import { Wallet } from "../../core/wallet/wallet.js";
import { generateMnemonic, validateMnemonic } from "../../core/mnemonic/index.js";
import { EsploraChainSource } from "../../core/chain/esplora.js";
import { networkByName, type Network } from "../../core/bitcoin/networks.js";
import { encryptMnemonic, decryptMnemonic, type EncryptedKeystore } from "../../core/wallet/keystore.js";
import type { PreparedTransaction } from "../../core/wallet/wallet.js";
import type { ChainTransaction } from "../../core/chain/types.js";

// ── Storage ───────────────────────────────────────────────────────────────
/**
 * The encrypted keystore lives in localStorage.
 *
 * ⚠️ Deliberate and worth understanding: localStorage is readable by any
 * script on this origin. That is acceptable ONLY because what is stored is
 * ciphertext — scrypt at N=2^17 makes offline guessing expensive, and the
 * plaintext seed is never written anywhere.
 *
 * The *decrypted* seed lives in a module-scoped variable and is dropped on
 * lock. It is never persisted.
 */
const STORE_KEY = "veyra.keystore.v1";
const PREFS_KEY = "veyra.prefs.v1";
const AUTO_LOCK_MS = 10 * 60 * 1000;

interface Prefs {
  network: string;
  esplora: string;
}

const ESPLORA: Record<string, string> = {
  mainnet: "https://blockstream.info/api",
  testnet: "https://blockstream.info/testnet/api",
  signet: "https://mempool.space/signet/api",
  regtest: "http://127.0.0.1:3002",
};

function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (raw) return JSON.parse(raw) as Prefs;
  } catch { /* corrupt prefs are not worth failing over */ }
  return { network: "signet", esplora: ESPLORA.signet! };
}

function savePrefs(prefs: Prefs) {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch { /* private mode */ }
}

const hasKeystore = () => localStorage.getItem(STORE_KEY) !== null;
const readKeystore = (): EncryptedKeystore | null => {
  const raw = localStorage.getItem(STORE_KEY);
  return raw ? (JSON.parse(raw) as EncryptedKeystore) : null;
};

// ── State ─────────────────────────────────────────────────────────────────
let wallet: Wallet | null = null;
let chain: EsploraChainSource | null = null;
let prefs = loadPrefs();
let screen: "home" | "receive" | "send" | "settings" = "home";
let history: ChainTransaction[] = [];
let prepared: PreparedTransaction | null = null;
let lockTimer: ReturnType<typeof setTimeout> | null = null;
let busy = false;

function touch() {
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, AUTO_LOCK_MS);
}

function lock() {
  wallet = null;
  history = [];
  prepared = null;
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = null;
  render();
}

// ── Formatting ────────────────────────────────────────────────────────────
const fmtBtc = (sats: bigint): string => {
  const neg = sats < 0n;
  const abs = neg ? -sats : sats;
  const whole = abs / 100_000_000n;
  const frac = (abs % 100_000_000n).toString().padStart(8, "0");
  return `${neg ? "-" : ""}${whole.toLocaleString("en-US")}.${frac}`;
};

/** Exact BTC → satoshis. Never parseFloat — see docs/ATTACKS.md VEY-011. */
function parseBtc(input: string): bigint {
  const t = input.trim();
  if (!/^\d*\.?\d*$/.test(t) || t === "" || t === ".") throw new Error("Enter a number");
  const [whole = "0", frac = ""] = t.split(".");
  if (frac.length > 8) throw new Error("Bitcoin has 8 decimal places");
  return BigInt(whole || "0") * 100_000_000n + BigInt((frac + "00000000").slice(0, 8));
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/**
 * Render an address with its Bech32 checksum distinguished.
 *
 * The final six characters are a BCH code that provably catches any four or
 * fewer mistyped characters. It is the part that protects the recipient, and
 * no other wallet shows it.
 */
function addr(address: string): string {
  const sep = address.lastIndexOf("1");
  if (sep < 1 || address.length < sep + 7) return esc(address);
  return `<span class="hrp">${esc(address.slice(0, sep + 1))}</span>${esc(
    address.slice(sep + 1, -6),
  )}<span class="sum">${esc(address.slice(-6))}</span>`;
}

const short = (s: string) => (s.length <= 20 ? s : `${s.slice(0, 10)}…${s.slice(-8)}`);

// ── QR (minimal, no dependency) ───────────────────────────────────────────
/**
 * A QR encoder would be ~15 KB of dependency for one screen. Instead the
 * address is shown as text with the checksum highlighted, plus a copy button.
 * Copy-paste is what people actually do, and it cannot introduce a typo —
 * which is the failure a QR code exists to prevent.
 */

// ── Rendering ─────────────────────────────────────────────────────────────
const root = () => document.getElementById("root")!;

function render() {
  const network = networkByName(prefs.network);
  if (!hasKeystore()) return renderOnboard(network);
  if (!wallet) return renderUnlock(network);
  renderApp(network);
}

function shell(network: Network | null, body: string, nav = false): string {
  return `
    <div class="shell">
      <header class="topbar">
        <h1 class="wordmark">Veyra</h1>
        ${network ? `<span class="chip" data-mainnet="${network.isMainnet}">${network.name}</span>` : ""}
      </header>
      <main>${body}</main>
    </div>
    ${nav ? `
      <nav class="nav">
        ${(["home", "receive", "send", "settings"] as const)
          .map(
            (s) =>
              `<button data-nav="${s}" aria-current="${screen === s}">${
                s === "home" ? "Wallet" : s[0]!.toUpperCase() + s.slice(1)
              }</button>`,
          )
          .join("")}
      </nav>` : ""}`;
}

// ── Onboarding ────────────────────────────────────────────────────────────
let draftMnemonic: string | null = null;

function renderOnboard(network: Network) {
  root().innerHTML = shell(network, `
    <div class="notice" data-t="info">
      A self-custodial wallet that runs entirely in this browser. No account, no
      signup, and no server holds your coins. <strong>You are the only one who
      can recover this wallet</strong> — if you lose the recovery phrase, the
      coins are gone permanently.
    </div>
    <div class="card">
      <p class="label">Create a wallet</p>
      <p style="margin-top:0;color:var(--muted);font-size:13.5px">
        Generates 12 words from your device's secure random number generator.
      </p>
      <div class="btn-row" style="margin-top:16px">
        <button class="primary" data-act="create">Create new wallet</button>
      </div>
    </div>
    <div class="card">
      <p class="label">Restore</p>
      <label class="f"><span>Recovery phrase (12 or 24 words)</span>
        <textarea id="restorePhrase" spellcheck="false" placeholder="word word word…"></textarea></label>
      <button data-act="restore">Restore wallet</button>
      <p class="status" id="onboardStatus"></p>
    </div>`);
}

function renderBackup(network: Network, mnemonic: string) {
  const words = mnemonic.split(" ");
  root().innerHTML = shell(network, `
    <div class="steps"><span class="on">Back up</span><span>/</span><span>Confirm</span><span>/</span><span>Encrypt</span></div>
    <div class="notice" data-t="danger">
      <strong>Write these down on paper, in order.</strong> Not a screenshot,
      not a text file. This is the only way to recover your coins. Anyone who
      sees it can take them.
    </div>
    <div class="card">
      <p class="label">Your recovery phrase</p>
      <div class="words">
        ${words.map((w, i) => `<div class="word"><b>${i + 1}</b>${esc(w)}</div>`).join("")}
      </div>
      <div class="btn-row">
        <button class="primary" data-act="backed-up">I've written it down</button>
      </div>
    </div>`);
}

function renderConfirm(network: Network, mnemonic: string) {
  // Confirming three random words is enough to catch someone who skipped the
  // step entirely, without being so tedious they copy-paste from the screen.
  const words = mnemonic.split(" ");
  const picks = [...words.keys()].sort(() => Math.random() - 0.5).slice(0, 3).sort((a, b) => a - b);

  root().innerHTML = shell(network, `
    <div class="steps"><span class="done">Back up</span><span>/</span><span class="on">Confirm</span><span>/</span><span>Encrypt</span></div>
    <div class="card">
      <p class="label">Confirm your backup</p>
      <p style="margin-top:0;color:var(--muted);font-size:13.5px">Enter these words from your phrase.</p>
      ${picks.map((i) => `<label class="f"><span>Word ${i + 1}</span>
        <input data-confirm="${i}" spellcheck="false" autocomplete="off" /></label>`).join("")}
      <div class="btn-row">
        <button class="ghost" data-act="show-again">Show phrase again</button>
        <button class="primary" data-act="confirmed">Confirm</button>
      </div>
      <p class="err hidden" id="confirmErr">Those don't match. Check your written copy.</p>
    </div>`);
}

function renderEncrypt(network: Network) {
  root().innerHTML = shell(network, `
    <div class="steps"><span class="done">Back up</span><span>/</span><span class="done">Confirm</span><span>/</span><span class="on">Encrypt</span></div>
    <div class="card">
      <p class="label">Set a passphrase</p>
      <p style="margin-top:0;color:var(--muted);font-size:13.5px">
        Encrypts your phrase before it is stored in this browser. It is not a
        second factor and it is not recoverable — if you forget it, restore from
        your written phrase instead.
      </p>
      <label class="f"><span>Passphrase (8+ characters)</span>
        <input id="pass1" type="password" autocomplete="new-password" /></label>
      <label class="f"><span>Repeat</span>
        <input id="pass2" type="password" autocomplete="new-password" /></label>
      <button class="commit" data-act="encrypt">Encrypt and finish</button>
      <p class="status" id="encryptStatus"></p>
    </div>`);
}

function renderUnlock(network: Network) {
  root().innerHTML = shell(network, `
    <div class="card">
      <p class="label">Unlock</p>
      <label class="f"><span>Passphrase</span>
        <input id="unlockPass" type="password" autocomplete="current-password" /></label>
      <button class="commit" data-act="unlock">Unlock</button>
      <p class="status" id="unlockStatus"></p>
    </div>
    <button class="ghost" data-act="forget-wallet">Remove this wallet from the browser</button>`);
  setTimeout(() => document.getElementById("unlockPass")?.focus(), 50);
}

// ── Main app ──────────────────────────────────────────────────────────────
function renderApp(network: Network) {
  const body =
    screen === "home" ? viewHome()
    : screen === "receive" ? viewReceive()
    : screen === "send" ? viewSend()
    : viewSettings(network);
  root().innerHTML = shell(network, body, true);
}

function viewHome(): string {
  const balance = wallet!.balance();
  return `
    ${networkByName(prefs.network).isMainnet ? `
      <div class="notice" data-t="danger"><strong>Mainnet.</strong> These are real
      bitcoin and transactions cannot be reversed.</div>` : ""}
    <div class="card">
      <p class="label">Spendable balance</p>
      <p class="balance">${fmtBtc(balance.spendable)}<small>BTC</small></p>
      <p class="sats">${balance.spendable.toLocaleString("en-US")} sat</p>
      <div class="breakdown">
        <div class="bk"><span>Total</span><span>${fmtBtc(balance.total)}</span></div>
        ${balance.unconfirmed > 0n ? `<div class="bk"><span>Unconfirmed</span><span style="color:var(--warning)">${fmtBtc(balance.unconfirmed)}</span></div>` : ""}
        <div class="bk"><span>Coins</span><span>${balance.utxoCount}</span></div>
      </div>
      <div style="height:16px"></div>
      <div class="btn-row">
        <button class="primary" data-nav="send" ${balance.spendable === 0n ? "disabled" : ""}>Send</button>
        <button data-nav="receive">Receive</button>
      </div>
    </div>
    <div class="card">
      <p class="label">Activity</p>
      ${history.length === 0
        ? `<p class="empty">No transactions yet.</p>`
        : history.slice(0, 15).map((tx) => {
            const v = tx.netValue ?? 0n;
            const sent = v < 0n;
            const internal = tx.direction === "internal";
            return `<div class="item">
              <div style="min-width:0">
                <div class="id">${esc(short(tx.txid))}</div>
                <div class="meta">${internal ? "Moved internally" : sent ? "Sent" : "Received"} · ${
                  tx.confirmations === 0 ? "Unconfirmed" : `${tx.confirmations} conf`
                }</div>
              </div>
              <span class="amt" style="color:${internal ? "var(--muted)" : sent ? "var(--text)" : "var(--teal)"}">
                ${internal ? "" : sent ? "−" : "+"}${fmtBtc(v < 0n ? -v : v)}</span>
            </div>`;
          }).join("")}
      <div style="height:16px"></div>
      <div class="btn-row"><button data-act="sync" ${busy ? "disabled" : ""}>${busy ? "Syncing…" : "Sync"}</button></div>
      <p class="status" id="syncStatus"></p>
    </div>`;
}

function viewReceive(): string {
  const derived = wallet!.currentReceiveAddress();
  const network = networkByName(prefs.network);
  return `
    <div class="notice" data-t="${network.isMainnet ? "danger" : "info"}">
      ${network.isMainnet
        ? "This is a <strong>mainnet</strong> address. Bitcoin sent here is real."
        : `This is a <strong>${network.name}</strong> address. Coins on this network have no value.`}
    </div>
    <div class="card">
      <p class="label">Receive</p>
      <div class="addr">${addr(derived.address)}</div>
      <p class="hint">The underlined last six characters are a checksum. They
        catch any four or fewer mistyped characters, so a typo cannot quietly
        send bitcoin somewhere else.</p>
      <div style="height:16px"></div>
      <div class="btn-row">
        <button class="primary" data-act="copy-addr">Copy address</button>
        <button data-act="next-addr">New address</button>
      </div>
      <p class="status" id="receiveStatus">${esc(derived.path)}</p>
    </div>`;
}

function viewSend(): string {
  if (prepared) {
    return `
      <div class="steps"><span class="done">Compose</span><span>/</span><span class="on">Review</span></div>
      <div class="card">
        <p class="label">To</p>
        <div class="addr">${addr(prepared.recipient)}</div>
        <div style="height:16px"></div>
        <div class="row"><span class="k">Amount</span><span class="v">${fmtBtc(prepared.amount)} BTC</span></div>
        <div class="row"><span class="k">Network fee</span><span class="v">${fmtBtc(prepared.fee)} BTC</span></div>
        <div class="row" data-total><span class="k">Total</span><span class="v">${fmtBtc(prepared.total)} BTC</span></div>
        <div class="row"><span class="k">Remaining</span><span class="v" style="color:var(--muted)">${fmtBtc(prepared.remainingBalance)} BTC</span></div>
      </div>
      <div class="card">
        <p class="label">What will be broadcast</p>
        <div class="row"><span class="k">Transaction id</span><span class="v">${esc(prepared.txid)}</span></div>
        <div class="row"><span class="k">Inputs</span><span class="v">${prepared.inputs.length}</span></div>
        <div class="row"><span class="k">Size</span><span class="v">${prepared.vsize} vB at ${prepared.feeRate.toFixed(1)} sat/vB</span></div>
      </div>
      <div class="notice" data-t="info">
        This transaction is already built and signed. Confirming broadcasts
        exactly these bytes — nothing above can change.
      </div>
      <button class="commit" data-act="broadcast" ${busy ? "disabled" : ""}>${busy ? "Broadcasting…" : "Confirm and send"}</button>
      <div style="height:12px"></div>
      <button class="ghost" data-act="cancel-send">← Change something</button>
      <p class="status" id="sendStatus"></p>`;
  }

  return `
    <div class="steps"><span class="on">Compose</span><span>/</span><span>Review</span></div>
    <div class="card">
      <p class="label">Send bitcoin</p>
      <label class="f"><span>Recipient address</span>
        <input id="to" spellcheck="false" autocomplete="off" placeholder="tb1q…" />
        <span class="hint">Paste it. Typing by hand risks an error.</span></label>
      <label class="f"><span>Amount in BTC</span>
        <input id="amount" inputmode="decimal" spellcheck="false" autocomplete="off" placeholder="0.00000000" />
        <span class="hint">Spendable: ${fmtBtc(wallet!.balance().spendable)} BTC</span></label>
      <label class="f"><span>Fee rate (sat/vB)</span>
        <input id="feeRate" inputmode="numeric" spellcheck="false" value="5" />
        <span class="hint">Static estimate, not a live network rate.</span></label>
      <button class="primary" data-act="review">Review</button>
      <p class="status" id="sendStatus"></p>
    </div>`;
}

function viewSettings(network: Network): string {
  return `
    <div class="card">
      <p class="label">Network</p>
      <label class="f"><span>Chain</span>
        <select id="network">
          ${["signet", "testnet", "mainnet", "regtest"].map(
            (n) => `<option value="${n}" ${n === prefs.network ? "selected" : ""}>${n}</option>`,
          ).join("")}
        </select></label>
      <label class="f"><span>Chain source (Esplora)</span>
        <input id="esplora" spellcheck="false" value="${esc(prefs.esplora)}" />
        <span class="hint">Must be one of the origins allowed by this page's
          security policy. Adding others requires rebuilding it.</span></label>
      <button class="primary" data-act="save-network">Save and reload wallet</button>
      <p class="status" id="settingsStatus"></p>
    </div>
    <div class="card">
      <p class="label">Security</p>
      <div class="row"><span class="k">Wallet type</span><span class="v">Self-custodial (BIP-84)</span></div>
      <div class="row"><span class="k">Keys held by</span><span class="v">This browser only</span></div>
      <div class="row"><span class="k">Stored as</span><span class="v">scrypt + AES-256-GCM</span></div>
      <div class="row"><span class="k">Path</span><span class="v">${esc(wallet!.account.path)}</span></div>
      <div class="row"><span class="k">Auto-lock</span><span class="v">10 minutes</span></div>
      <div class="row"><span class="k">Recoverable by us</span><span class="v" style="color:var(--danger)">No</span></div>
      <p class="hint" style="margin-top:12px">
        Nobody can restore this wallet from anything but your recovery phrase.
        There is no account and no support desk that can help.
      </p>
    </div>
    <div class="card">
      <p class="label">Privacy</p>
      <p style="margin-top:0;font-size:13.5px;color:var(--muted)">
        ${chain?.isThirdParty
          ? `<strong>${esc(new URL(prefs.esplora).host)}</strong> can see every address in this wallet,
             that they belong to one wallet, your balance, your full history, and your IP address.
             Running your own Esplora removes this entirely.`
          : "You are using a local chain source, so nothing about this wallet leaves your machine."}
      </p>
    </div>
    <div class="card">
      <p class="label">Danger</p>
      <button data-act="lock">Lock now</button>
      <div style="height:8px"></div>
      <button data-act="forget-wallet" style="border-color:var(--danger);color:var(--danger)">
        Remove wallet from this browser</button>
      <p class="hint">Removing only deletes the local copy. Your recovery phrase still controls the coins.</p>
    </div>`;
}

// ── Actions ───────────────────────────────────────────────────────────────
function setStatus(id: string, message: string, tone: "" | "ok" | "danger" = "") {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = message;
  element.style.color =
    tone === "ok" ? "var(--teal)" : tone === "danger" ? "var(--danger)" : "var(--muted)";
}

function connectChain(network: Network) {
  chain = new EsploraChainSource({ baseUrl: prefs.esplora, network: network.name });
}

async function refresh() {
  if (!wallet || !chain || busy) return;
  busy = true;
  render();
  try {
    await wallet.sync(chain);
    try { history = await wallet.history(chain, { limit: 25 }); } catch { history = []; }
    busy = false;
    render();
    setStatus("syncStatus", "Up to date.", "ok");
  } catch (error) {
    busy = false;
    render();
    setStatus("syncStatus", (error as Error).message, "danger");
  }
}

async function unlockWith(passphrase: string) {
  const store = readKeystore();
  if (!store) return;
  setStatus("unlockStatus", "Unlocking…");
  try {
    // scrypt at N=2^17 takes about a second. That cost is the defence.
    const mnemonic = await decryptMnemonic(store, passphrase);
    const network = networkByName(prefs.network);
    wallet = Wallet.restore(mnemonic, network);
    connectChain(network);
    touch();
    screen = "home";
    render();
    void refresh();
  } catch (error) {
    setStatus("unlockStatus", (error as Error).message, "danger");
  }
}

document.addEventListener("click", async (event) => {
  const target = (event.target as HTMLElement).closest("[data-act],[data-nav]") as HTMLElement | null;
  if (!target) return;
  touch();

  const nav = target.dataset.nav;
  if (nav) {
    screen = nav as typeof screen;
    if (nav !== "send") prepared = null;
    return render();
  }

  const network = networkByName(prefs.network);

  switch (target.dataset.act) {
    case "create": {
      draftMnemonic = generateMnemonic(12);
      return renderBackup(network, draftMnemonic);
    }
    case "restore": {
      const phrase = (document.getElementById("restorePhrase") as HTMLTextAreaElement).value
        .trim().replace(/\s+/g, " ").toLowerCase();
      if (!validateMnemonic(phrase)) {
        return setStatus("onboardStatus", "That phrase fails its checksum — check for mistyped words.", "danger");
      }
      draftMnemonic = phrase;
      return renderEncrypt(network);
    }
    case "backed-up": return renderConfirm(network, draftMnemonic!);
    case "show-again": return renderBackup(network, draftMnemonic!);
    case "confirmed": {
      const words = draftMnemonic!.split(" ");
      const inputs = [...document.querySelectorAll<HTMLInputElement>("[data-confirm]")];
      const ok = inputs.every(
        (input) => input.value.trim().toLowerCase() === words[Number(input.dataset.confirm)],
      );
      if (!ok) return document.getElementById("confirmErr")!.classList.remove("hidden");
      return renderEncrypt(network);
    }
    case "encrypt": {
      const a = (document.getElementById("pass1") as HTMLInputElement).value;
      const b = (document.getElementById("pass2") as HTMLInputElement).value;
      if (a !== b) return setStatus("encryptStatus", "Passphrases do not match.", "danger");
      setStatus("encryptStatus", "Encrypting… this takes a second by design.");
      try {
        const store = await encryptMnemonic(draftMnemonic!, a, { network: network.name });
        localStorage.setItem(STORE_KEY, JSON.stringify(store));
        const mnemonic = draftMnemonic!;
        draftMnemonic = null;
        wallet = Wallet.restore(mnemonic, network);
        connectChain(network);
        touch();
        screen = "home";
        render();
        return void refresh();
      } catch (error) {
        return setStatus("encryptStatus", (error as Error).message, "danger");
      }
    }
    case "unlock":
      return unlockWith((document.getElementById("unlockPass") as HTMLInputElement).value);
    case "lock": return lock();
    case "forget-wallet": {
      if (!confirm("Remove this wallet from the browser? You can only get it back with your recovery phrase.")) return;
      localStorage.removeItem(STORE_KEY);
      lock();
      return;
    }
    case "sync": return void refresh();
    case "copy-addr": {
      await navigator.clipboard.writeText(wallet!.currentReceiveAddress().address);
      return setStatus("receiveStatus", "Copied.", "ok");
    }
    case "next-addr": {
      try { wallet!.nextReceiveAddress(); render(); }
      catch (error) { setStatus("receiveStatus", (error as Error).message, "danger"); }
      return;
    }
    case "review": {
      try {
        prepared = wallet!.send({
          to: (document.getElementById("to") as HTMLInputElement).value.trim(),
          amount: parseBtc((document.getElementById("amount") as HTMLInputElement).value),
          feeRate: Number((document.getElementById("feeRate") as HTMLInputElement).value),
        });
        return render();
      } catch (error) {
        return setStatus("sendStatus", (error as Error).message, "danger");
      }
    }
    case "cancel-send": { prepared = null; return render(); }
    case "broadcast": {
      if (!prepared || busy) return;
      busy = true; render();
      try {
        const txid = await wallet!.broadcast(chain!, prepared);
        prepared = null; busy = false; screen = "home";
        render();
        setStatus("syncStatus", `Sent. ${txid}`, "ok");
        return void refresh();
      } catch (error) {
        busy = false; render();
        return setStatus("sendStatus", (error as Error).message, "danger");
      }
    }
    case "save-network": {
      prefs = {
        network: (document.getElementById("network") as HTMLSelectElement).value,
        esplora: (document.getElementById("esplora") as HTMLInputElement).value.trim(),
      };
      savePrefs(prefs);
      // The wallet must be re-derived: a different network is a different
      // coin type, therefore an entirely different key tree.
      lock();
      return;
    }
  }
});

// Changing the network preset updates the endpoint, so a user does not end up
// pointed at a testnet server while believing they are on mainnet.
document.addEventListener("change", (event) => {
  const target = event.target as HTMLElement;
  if (target.id === "network") {
    const chosen = (target as HTMLSelectElement).value;
    const field = document.getElementById("esplora") as HTMLInputElement | null;
    if (field) field.value = ESPLORA[chosen] ?? "";
  }
});

document.addEventListener("keydown", (event) => {
  touch();
  if (event.key === "Enter") {
    const active = document.activeElement as HTMLElement | null;
    if (active?.id === "unlockPass") document.querySelector<HTMLElement>('[data-act="unlock"]')?.click();
  }
});

render();
