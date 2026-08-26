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
 *   1. **A PINNED `connect-src`.** The CSP names the exact endpoints this page
 *      may contact. Injected script cannot POST a seed to an attacker's
 *      server — the browser refuses the request. This is the single most
 *      important control here, and nothing in this file may widen it.
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
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  HOW THE INTERFACE WORKS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Plain TypeScript. Rendering is `root().innerHTML = …`, and every click is
 * handled by one delegated listener dispatching on `data-act` / `data-nav`.
 * There is no framework, because a self-contained file under a strict CSP does
 * not need one and every byte here ships to the user.
 *
 * ⚠️ The consequence that governs every feature below: **a render destroys the
 * DOM.** Anything that must survive a sync, a lock timer tick, or a navigation
 * has to live in module state or in `prefs` — never in an element. The flip
 * card and the activity paging are both built that way.
 */

import QRCode from "qrcode";
import { Wallet } from "../../core/wallet/wallet.js";
import { generateMnemonic, validateMnemonic } from "../../core/mnemonic/index.js";
import { EsploraChainSource } from "../../core/chain/esplora.js";
import { networkByName, type Network } from "../../core/bitcoin/networks.js";
import {
  encryptMnemonic,
  decryptMnemonic,
  type EncryptedKeystore,
} from "../../core/wallet/keystore.js";
import type { PreparedTransaction } from "../../core/wallet/wallet.js";
import type { ChainTransaction } from "../../core/chain/types.js";
import { cachedChainSource, type CachedChainSource } from "./chain-cache.js";
import { fetchUsdRate, fmtUsd, fmtRateAge, isStale, type FiatRate } from "./price.js";

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

/** How many transactions to fold per sync, and how many rows to reveal at once. */
const HISTORY_LIMIT = 100;
const ACTIVITY_PAGE = 20;
const HOME_ACTIVITY_ROWS = 5;

interface Prefs {
  network: string;
  esplora: string;
  /** Balance hidden behind the flip card. Defaults to hidden. */
  balanceHidden: boolean;
  /** Show a USD value. Mainnet only; no request is made elsewhere. */
  fiat: boolean;
  /** Shown on the cover face, so several wallets are tellable apart. */
  walletName: string;
}

const ESPLORA: Record<string, string> = {
  mainnet: "https://blockstream.info/api",
  testnet: "https://blockstream.info/testnet/api",
  signet: "https://mempool.space/signet/api",
  regtest: "http://127.0.0.1:3002",
};

const DEFAULT_NETWORK = "signet";

/**
 * Read preferences, repairing anything missing or malformed.
 *
 * Every wallet created before increment 21 has a stored blob of exactly
 * `{network, esplora}`, so each field is defaulted individually rather than
 * trusting the shape. The `!== false` tests matter: they make *absent* and
 * *garbage* both resolve to the safe value, which for `balanceHidden` means
 * hidden. A wallet that revealed a balance on first open in a café would have
 * failed at the only thing that card is for.
 */
function loadPrefs(): Prefs {
  let raw: Partial<Prefs> = {};
  try {
    const stored = localStorage.getItem(PREFS_KEY);
    if (stored) raw = JSON.parse(stored) as Partial<Prefs>;
  } catch {
    /* corrupt prefs are not worth failing over */
  }

  const network = typeof raw.network === "string" ? raw.network : DEFAULT_NETWORK;

  return {
    network,
    esplora: typeof raw.esplora === "string" ? raw.esplora : (ESPLORA[network] ?? ""),
    balanceHidden: raw.balanceHidden !== false,
    fiat: raw.fiat !== false,
    walletName: typeof raw.walletName === "string" ? raw.walletName.slice(0, 24) : "",
  };
}

function savePrefs(next: Prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(next));
  } catch {
    /* private mode */
  }
}

const hasKeystore = () => localStorage.getItem(STORE_KEY) !== null;
const readKeystore = (): EncryptedKeystore | null => {
  const raw = localStorage.getItem(STORE_KEY);
  return raw ? (JSON.parse(raw) as EncryptedKeystore) : null;
};

// ── State ─────────────────────────────────────────────────────────────────
type Screen = "home" | "activity" | "receive" | "send" | "settings";

let wallet: Wallet | null = null;
let chain: CachedChainSource | null = null;
let prefs = loadPrefs();
let screen: Screen = "home";
let prepared: PreparedTransaction | null = null;
let lockTimer: ReturnType<typeof setTimeout> | null = null;
let busy = false;

let history: ChainTransaction[] = [];
/**
 * True when the history lookup FAILED.
 *
 * Kept separate from `history.length === 0` on purpose. Telling someone they
 * have no transactions because the request broke is a lie the interface can
 * easily avoid, and it is the one someone with money would notice first.
 */
let historyUnavailable = false;
let historyError: string | null = null;
/** How many rows the activity screen shows. Module state, so it survives render. */
let historyShown = ACTIVITY_PAGE;

/** Live USD rate, or null. There is deliberately no remembered fallback. */
let rate: FiatRate | null = null;

/** When the last successful sync finished, for the "Updated 2m ago" label. */
let lastSyncedAt: number | null = null;

/**
 * The face the flip card should animate FROM on the next render, or null.
 *
 * Purely cosmetic, and the only transient DOM state in the file. See the note
 * above `renderApp` for why losing it is harmless.
 */
let flipAnimateFrom: boolean | null = null;

function touch() {
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = setTimeout(lock, AUTO_LOCK_MS);
}

function lock() {
  wallet = null;
  history = [];
  historyUnavailable = false;
  historyError = null;
  historyShown = ACTIVITY_PAGE;
  prepared = null;
  rate = null;
  flipAnimateFrom = null;
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
 * Icons, as inline SVG.
 *
 * Inline rather than an icon font or sprite sheet for the same reason nothing
 * else here is fetched: `img-src` is `'self' data:` and there is no network
 * budget for decoration. An inline `<svg>` is markup, not a request, so it
 * costs nothing at runtime and cannot fail to load.
 *
 * All of them are 24-grid, stroked with `currentColor`, so an icon inherits
 * the meaning of whatever it sits inside — a danger button gets a danger icon
 * without a second rule. `aria-hidden` throughout: every icon here sits beside
 * a real text label, and announcing it twice helps nobody.
 */
const ICONS: Record<string, string> = {
  wallet: `<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H18a2 2 0 0 1 2 2v1"/><path d="M3 7.5V17a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5a2 2 0 0 0-2-2H5.5A2.5 2.5 0 0 1 3 7.5Z"/><circle cx="16.5" cy="14" r="1.1" fill="currentColor" stroke="none"/>`,
  receive: `<path d="M12 4v12"/><path d="m7 11 5 5 5-5"/><path d="M5 20h14"/>`,
  send: `<path d="M12 20V8"/><path d="m7 13 5-5 5 5"/><path d="M5 4h14"/>`,
  settings: `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>`,
  sync: `<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>`,
  copy: `<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>`,
  plus: `<path d="M12 5v14"/><path d="M5 12h14"/>`,
  external: `<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>`,
  lock: `<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/>`,
  eye: `<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>`,
  eyeOff: `<path d="m3 3 18 18"/><path d="M10.6 6.2A9.9 9.9 0 0 1 12 6c6.4 0 10 6 10 6a17 17 0 0 1-3.4 4"/><path d="M6.2 7.4A16.6 16.6 0 0 0 2 12s3.6 7 10 7a9.7 9.7 0 0 0 4.2-.9"/><path d="M9.9 10.1a3 3 0 0 0 4.2 4.2"/>`,
  inbox: `<path d="M4 13h4l1.5 3h5L16 13h4"/><path d="M5.4 5.6 3 13v5a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5l-2.4-7.4A2 2 0 0 0 16.7 4H7.3a2 2 0 0 0-1.9 1.6Z"/>`,
  shield: `<path d="M12 3 5 6v5.5c0 4.3 3 8.3 7 9.5 4-1.2 7-5.2 7-9.5V6Z"/>`,
  trash: `<path d="M4 7h16"/><path d="M10 11v6M14 11v6"/><path d="M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12"/><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/>`,
  book: `<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15H6.5A2.5 2.5 0 0 0 4 20.5Z"/><path d="M4 20.5A2.5 2.5 0 0 1 6.5 18H20v3H6.5A2.5 2.5 0 0 1 4 20.5Z"/>`,
};

const icon = (name: string, size = 18): string =>
  `<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none"
     stroke="currentColor" stroke-width="1.7" stroke-linecap="round"
     stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONS[name] ?? ""}</svg>`;

/**
 * Hide a figure when the balance is hidden.
 *
 * ⚠️ This is what makes the flip card a real feature rather than a decoration.
 * A card that conceals the balance while the activity list beneath it shows
 * `+0.00310000` has hidden nothing, and is worse than showing the balance
 * outright because the user believes it worked. Every amount and every fiat
 * figure on a screen goes through here.
 *
 * Directions, dates and confirmation counts stay visible — they reveal that
 * activity happened, not how much, and hiding them would make the screen
 * useless rather than private.
 */
const MASK = "••••••";
const hide = (text: string): string => (prefs.balanceHidden ? MASK : text);

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

/**
 * Relative time, hand-rolled.
 *
 * `Intl.RelativeTimeFormat` would do this in one line and bring a locale
 * dependency whose output changes under a different ICU build — including in
 * jsdom, where the standalone render test runs. Eight lines of arithmetic are
 * deterministic everywhere and read the same in every environment.
 */
function relTime(unixSeconds: number, now = Date.now()): string {
  const seconds = Math.max(0, Math.floor(now / 1000) - unixSeconds);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} day${days === 1 ? "" : "s"} ago`;
  return new Date(unixSeconds * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/** The USD line for an amount, or an em dash. Never a remembered figure. */
function fiat(sats: bigint): string {
  const network = networkByName(prefs.network);
  if (!network.isMainnet) return "";
  if (!prefs.fiat) return "";
  return fmtUsd(sats, rate);
}

/**
 * A block-explorer URL for a txid, DERIVED from the configured chain source.
 *
 * Deriving it rather than hardcoding a favourite explorer means the link points
 * at the server that just answered the query about this transaction. It learns
 * nothing it does not already know. A hardcoded explorer would hand a brand-new
 * third party the user's txid every time they clicked.
 *
 * Returns null for a local regtest Esplora, which has no web interface.
 */
function explorerTxUrl(txid: string): string | null {
  // The txid came from a server. It has already been validated once in
  // core/chain, and this is the last mile before it enters an href.
  if (!/^[0-9a-f]{64}$/.test(txid)) return null;
  const base = prefs.esplora;
  if (!base.startsWith("https://") || !base.endsWith("/api")) return null;
  return `${base.slice(0, -4)}/tx/${txid}`;
}

/**
 * What to display for a transaction, and what to call it.
 *
 * ⚠️ Two corrections over the obvious rendering, both of which would otherwise
 * tell the user something false:
 *
 * **Fee is shown only for sends.** `ChainTransaction.fee` is documented as
 * "only known for transactions we sent", but Esplora populates it from
 * `/address/:a/txs` for EVERY transaction — including ones a stranger paid for.
 * Rendering it on a received row would tell the user they paid to be paid.
 *
 * **`netValue` for a send already includes the fee.** It is `−(amount + fee)`.
 * Showing `−0.00105` beside `fee 0.00005` invites the reader to add them.
 * So the fee is subtracted out and reported separately — clamping back to the
 * raw value if the fee is not smaller, since a hostile server could otherwise
 * drive the displayed amount negative.
 */
function txAmounts(tx: ChainTransaction): { amount: bigint; fee: bigint | null } {
  const net = tx.netValue ?? 0n;
  const abs = net < 0n ? -net : net;

  if (tx.direction === "sent" && tx.fee !== undefined && tx.fee > 0n && tx.fee < abs) {
    return { amount: abs - tx.fee, fee: tx.fee };
  }
  return { amount: abs, fee: null };
}

/** One transaction row, shared by the home card and the activity screen. */
function txRow(tx: ChainTransaction, detailed = false): string {
  const { amount, fee } = txAmounts(tx);
  const sent = tx.direction === "sent";
  const internal = tx.direction === "internal";

  // Sign AND word, so the meaning survives greyscale and colour blindness.
  const sign = internal ? "" : sent ? "−" : "+";
  const word = internal ? "Moved internally" : sent ? "Sent" : "Received";
  const tone = internal ? "internal" : sent ? "sent" : "received";

  const when =
    tx.confirmations === 0
      ? "In the mempool"
      : tx.blockTime !== undefined
        ? relTime(tx.blockTime)
        : `${tx.confirmations} confirmations`;

  const settled =
    tx.confirmations === 0
      ? "Unconfirmed"
      : tx.confirmations >= 6
        ? "Confirmed"
        : `${tx.confirmations} confirmation${tx.confirmations === 1 ? "" : "s"}`;

  const meta = [when, settled, fee ? `fee ${hide(fmtBtc(fee))}` : null]
    .filter(Boolean)
    .join(" · ");

  const url = explorerTxUrl(tx.txid);
  const id = url
    ? `<a class="id" href="${url}" target="_blank" rel="noopener noreferrer">${esc(short(tx.txid))}</a>`
    : `<span class="id">${esc(short(tx.txid))}</span>`;

  const usd = fiat(sent ? -amount : amount);

  return `<div class="item">
    <div class="item-main">
      <div class="item-word" data-tone="${tone}">${word}</div>
      <div class="meta">${id}${detailed && tx.blockTime !== undefined ? ` · <time datetime="${new Date(tx.blockTime * 1000).toISOString()}">${esc(new Date(tx.blockTime * 1000).toLocaleString("en-US"))}</time>` : ""}</div>
      <div class="meta">${esc(meta)}</div>
    </div>
    <div class="item-amt">
      <div class="amt" data-tone="${tone}">${hide(`${sign}${fmtBtc(amount)}`)}</div>
      ${usd ? `<div class="amt-fiat">${hide(usd)}</div>` : ""}
    </div>
  </div>`;
}

/**
 * The activity list body: failure, empty, or rows — three distinct states.
 *
 * The empty state offers the next step rather than just reporting absence. A
 * bordered box containing the words "No transactions yet" is the single
 * biggest source of dead space in a new wallet, and it leaves the one person
 * who most needs direction — someone who has just created a wallet — with
 * nothing to do.
 */
function activityBody(rows: ChainTransaction[], detailed = false): string {
  if (historyUnavailable) {
    return `<div class="notice" data-t="warn">
      <strong>Transaction history could not be loaded.</strong>
      This is not the same as having none — the request to the chain source failed.
      ${historyError ? `<div class="hint">${esc(historyError)}</div>` : ""}
      <div class="btn-row" style="margin-top:12px">
        <button data-act="sync" ${busy ? "disabled" : ""}>${icon("sync", 16)}<span>Try again</span></button>
      </div>
    </div>`;
  }

  if (rows.length === 0) {
    return `<div class="empty">
      <span class="empty-icon">${icon("inbox", 26)}</span>
      <p class="empty-title">Nothing here yet</p>
      <p class="empty-body">Transactions appear here once this wallet has
        received or sent bitcoin.</p>
      <button class="primary" data-nav="receive">${icon("receive", 16)}<span>Show my address</span></button>
    </div>`;
  }

  return `<div class="items">${rows.map((tx) => txRow(tx, detailed)).join("")}</div>`;
}

// ── Rendering ─────────────────────────────────────────────────────────────
const root = () => document.getElementById("root")!;

function render() {
  const network = networkByName(prefs.network);
  if (!hasKeystore()) return renderOnboard(network);
  if (!wallet) return renderUnlock(network);
  renderApp(network);
}

function shell(network: Network | null, body: string, nav = false): string {
  const tabs = [
    ["home", "Wallet", "wallet"],
    ["receive", "Receive", "receive"],
    ["send", "Send", "send"],
    ["settings", "Settings", "settings"],
  ] as const;

  return `
    <div class="shell">
      <header class="topbar">
        <div class="brand">
          <h1 class="wordmark">Veyra</h1>
          ${network ? `<span class="chip" data-mainnet="${network.isMainnet}"><i class="dot"></i>${esc(network.name)}</span>` : ""}
        </div>
        ${
          // Sync is a global action, so it belongs in the chrome rather than
          // buried at the bottom of the activity list where it used to live.
          nav
            ? `<div class="topbar-actions">
                 <span class="synced">${syncedLabel()}</span>
                 <button class="icon-btn" data-act="sync" ${busy ? "disabled" : ""}
                         aria-label="Sync with the chain" title="Sync with the chain">
                   <span class="${busy ? "spin" : ""}">${icon("sync", 17)}</span>
                 </button>
               </div>`
            : ""
        }
      </header>

      ${
        nav
          ? `<nav class="nav">
        ${tabs
          .map(
            ([id, label, glyph]) =>
              // The activity screen is reached from the Wallet tab, so that tab
              // stays lit while it is open. Otherwise no tab is current and the
              // user has no indication of where they are.
              `<button data-nav="${id}" aria-current="${
                id === "home" ? screen === "home" || screen === "activity" : screen === id
              }">${icon(glyph, 19)}<span>${label}</span></button>`,
          )
          .join("")}
      </nav>`
          : ""
      }

      <main>${body}</main>
    </div>`;
}

/** "Updated 2 minutes ago" — or nothing at all before the first sync. */
function syncedLabel(): string {
  if (busy) return "Syncing…";
  if (lastSyncedAt === null) return "";
  const seconds = Math.floor((Date.now() - lastSyncedAt) / 1000);
  if (seconds < 45) return "Updated just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `Updated ${minutes}m ago`;
  return `Updated ${Math.round(minutes / 60)}h ago`;
}

// ── Onboarding ────────────────────────────────────────────────────────────
let draftMnemonic: string | null = null;

/**
 * The network is chosen HERE, not buried in settings.
 *
 * Changing network after the fact re-derives an entirely different key tree
 * from the same seed — a different coin type is a different wallet — so the
 * old flow could hand someone a funded signet wallet and then appear to lose
 * their coins when they switched to mainnet. Asking once, up front, with the
 * consequence stated, is the only version of this that is not a trap.
 */
function networkPicker(id: string): string {
  return `<label class="f"><span>Network</span>
    <select id="${id}">
      ${(["signet", "testnet", "mainnet", "regtest"] as const)
        .map(
          (n) =>
            `<option value="${n}" ${n === prefs.network ? "selected" : ""}>${
              n === "mainnet" ? "mainnet — real bitcoin" : `${n} — test coins, no value`
            }</option>`,
        )
        .join("")}
    </select>
    <span class="hint">This decides which coins the wallet controls. It cannot be
      changed later without re-deriving a different wallet from your phrase.</span>
  </label>`;
}

function renderOnboard(network: Network) {
  root().innerHTML = shell(
    network,
    `
    <div class="notice" data-t="info">
      A self-custodial wallet that runs entirely in this browser. No account, no
      signup, and no server holds your coins. <strong>You are the only one who
      can recover this wallet</strong> — if you lose the recovery phrase, the
      coins are gone permanently.
    </div>
    ${
      network.isMainnet
        ? `<div class="notice" data-t="danger"><strong>Mainnet selected.</strong>
             Coins in this wallet will be real and transactions cannot be reversed.</div>`
        : ""
    }
    <div class="card">
      <p class="label">Create a wallet</p>
      ${networkPicker("onboardNetwork")}
      <p class="hint" style="margin-bottom:16px">
        Generates 12 words from your device's secure random number generator.
      </p>
      <button class="primary" data-act="create">Create new wallet</button>
    </div>
    <div class="card">
      <p class="label">Restore</p>
      <label class="f"><span>Recovery phrase (12 or 24 words)</span>
        <textarea id="restorePhrase" spellcheck="false" placeholder="word word word…"></textarea></label>
      <button data-act="restore">Restore wallet</button>
      <p class="status" id="onboardStatus"></p>
    </div>`,
  );
}

function steps(current: number): string {
  return `<div class="steps">${["Back up", "Confirm", "Encrypt"]
    .map(
      (label, index) =>
        `<span class="${index === current ? "on" : index < current ? "done" : ""}">${label}</span>`,
    )
    .join("<span>/</span>")}</div>`;
}

function renderBackup(network: Network, mnemonic: string) {
  const words = mnemonic.split(" ");
  root().innerHTML = shell(
    network,
    `
    ${steps(0)}
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
      <button class="primary" data-act="backed-up">I've written it down</button>
    </div>`,
  );
}

function renderConfirm(network: Network, mnemonic: string) {
  // Confirming three random words is enough to catch someone who skipped the
  // step entirely, without being so tedious they copy-paste from the screen.
  const words = mnemonic.split(" ");
  const picks = [...words.keys()]
    .sort(() => Math.random() - 0.5)
    .slice(0, 3)
    .sort((a, b) => a - b);

  root().innerHTML = shell(
    network,
    `
    ${steps(1)}
    <div class="card">
      <p class="label">Confirm your backup</p>
      <p class="hint" style="margin-bottom:16px">Enter these words from your phrase.</p>
      ${picks
        .map(
          (i) => `<label class="f"><span>Word ${i + 1}</span>
        <input data-confirm="${i}" spellcheck="false" autocomplete="off" /></label>`,
        )
        .join("")}
      <div class="btn-row">
        <button class="ghost" data-act="show-again">Show phrase again</button>
        <button class="primary" data-act="confirmed">Confirm</button>
      </div>
      <p class="err hidden" id="confirmErr">Those don't match. Check your written copy.</p>
    </div>`,
  );
}

function renderEncrypt(network: Network) {
  root().innerHTML = shell(
    network,
    `
    ${steps(2)}
    <div class="card">
      <p class="label">Set a passphrase</p>
      <p class="hint" style="margin-bottom:16px">
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
    </div>`,
  );
}

function renderUnlock(network: Network) {
  root().innerHTML = shell(
    network,
    `
    <div class="card">
      <p class="label">Unlock</p>
      <label class="f"><span>Passphrase</span>
        <input id="unlockPass" type="password" autocomplete="current-password" /></label>
      <button class="commit" data-act="unlock">Unlock</button>
      <p class="status" id="unlockStatus"></p>
    </div>
    <button class="ghost" data-act="forget-wallet">Remove this wallet from the browser</button>`,
  );
  setTimeout(() => document.getElementById("unlockPass")?.focus(), 50);
}

// ── Main app ──────────────────────────────────────────────────────────────
/**
 * Render a screen, then run the one piece of cosmetic DOM work in the file.
 *
 * The flip card's state comes from `prefs`, so the markup is already correct
 * the instant it is written. To make the flip *animate*, the card is emitted
 * showing the previous face and corrected on the next frame — a transition
 * needs two values and one render only ever produces one.
 *
 * If the frame never runs, the card is still in the right state; only the
 * animation is lost. That is why this is safe to do here and nowhere else.
 */
function renderApp(network: Network) {
  const body =
    screen === "home"
      ? viewHome(network)
      : screen === "activity"
        ? viewActivity()
        : screen === "receive"
          ? viewReceive(network)
          : screen === "send"
            ? viewSend()
            : viewSettings(network);

  root().innerHTML = shell(network, body, true);

  if (flipAnimateFrom !== null) {
    const shown = !prefs.balanceHidden;
    flipAnimateFrom = null;
    requestAnimationFrame(() => {
      const card = document.getElementById("balanceCard");
      card?.setAttribute("data-shown", String(shown));
      card?.setAttribute("aria-pressed", String(shown));
    });
  }

  if (screen === "receive") void paintQr();
}

/**
 * The balance card.
 *
 * ─── Why it is a flip card ─────────────────────────────────────────────────
 * A balance is the one number on screen that is nobody else's business, and a
 * wallet gets opened on trains and in cafés. Hiding it behind a deliberate
 * gesture costs one tap and removes the whole problem.
 *
 * ─── Why the state lives in prefs ──────────────────────────────────────────
 * `renderApp` replaces `innerHTML` on every change — a completed sync, the
 * auto-lock timer, a navigation. A flip held in the DOM (a class, a checkbox,
 * `:target`, `:has()`) would be silently undone mid-glance. Rendering
 * `data-shown` FROM `prefs.balanceHidden` makes every re-render idempotent and
 * makes persistence across reloads fall out for free.
 *
 * ─── Why Send and Receive are outside the card ─────────────────────────────
 * On the back face they would be unreachable while the balance is hidden, and
 * a `<button>` inside a `<button>` is invalid HTML with undefined click
 * behaviour. The card is one control that does one thing.
 */
function viewHome(network: Network): string {
  const balance = wallet!.balance();
  const shown = flipAnimateFrom !== null ? !flipAnimateFrom : !prefs.balanceHidden;
  const usd = fiat(balance.spendable);
  const recent = history.slice(0, HOME_ACTIVITY_ROWS);

  const left = `
    <button class="hero flip" id="balanceCard" data-act="toggle-balance"
            data-shown="${shown}" aria-pressed="${shown}"
            aria-label="Show or hide the balance">
      <span class="flip-inner">
        <span class="flip-face" data-face="balance">
          <span class="hero-top">
            <span class="label">Spendable balance</span>
            <span class="flip-hint">${icon("eyeOff", 15)}<span>Hide</span></span>
          </span>
          <span class="balance">${fmtBtc(balance.spendable)}<small>BTC</small></span>
          ${usd ? `<span class="fiat">${usd}</span>` : ""}
          <span class="sats">${balance.spendable.toLocaleString("en-US")} sat</span>
          <span class="breakdown">
            <span class="bk"><span>Total</span><span>${fmtBtc(balance.total)}</span></span>
            ${
              balance.unconfirmed > 0n
                ? `<span class="bk"><span>Unconfirmed</span><span data-tone="warn">${fmtBtc(balance.unconfirmed)}</span></span>`
                : ""
            }
            <span class="bk"><span>Coins</span><span>${balance.utxoCount}</span></span>
          </span>
        </span>

        <span class="flip-face" data-face="cover">
          <span class="hero-top">
            <span class="label">${esc(prefs.walletName || "Veyra wallet")}</span>
            <span class="flip-hint">${icon("eye", 15)}<span>Reveal</span></span>
          </span>
          <span class="balance">••••••••<small>BTC</small></span>
          <span class="sats">${esc(network.name)} · ${esc(wallet!.account.node.identifier)}</span>
          <span class="breakdown">
            <span class="bk"><span>Balance</span><span>Hidden</span></span>
          </span>
        </span>
      </span>
    </button>

    <div class="btn-row">
      <button class="primary" data-nav="send" ${balance.spendable === 0n ? "disabled" : ""}>
        ${icon("send")}<span>Send</span></button>
      <button data-nav="receive">${icon("receive")}<span>Receive</span></button>
    </div>

    ${
      rate
        ? `<p class="hint source-line">USD via ${esc(rate.source)} · ${esc(fmtRateAge(rate))}${
            isStale(rate) ? " · may be out of date" : ""
          }</p>`
        : network.isMainnet && prefs.fiat
          ? `<p class="hint source-line">USD price unavailable — showing bitcoin amounts only.</p>`
          : ""
    }
    <p class="status" id="syncStatus"></p>`;

  const right = `
    <section class="panel">
      <div class="panel-head">
        <h2 class="label">Activity</h2>
        ${
          history.length > HOME_ACTIVITY_ROWS
            ? `<button class="link-btn" data-act="all-activity">View all (${history.length})</button>`
            : ""
        }
      </div>
      ${activityBody(recent)}
    </section>`;

  return `
    ${
      network.isMainnet
        ? `<div class="notice" data-t="danger"><strong>Mainnet.</strong> These are real
      bitcoin and transactions cannot be reversed.</div>`
        : ""
    }
    <div class="home-grid">
      <div class="col">${left}</div>
      <div class="col">${right}</div>
    </div>`;
}

function viewActivity(): string {
  const rows = history.slice(0, historyShown);

  return `
    <button class="ghost back" data-nav="home">← Wallet</button>
    <section class="panel">
      <div class="panel-head">
        <h2 class="label">All activity</h2>
        ${history.length > 0 ? `<span class="count">${history.length}</span>` : ""}
      </div>
      ${activityBody(rows, true)}
      ${
        history.length > historyShown
          ? `<button class="ghost wide" data-act="more-activity">Show more</button>`
          : ""
      }
      <p class="hint">
        A chain source returns only the most recent transactions for each
        address, so history from long ago may not appear here. The coins are
        unaffected either way — this is a limit on what the server will tell us,
        not on what the wallet controls.
      </p>
    </section>`;
}

/**
 * Paint the receive QR after the screen is in the DOM.
 *
 * `qrcode` is the one dependency here that exists purely for presentation, and
 * it stays for the reason it was originally added: a QR code is a
 * Reed–Solomon-coded 2D symbol, and hand-rolling it risks producing an address
 * that scans as something else. Encoding a public address is also the safest
 * possible use of a third-party library in this file — it never sees a key.
 *
 * The address is uppercased because Bech32 is case-insensitive and uppercase
 * encodes in QR's compact alphanumeric mode, producing a symbol that scans from
 * further away.
 */
async function paintQr() {
  const box = document.getElementById("qrBox");
  if (!box || !wallet) return;

  const address = wallet.currentReceiveAddress().address;
  try {
    const url = await QRCode.toDataURL(address.toUpperCase(), {
      errorCorrectionLevel: "M",
      margin: 1,
      width: 440,
      color: { dark: "#0a0c0e", light: "#ffffff" },
    });
    const img = document.createElement("img");
    // Set as a property, never as an HTML string: a literal `src="…"` in the
    // built file is what `assertSelfContained` scans for.
    img.src = url;
    img.alt = "QR code containing this receiving address";
    img.width = 220;
    img.height = 220;
    box.replaceChildren(img);
  } catch {
    box.textContent = "QR unavailable — copy the address instead.";
  }
}

function viewReceive(network: Network): string {
  const derived = wallet!.currentReceiveAddress();
  return `
    <div class="notice" data-t="${network.isMainnet ? "danger" : "info"}">
      ${
        network.isMainnet
          ? "This is a <strong>mainnet</strong> address. Bitcoin sent here is real."
          : `This is a <strong>${esc(network.name)}</strong> address. Coins on this network have no value.`
      }
    </div>
    <section class="panel receive-panel">
      <div class="panel-head"><h2 class="label">Receive</h2></div>
      <div class="qr" id="qrBox"><span class="qr-wait">Generating…</span></div>
      <div class="addr">${addr(derived.address)}</div>
      <p class="hint">The underlined last six characters are a checksum. They
        catch any four or fewer mistyped characters, so a typo cannot quietly
        send bitcoin somewhere else.</p>
      <div class="btn-row" style="margin-top:16px">
        <button class="primary" data-act="copy-addr">${icon("copy", 16)}<span>Copy address</span></button>
        <button data-act="next-addr">${icon("plus", 16)}<span>New address</span></button>
      </div>
      <p class="status" id="receiveStatus">${esc(derived.path)}</p>
    </section>`;
}

function viewSend(): string {
  if (prepared) {
    const amountUsd = fiat(prepared.amount);
    return `
      <div class="steps"><span class="done">Compose</span><span>/</span><span class="on">Review</span></div>
      <section class="panel">
        <div class="panel-head"><h2 class="label">To</h2></div>
        <div class="addr">${addr(prepared.recipient)}</div>
        <div style="height:16px"></div>
        <div class="row"><span class="k">Amount</span><span class="v">${fmtBtc(prepared.amount)} BTC${
          amountUsd ? `<span class="v-fiat">${amountUsd}</span>` : ""
        }</span></div>
        <div class="row"><span class="k">Network fee</span><span class="v">${fmtBtc(prepared.fee)} BTC</span></div>
        <div class="row" data-total><span class="k">Total</span><span class="v">${fmtBtc(prepared.total)} BTC</span></div>
        <div class="row"><span class="k">Remaining</span><span class="v" data-tone="muted">${fmtBtc(prepared.remainingBalance)} BTC</span></div>
      </div>
      <section class="panel">
        <div class="panel-head"><h2 class="label">What will be broadcast</h2></div>
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
    <section class="panel">
      <div class="panel-head"><h2 class="label">Send bitcoin</h2></div>
      <label class="f"><span>Recipient address</span>
        <input id="to" spellcheck="false" autocomplete="off" placeholder="bc1q…" />
        <span class="hint">Paste it. Typing by hand risks an error.</span></label>
      <label class="f"><span>Amount in BTC</span>
        <input id="amount" inputmode="decimal" spellcheck="false" autocomplete="off" placeholder="0.00000000" />
        <span class="hint">Spendable: ${hide(fmtBtc(wallet!.balance().spendable))} BTC</span></label>
      <label class="f"><span>Fee rate (sat/vB)</span>
        <input id="feeRate" inputmode="numeric" spellcheck="false" value="5" />
        <span class="hint">Static estimate, not a live network rate.</span></label>
      <button class="primary" data-act="review">Review</button>
      <p class="status" id="sendStatus"></p>
    </div>`;
}

/**
 * Settings.
 *
 * Previously six identically-weighted cards stacked in a column, which read as
 * a wall rather than as choices. Grouped here into three panels plus a
 * visually distinct danger area and a plain footer, so the eye can find the
 * one thing it came for. A bordered box around every group means none of them
 * stands out.
 */
function viewSettings(network: Network): string {
  return `
    <div class="settings-grid">
      <section class="panel">
        <div class="panel-head"><h2 class="label">Display</h2></div>

        <label class="f"><span>Wallet name</span>
          <input id="walletName" maxlength="24" spellcheck="false" value="${esc(prefs.walletName)}" placeholder="Veyra wallet" />
          <span class="hint">Shown on the hidden face of the balance card, so several
            wallets are tellable apart without revealing any of them.</span></label>

        <label class="check"><input type="checkbox" id="balanceHidden" ${prefs.balanceHidden ? "checked" : ""} />
          <span><strong>Hide the balance by default</strong>
            <em>Every amount on screen is masked until you flip the card.</em></span></label>

        <label class="check"><input type="checkbox" id="fiat" ${prefs.fiat ? "checked" : ""} />
          <span><strong>Show a USD value</strong>
            <em>Mainnet only. Test coins have no market value, so none is shown or requested.</em></span></label>

        <button class="primary wide" data-act="save-display">Save display settings</button>
        <p class="status" id="displayStatus"></p>
      </section>

      <section class="panel">
        <div class="panel-head"><h2 class="label">Network</h2></div>

        <label class="f"><span>Chain</span>
          <select id="network">
            ${["signet", "testnet", "mainnet", "regtest"]
              .map(
                (n) => `<option value="${n}" ${n === prefs.network ? "selected" : ""}>${n}</option>`,
              )
              .join("")}
          </select></label>

        <label class="f"><span>Chain source (Esplora)</span>
          <input id="esplora" spellcheck="false" value="${esc(prefs.esplora)}" />
          <span class="hint">Must be one of the origins allowed by this page's
            security policy. Adding others requires rebuilding it.</span></label>

        <div class="notice" data-t="warn">
          Changing the network re-derives an entirely different wallet from the same
          phrase — a different coin type is a different key tree. The wallet locks
          and you will need to unlock again.
        </div>

        <button class="primary wide" data-act="save-network">Save and reload wallet</button>
        <p class="status" id="settingsStatus"></p>
      </section>

      <section class="panel">
        <div class="panel-head"><h2 class="label">${icon("shield", 15)}<span>Security</span></h2></div>

        <div class="row"><span class="k">Wallet type</span><span class="v">Self-custodial (BIP-84)</span></div>
        <div class="row"><span class="k">Keys held by</span><span class="v">This browser only</span></div>
        <div class="row"><span class="k">Stored as</span><span class="v">scrypt + AES-256-GCM</span></div>
        <div class="row"><span class="k">Path</span><span class="v">${esc(wallet!.account.path)}</span></div>
        <div class="row"><span class="k">Fingerprint</span><span class="v">${esc(wallet!.account.node.identifier)}</span></div>
        <div class="row"><span class="k">Auto-lock</span><span class="v">10 minutes</span></div>
        <div class="row"><span class="k">Recoverable by us</span><span class="v" data-tone="danger">No</span></div>

        <p class="hint">Nobody can restore this wallet from anything but your recovery
          phrase. There is no account and no support desk that can help.</p>
      </section>

      <section class="panel">
        <div class="panel-head"><h2 class="label">Who can see what</h2></div>

        <p class="hint" style="margin-top:0">
          ${
            chain?.isThirdParty
              ? `<strong>${esc(new URL(prefs.esplora).host)}</strong> can see every address in this
                 wallet, that they belong to one wallet, your balance, your full history, and your
                 IP address. Running your own Esplora removes this entirely.`
              : "You are using a local chain source, so nothing about this wallet leaves your machine."
          }
        </p>
        ${
          network.isMainnet && prefs.fiat
            ? `<p class="hint">The USD price comes from <strong>mempool.space</strong>, a second
                 server. It learns your IP address and that this page is open — not your addresses,
                 your balance, or your history. Turn off <em>Show a USD value</em> to contact only
                 your chain source.</p>`
            : ""
        }
      </section>
    </div>

    <section class="danger-zone">
      <div class="panel-head"><h2 class="label" data-tone="danger">Danger</h2></div>
      <div class="btn-row">
        <button data-act="lock">${icon("lock", 16)}<span>Lock now</span></button>
        <button class="danger" data-act="forget-wallet">${icon("trash", 16)}<span>Remove wallet</span></button>
      </div>
      <p class="hint">Removing only deletes the local copy. Your recovery phrase still
        controls the coins.</p>
    </section>

    <footer class="foot">
      <a href="/docs/">${icon("book", 15)}<span>Documentation</span></a>
      <a href="/veyra-sign.html">${icon("lock", 15)}<span>Offline signer</span></a>
      <a href="/SHA256SUMS">${icon("shield", 15)}<span>Verify this page</span></a>
    </footer>
    <p class="hint foot-note">
      Holding more than you would shrug at losing? Use the offline signer on a
      machine with no network instead of this page.
    </p>`;
}

// ── Actions ───────────────────────────────────────────────────────────────
function setStatus(id: string, message: string, tone: "" | "ok" | "danger" = "") {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = message;
  element.setAttribute("data-tone", tone);
}

function connectChain(network: Network) {
  // Wrapped so one sync pass stops asking the same server the same questions
  // forty times over. See app/src/chain-cache.ts.
  chain = cachedChainSource(
    new EsploraChainSource({ baseUrl: prefs.esplora, network: network.name }),
  );
}

async function refresh() {
  if (!wallet || !chain || busy) return;
  busy = true;
  render();
  try {
    await wallet.sync(chain);

    try {
      history = await wallet.history(chain, { limit: HISTORY_LIMIT });
      historyUnavailable = false;
      historyError = null;
    } catch (error) {
      // A FAILURE is not an empty history. Rendering "No transactions yet" here
      // would tell someone with money that they have none.
      history = [];
      historyUnavailable = true;
      historyError = (error as Error).message;
    }

    await refreshRate();

    lastSyncedAt = Date.now();
    busy = false;
    render();
    setStatus("syncStatus", "Up to date.", "ok");
  } catch (error) {
    busy = false;
    render();
    setStatus("syncStatus", (error as Error).message, "danger");
  }
}

/**
 * Fetch a USD rate, or leave it null.
 *
 * Mainnet only, and only when asked for: signet and testnet coins have no
 * market value, so quoting one would be a lie and requesting one would leak a
 * page view to a server the user has no reason to be talking to.
 */
async function refreshRate() {
  if (!networkByName(prefs.network).isMainnet || !prefs.fiat) {
    rate = null;
    return;
  }
  try {
    rate = await fetchUsdRate();
  } catch {
    // No cached value, no guess. The interface shows an em dash.
    rate = null;
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
    screen = nav as Screen;
    if (nav !== "send") prepared = null;
    return render();
  }

  const network = networkByName(prefs.network);

  switch (target.dataset.act) {
    case "toggle-balance": {
      // State first, animation second. `flipAnimateFrom` carries the OLD face
      // so the card can be rendered on it and corrected next frame; if that
      // frame never runs, the card is still correct and only the flip is lost.
      const previous = prefs.balanceHidden;
      prefs = { ...prefs, balanceHidden: !previous };
      savePrefs(prefs);
      flipAnimateFrom = previous;
      return render();
    }
    case "all-activity": {
      screen = "activity";
      historyShown = ACTIVITY_PAGE;
      return render();
    }
    case "more-activity": {
      historyShown += ACTIVITY_PAGE;
      return render();
    }
    case "create": {
      draftMnemonic = generateMnemonic(12);
      return renderBackup(network, draftMnemonic);
    }
    case "restore": {
      const phrase = (document.getElementById("restorePhrase") as HTMLTextAreaElement).value
        .trim()
        .replace(/\s+/g, " ")
        .toLowerCase();
      if (!validateMnemonic(phrase)) {
        return setStatus(
          "onboardStatus",
          "That phrase fails its checksum — check for mistyped words.",
          "danger",
        );
      }
      draftMnemonic = phrase;
      return renderEncrypt(network);
    }
    case "backed-up":
      return renderConfirm(network, draftMnemonic!);
    case "show-again":
      return renderBackup(network, draftMnemonic!);
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
    case "lock":
      return lock();
    case "forget-wallet": {
      if (
        !confirm(
          "Remove this wallet from the browser? You can only get it back with your recovery phrase.",
        )
      )
        return;
      localStorage.removeItem(STORE_KEY);
      lock();
      return;
    }
    case "sync":
      return void refresh();
    case "copy-addr": {
      await navigator.clipboard.writeText(wallet!.currentReceiveAddress().address);
      return setStatus("receiveStatus", "Copied.", "ok");
    }
    case "next-addr": {
      try {
        wallet!.nextReceiveAddress();
        render();
      } catch (error) {
        setStatus("receiveStatus", (error as Error).message, "danger");
      }
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
    case "cancel-send": {
      prepared = null;
      return render();
    }
    case "broadcast": {
      if (!prepared || busy) return;
      busy = true;
      render();
      try {
        const txid = await wallet!.broadcast(chain!, prepared);
        prepared = null;
        busy = false;
        screen = "home";
        render();
        setStatus("syncStatus", `Sent. ${txid}`, "ok");
        return void refresh();
      } catch (error) {
        busy = false;
        render();
        return setStatus("sendStatus", (error as Error).message, "danger");
      }
    }
    case "save-display": {
      prefs = {
        ...prefs,
        walletName: (document.getElementById("walletName") as HTMLInputElement).value
          .trim()
          .slice(0, 24),
        balanceHidden: (document.getElementById("balanceHidden") as HTMLInputElement).checked,
        fiat: (document.getElementById("fiat") as HTMLInputElement).checked,
      };
      savePrefs(prefs);
      await refreshRate();
      render();
      return setStatus("displayStatus", "Saved.", "ok");
    }
    case "save-network": {
      // Spread, don't rebuild. Listing only the two fields this screen edits
      // would silently erase every other preference — the display settings
      // above — the first time anyone saved network settings.
      prefs = {
        ...prefs,
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

// Changing a network preset updates the endpoint, so a user does not end up
// pointed at a testnet server while believing they are on mainnet.
document.addEventListener("change", (event) => {
  const target = event.target as HTMLElement;

  if (target.id === "network") {
    const chosen = (target as HTMLSelectElement).value;
    const field = document.getElementById("esplora") as HTMLInputElement | null;
    if (field) field.value = ESPLORA[chosen] ?? "";
    return;
  }

  // Onboarding: the network is picked before a wallet exists, so it is stored
  // immediately and the screen re-rendered to show the mainnet warning.
  if (target.id === "onboardNetwork") {
    const chosen = (target as HTMLSelectElement).value;
    prefs = { ...prefs, network: chosen, esplora: ESPLORA[chosen] ?? "" };
    savePrefs(prefs);
    render();
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
