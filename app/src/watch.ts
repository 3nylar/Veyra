/**
 * CLIENT-SIDE WATCH WALLET
 *
 * Runs entirely in the browser. Holds an account xpub, talks directly to an
 * Esplora instance you name, and builds unsigned PSBTs. No server of ours is
 * involved at any point.
 *
 * ─── Why this page holds no keys ───────────────────────────────────────────
 * It is permitted to make network requests, because it must reach a chain
 * source. A page with that permission can also reach an attacker's server, so
 * the exfiltration guarantee that protects veyra-sign.html is impossible here.
 *
 * Those two properties genuinely cannot coexist in one page. Splitting them is
 * not caution — it is the only arrangement where either guarantee is real.
 */
import { WatchOnlyWallet } from "../../core/wallet/watchOnly.js";
import { EsploraChainSource } from "../../core/chain/esplora.js";
import { networkByName } from "../../core/bitcoin/networks.js";
import { Psbt } from "../../core/psbt/psbt.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const value = (id: string) => ($(id) as HTMLInputElement).value.trim();

let wallet: WatchOnlyWallet | null = null;
let chain: EsploraChainSource | null = null;
let receiveIndex = 0;

const formatBtc = (satoshis: bigint): string => {
  const negative = satoshis < 0n;
  const abs = negative ? -satoshis : satoshis;
  const whole = abs / 100_000_000n;
  const fraction = (abs % 100_000_000n).toString().padStart(8, "0");
  return `${negative ? "-" : ""}${whole.toLocaleString("en-US")}.${fraction}`;
};

/** Exact BTC→satoshi conversion. Never parseFloat — see docs/ATTACKS.md VEY-011. */
function parseBtc(input: string): bigint {
  const trimmed = input.trim();
  if (!/^\d*\.?\d*$/.test(trimmed) || trimmed === "" || trimmed === ".") {
    throw new Error("Enter a number");
  }
  const [whole = "0", fraction = ""] = trimmed.split(".");
  if (fraction.length > 8) throw new Error("Bitcoin has 8 decimal places");
  return BigInt(whole || "0") * 100_000_000n + BigInt((fraction + "00000000").slice(0, 8));
}

function status(id: string, message: string, tone: "" | "ok" | "danger" = "") {
  const element = $(id);
  element.textContent = message;
  element.style.color =
    tone === "ok" ? "var(--teal)" : tone === "danger" ? "var(--danger)" : "var(--muted)";
}

/**
 * Render an address with its Bech32 checksum distinguished.
 *
 * The final six characters are a BCH error-detecting code with a proven bound:
 * any four or fewer mistyped characters are caught. It is the part that
 * protects the recipient, and no wallet shows it.
 */
function renderAddress(address: string): string {
  const separator = address.lastIndexOf("1");
  if (separator < 1 || address.length < separator + 7) return address;
  const hrp = address.slice(0, separator + 1);
  const body = address.slice(separator + 1, address.length - 6);
  const checksum = address.slice(-6);
  return `<span class="hrp">${hrp}</span>${body}<span class="sum">${checksum}</span>`;
}

/** Default Esplora endpoints, adjusted when the network changes. */
const ESPLORA_DEFAULTS: Record<string, string> = {
  mainnet: "https://blockstream.info/api",
  testnet: "https://blockstream.info/testnet/api",
  signet: "https://mempool.space/signet/api",
  regtest: "http://127.0.0.1:3002",
};

$("network").addEventListener("change", () => {
  const network = ($("network") as HTMLSelectElement).value;
  ($("esplora") as HTMLInputElement).value = ESPLORA_DEFAULTS[network] ?? "";
});

// ── Connect ───────────────────────────────────────────────────────────────
$("connect").addEventListener("click", async () => {
  try {
    const network = networkByName(($("network") as HTMLSelectElement).value);
    wallet = WatchOnlyWallet.fromExtendedPublicKey(value("xpub"), network);
    chain = new EsploraChainSource({ baseUrl: value("esplora"), network: network.name });

    receiveIndex = 0;
    showReceive();
    $("balanceCard").classList.remove("hidden");
    $("receiveCard").classList.remove("hidden");
    $("sendCard").classList.remove("hidden");
    $("broadcastCard").classList.remove("hidden");

    status("connectStatus", `Loaded ${wallet.path} · ${wallet.fingerprint}`, "ok");

    // The privacy cost is stated at the moment the user commits to a source,
    // not buried in documentation they have already skipped.
    const notice = $("privacyNotice");
    notice.style.display = "block";
    $("privacyText").textContent = chain.isThirdParty
      ? `${value("esplora")} will learn every address in this wallet, that they belong to one wallet, your full balance and history, and your IP address. Running your own Esplora removes this entirely.`
      : "This looks like a local instance, so nothing about your wallet leaves this machine.";

    await doSync();
  } catch (error) {
    status("connectStatus", (error as Error).message, "danger");
  }
});

async function doSync() {
  if (!wallet || !chain) return status("connectStatus", "Load a wallet first.", "danger");
  status("connectStatus", "Scanning the chain…");
  try {
    const result = await wallet.sync(chain);
    const balance = wallet.balance();
    $("balance").innerHTML = `${formatBtc(balance.spendable)}<small>BTC</small>`;
    $("bTotal").textContent = formatBtc(balance.total);
    $("bUnconf").textContent = formatBtc(balance.unconfirmed);
    $("bCount").textContent = String(balance.utxoCount);
    status(
      "connectStatus",
      `Scanned ${result.addressesScanned} addresses · ${result.utxos} coins`,
      "ok",
    );
    showReceive();
  } catch (error) {
    status("connectStatus", (error as Error).message, "danger");
  }
}

$("sync").addEventListener("click", () => void doSync());

// ── Receive ───────────────────────────────────────────────────────────────
function showReceive() {
  if (!wallet) return;
  const derived = wallet.account.receiveAddress(receiveIndex);
  $("receiveAddr").innerHTML = renderAddress(derived.address);
  $("receivePath").textContent = derived.path;
}

$("nextAddr").addEventListener("click", () => {
  // Capped at the gap limit: funds beyond 20 consecutive unused addresses may
  // not be found when restoring from the seed.
  if (receiveIndex >= 19) {
    return status("connectStatus", "Gap limit reached — use an earlier address.", "danger");
  }
  receiveIndex++;
  showReceive();
});

$("copyAddr").addEventListener("click", async () => {
  if (!wallet) return;
  await navigator.clipboard.writeText(wallet.account.receiveAddress(receiveIndex).address);
  status("connectStatus", "Address copied.", "ok");
});

// ── Build ─────────────────────────────────────────────────────────────────
$("build").addEventListener("click", () => {
  if (!wallet) return status("buildStatus", "Load a wallet first.", "danger");
  try {
    const payment = wallet.buildPayment({
      to: value("to"),
      amount: parseBtc(value("amount")),
      feeRate: Number(value("feeRate")),
    });

    $("reviewRows").innerHTML = [
      `<div class="row"><span class="k">To</span><span class="v">${renderAddress(payment.recipient)}</span></div>`,
      `<div class="row"><span class="k">Amount</span><span class="v">${formatBtc(payment.amount)} BTC</span></div>`,
      `<div class="row"><span class="k">Network fee</span><span class="v">${formatBtc(payment.fee)} BTC</span></div>`,
      `<div class="row total"><span class="k">Total</span><span class="v">${formatBtc(payment.total)} BTC</span></div>`,
      `<div class="row"><span class="k">Remaining</span><span class="v">${formatBtc(payment.remainingBalance)} BTC</span></div>`,
      `<div class="row"><span class="k">Inputs</span><span class="v">${payment.inputs.length} · ${payment.vsize} vbytes</span></div>`,
      `<div class="row"><span class="k">Txid</span><span class="v">${payment.txid}</span></div>`,
    ].join("");

    ($("psbtOut") as HTMLTextAreaElement).value = payment.psbt;
    $("psbtCard").classList.remove("hidden");
    status("buildStatus", "Built. Nothing has been signed or broadcast.", "ok");
  } catch (error) {
    status("buildStatus", (error as Error).message, "danger");
  }
});

$("copyPsbt").addEventListener("click", async () => {
  await navigator.clipboard.writeText(($("psbtOut") as HTMLTextAreaElement).value);
  status("buildStatus", "PSBT copied. Sign it offline.", "ok");
});

// ── Broadcast ─────────────────────────────────────────────────────────────
$("broadcast").addEventListener("click", async () => {
  if (!wallet || !chain) return status("broadcastStatus", "Load a wallet first.", "danger");
  const hex = ($("signedHex") as HTMLTextAreaElement).value.trim();
  if (!hex) return status("broadcastStatus", "Paste the signed transaction hex.", "danger");

  status("broadcastStatus", "Broadcasting…");
  try {
    // Every input is checked against the coins this wallet watches before
    // anything is published — otherwise this would relay arbitrary bytes.
    const txid = await wallet.broadcastSigned(chain, hex);
    status("broadcastStatus", `Broadcast. txid ${txid}`, "ok");
    await doSync();
  } catch (error) {
    status("broadcastStatus", (error as Error).message, "danger");
  }
});

void Psbt;
