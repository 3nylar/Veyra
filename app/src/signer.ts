/**
 * CLIENT-SIDE SIGNER
 *
 * Opens a PSBT built by a watch-only server, unlocks a seed locally, signs,
 * and returns transaction hex. The seed never leaves this page — the CSP in
 * signer.html sets `connect-src 'none'`, so there is no network channel at
 * all.
 *
 * ─── Why this is the right shape ───────────────────────────────────────────
 * The hosted API holds an xpub and cannot sign. This page holds the seed and
 * cannot reach the network. Neither half is dangerous alone, and together they
 * do what a single hosted signing wallet would — without any machine holding
 * both the keys and a network connection.
 *
 * ─── What a browser cannot give you ────────────────────────────────────────
 * Being honest about the limits, because "sign in your browser" is often sold
 * as more than it is:
 *
 *   · No memory protection. The seed is in the heap; anything that can read
 *     the process reads it.
 *   · No secure element. A hardware wallet keeps the key in a chip that never
 *     exposes it. This cannot.
 *   · Extensions run with access to page content on many browsers.
 *   · A compromised browser or OS defeats everything above.
 *
 * The CSP removes the *exfiltration* channel, which is the most likely attack
 * by a wide margin. It does not make a browser a secure enclave. An
 * air-gapped machine is what closes the rest.
 */
import { Psbt } from "../../core/psbt/psbt.js";
import { Transaction, TxInput } from "../../core/transactions/transaction.js";
import { ExtendedKey } from "../../core/derivation/bip32.js";
import { mnemonicToSeed, validateMnemonic } from "../../core/mnemonic/index.js";
import { decryptMnemonic, type EncryptedKeystore } from "../../core/wallet/keystore.js";
import { sighash, SighashCache, SIGHASH_ALL } from "../../core/signing/sighash.js";
import { signDigestWithSighashType, verifyWitnessSignature } from "../../core/signing/ecdsa.js";
import { PublicKey } from "../../core/keys/publicKey.js";
import { bytesToHex } from "../../core/crypto/bytes.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

/** Held in a closure only. Never written to storage of any kind. */
let mnemonic: string | null = null;
let loadedPsbt: Psbt | null = null;

const formatBtc = (satoshis: bigint): string => {
  const whole = satoshis / 100_000_000n;
  const fraction = (satoshis % 100_000_000n).toString().padStart(8, "0");
  return `${whole.toLocaleString("en-US")}.${fraction}`;
};

function status(element: HTMLElement, message: string, tone: "" | "ok" | "danger" = "") {
  element.textContent = message;
  element.style.color =
    tone === "ok" ? "var(--teal)" : tone === "danger" ? "var(--danger)" : "var(--muted)";
}

// ── 1. Unlock ─────────────────────────────────────────────────────────────
$("unlock").addEventListener("click", async () => {
  const out = $("unlockStatus");
  const raw = ($("secret") as HTMLTextAreaElement).value.trim();
  const passphrase = ($("passphrase") as HTMLInputElement).value;

  if (!raw) return status(out, "Paste a keystore or a mnemonic first.", "danger");
  status(out, "Unlocking…");

  try {
    if (raw.startsWith("{")) {
      const store = JSON.parse(raw) as EncryptedKeystore;
      // scrypt at N=2^17 takes about a second. That cost is the point.
      mnemonic = await decryptMnemonic(store, passphrase);
    } else {
      if (!validateMnemonic(raw)) {
        return status(out, "That mnemonic fails its checksum — check for mistyped words.", "danger");
      }
      mnemonic = raw;
    }
    status(out, "Unlocked. Nothing was stored; refreshing forgets it.", "ok");
  } catch (error) {
    mnemonic = null;
    status(out, (error as Error).message, "danger");
  }
});

$("forget").addEventListener("click", () => {
  mnemonic = null;
  ($("secret") as HTMLTextAreaElement).value = "";
  ($("passphrase") as HTMLInputElement).value = "";
  status($("unlockStatus"), "Locked.");
});

// ── 2. Review ─────────────────────────────────────────────────────────────
$("review").addEventListener("click", () => {
  const raw = ($("psbt") as HTMLTextAreaElement).value.trim();
  const details = $("details");
  try {
    loadedPsbt = Psbt.fromBase64(raw);
  } catch (error) {
    $("reviewCard").classList.add("hidden");
    details.innerHTML = "";
    return alert(`Could not read that PSBT: ${(error as Error).message}`);
  }

  const tx = loadedPsbt.transaction;
  let inputTotal = 0n;
  for (let i = 0; i < loadedPsbt.inputCount; i++) {
    const utxo = loadedPsbt.getWitnessUtxo(i);
    if (!utxo) {
      return alert(`Input ${i} has no witness_utxo — this signer cannot verify its amount.`);
    }
    inputTotal += utxo.value;
  }
  const outputTotal = tx.totalOutputValue();
  const fee = inputTotal - outputTotal;

  const rows: string[] = [];
  tx.outputs.forEach((output, index) => {
    rows.push(
      `<div class="row"><span class="k">Output ${index}</span><span class="v">${formatBtc(output.value)} BTC<br><span style="color:var(--dim)">${bytesToHex(output.scriptPubKey)}</span></span></div>`,
    );
  });
  rows.push(`<div class="row"><span class="k">Inputs</span><span class="v">${loadedPsbt.inputCount} · ${formatBtc(inputTotal)} BTC</span></div>`);
  rows.push(`<div class="row"><span class="k">Network fee</span><span class="v">${formatBtc(fee)} BTC</span></div>`);
  rows.push(`<div class="row total"><span class="k">Total leaving</span><span class="v">${formatBtc(inputTotal)} BTC</span></div>`);
  rows.push(`<div class="row"><span class="k">Txid</span><span class="v">${tx.txid()}</span></div>`);

  details.innerHTML = rows.join("");
  $("reviewCard").classList.remove("hidden");
});

// ── 3. Sign ───────────────────────────────────────────────────────────────
$("sign").addEventListener("click", () => {
  const out = $("resultStatus");
  if (!mnemonic) return alert("Unlock your seed first.");
  if (!loadedPsbt) return alert("Load a PSBT first.");

  try {
    const master = ExtendedKey.fromSeed(mnemonicToSeed(mnemonic));
    const psbt = loadedPsbt;
    const tx = psbt.transaction;
    const cache = new SighashCache(tx);

    for (let index = 0; index < psbt.inputCount; index++) {
      const utxo = psbt.getWitnessUtxo(index);
      const [derivation] = psbt.getBip32Derivations(index);
      if (!utxo || !derivation) {
        throw new Error(`input ${index} is missing the data needed to sign it`);
      }

      const node = master.derivePath(derivation.path);
      const publicKey = PublicKey.fromPrivateKey(node.privateKey);

      // The PSBT says which key should sign. If ours does not match, this
      // input belongs to someone else — signing anyway would produce a
      // useless signature and reveal that we hold a different key.
      if (bytesToHex(publicKey.toBytes()) !== bytesToHex(derivation.publicKey)) {
        throw new Error(
          `input ${index} expects a different key than this seed derives at ${derivation.path}`,
        );
      }

      const digest = sighash(
        tx,
        index,
        { value: utxo.value, publicKeyHash: publicKey.hash160() },
        SIGHASH_ALL,
        cache,
      );
      const signature = signDigestWithSighashType(digest, node.privateKey, SIGHASH_ALL);
      if (!verifyWitnessSignature(digest, signature, publicKey)) {
        throw new Error(`signature for input ${index} failed self-verification`);
      }
      psbt.addPartialSignature(index, publicKey.toBytes(), signature);
    }

    const signed = psbt.finalize().extract();
    ($("signedHex") as HTMLTextAreaElement).value = signed.toHex();
    $("resultCard").classList.remove("hidden");
    status(out, `Signed. txid ${signed.txid()}`, "ok");
    void Transaction;
    void TxInput;
  } catch (error) {
    status(out, (error as Error).message, "danger");
    $("resultCard").classList.remove("hidden");
    ($("signedHex") as HTMLTextAreaElement).value = "";
  }
});

$("copy").addEventListener("click", async () => {
  const hex = ($("signedHex") as HTMLTextAreaElement).value;
  try {
    await navigator.clipboard.writeText(hex);
    status($("resultStatus"), "Copied.", "ok");
  } catch {
    ($("signedHex") as HTMLTextAreaElement).select();
    status($("resultStatus"), "Press Ctrl+C to copy.");
  }
});

$("reset").addEventListener("click", () => {
  loadedPsbt = null;
  ($("psbt") as HTMLTextAreaElement).value = "";
  ($("signedHex") as HTMLTextAreaElement).value = "";
  $("reviewCard").classList.add("hidden");
  $("resultCard").classList.add("hidden");
});
