/**
 * GENERATE THE SECURITY-CHALLENGE WALLET
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  READ THIS BEFORE RUNNING IT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This creates a **real mainnet Bitcoin wallet** and writes its encrypted
 * keystore to `challenge/keystore.json`, which is committed and published. Any
 * coins sent to the address it prints are real, and anyone who breaks that
 * ciphertext can take them. That is the entire point — see README.md, "The
 * security challenge".
 *
 * Three properties make the challenge honest, and this script enforces all
 * three rather than trusting anyone to remember them:
 *
 *   1. **A dedicated wallet.** Freshly generated here, used for nothing else.
 *      Publishing a keystore for a wallet that has held anything else would
 *      put unrelated funds behind the same ciphertext.
 *
 *   2. **A passphrase that cannot be guessed.** Generated here from the
 *      CSPRNG — twelve words from the BIP-39 list, about 132 bits. A
 *      human-chosen passphrase would turn the challenge into a test of
 *      password strength rather than of the cryptography, and the money would
 *      be gone within hours. This is the most important line in the file.
 *
 *   3. **The published file actually opens the published address.** The
 *      keystore is decrypted again after writing and checked to derive the
 *      same address. Publishing one that does not would make the challenge a
 *      lie — accidentally, but a lie, and an undiscoverable one: the only way
 *      to check from outside is to break it first.
 *
 * ─── What it deliberately does NOT do ──────────────────────────────────────
 * It never writes the mnemonic or the passphrase anywhere. Both are printed
 * once. Anything printed is in your terminal scrollback, so clear it once you
 * have written them down on paper.
 *
 * Usage:
 *   VEYRA_I_UNDERSTAND_MAINNET_RISK=yes npx tsx scripts/new-challenge-wallet.ts
 *
 * Add `--network signet` to rehearse the whole flow with worthless coins
 * first. Doing that at least once is strongly recommended.
 */

import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { generateMnemonic, validateMnemonic } from "../core/mnemonic/index.js";
import { ENGLISH_WORDLIST } from "../core/mnemonic/wordlist.js";
import { randomBytes } from "../core/crypto/entropy.js";
import { encryptMnemonic, decryptMnemonic } from "../core/wallet/keystore.js";
import { Wallet } from "../core/wallet/wallet.js";
import { networkByName } from "../core/bitcoin/networks.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// ── Arguments ─────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const networkIndex = args.indexOf("--network");
const networkName = networkIndex === -1 ? "mainnet" : (args[networkIndex + 1] ?? "mainnet");

const outDir = join(root, "challenge");
const outFile = join(outDir, "keystore.json");

if (!["mainnet", "signet", "testnet", "regtest"].includes(networkName)) {
  console.error(`Unknown network '${networkName}'.`);
  process.exit(1);
}
const network = networkByName(networkName);

// ── Guards ────────────────────────────────────────────────────────────────
/**
 * Mainnet requires saying so out loud.
 *
 * The same guard the API uses. A misconfigured environment variable should
 * produce a useless wallet, never an expensive one.
 */
if (network.isMainnet && process.env.VEYRA_I_UNDERSTAND_MAINNET_RISK !== "yes") {
  console.error(`
  REFUSING TO GENERATE A MAINNET WALLET.

  This creates a wallet for REAL bitcoin. Coins sent to it can be taken by
  anyone who breaks the keystore it publishes, and no transaction can be
  reversed.

  Rehearse on signet first. Same code path, worthless coins:

      npx tsx scripts/new-challenge-wallet.ts --network signet

  When you genuinely mean mainnet:

      VEYRA_I_UNDERSTAND_MAINNET_RISK=yes npx tsx scripts/new-challenge-wallet.ts
`);
  process.exit(1);
}

/**
 * Never silently replace an existing keystore.
 *
 * If a challenge wallet is already published and funded, overwriting this file
 * orphans those coins: the seed controlling them would survive only in a paper
 * backup, and the published file would no longer open the advertised address.
 */
if (existsSync(outFile)) {
  console.error(`
  REFUSING TO OVERWRITE ${outFile}

  A challenge keystore already exists. If it has ever been published or
  funded, replacing it orphans those coins and invalidates the address in the
  README. Move the old file aside deliberately if you really mean to.
`);
  process.exit(1);
}

// ── A passphrase nobody can guess ─────────────────────────────────────────
/**
 * Twelve words drawn uniformly from the BIP-39 list: 12 x 11 = 132 bits.
 *
 * Rejection sampling rather than `draw % 2048`, which would bias the low
 * indices. A modulo bias here is a real reduction in the entropy the entire
 * challenge rests on. 2048 divides 65536 exactly, so in practice nothing is
 * ever rejected — the loop exists so the property does not depend on that
 * happening to be true.
 */
function generatePassphrase(words = 12): string {
  const out: string[] = [];
  const limit = Math.floor(65536 / ENGLISH_WORDLIST.length) * ENGLISH_WORDLIST.length;

  // Drawn from a pool refilled in 32-byte blocks, because `randomBytes` refuses
  // to hand out fewer than 16 bytes at a time — a policy guard against exactly
  // the kind of small, casual draw that produces a weak-entropy wallet.
  let pool = randomBytes(32);
  let offset = 0;
  const next = (): number => {
    if (offset + 2 > pool.length) {
      pool = randomBytes(32);
      offset = 0;
    }
    const value = (pool[offset]! << 8) | pool[offset + 1]!;
    offset += 2;
    return value;
  };

  while (out.length < words) {
    const draw = next();
    if (draw >= limit) continue;
    out.push(ENGLISH_WORDLIST[draw % ENGLISH_WORDLIST.length]!);
  }
  return out.join(" ");
}

// ── Generate ──────────────────────────────────────────────────────────────
console.log(`\nGenerating a ${network.name} challenge wallet...\n`);

// 24 words rather than 12. This phrase is the last resort if the passphrase is
// lost, and its checksum is 8 bits instead of 4 — roughly 16x better at
// catching a transcription error on the paper copy it will live on.
const mnemonic = generateMnemonic(24);
if (!validateMnemonic(mnemonic)) throw new Error("generated an invalid mnemonic");

const passphrase = generatePassphrase();
const wallet = Wallet.restore(mnemonic, network);
const address = wallet.currentReceiveAddress();

const keystore = await encryptMnemonic(mnemonic, passphrase, {
  network: network.name,
  fingerprint: wallet.account.node.identifier,
});

mkdirSync(outDir, { recursive: true });
writeFileSync(outFile, `${JSON.stringify(keystore, null, 2)}\n`, "utf8");

// ── Verify what was actually written ──────────────────────────────────────
// Read the file back off disk rather than reusing the object in memory: the
// thing that gets published is the file, so the file is what must be checked.
const reopened = await decryptMnemonic(JSON.parse(readFileSync(outFile, "utf8")), passphrase);
if (reopened !== mnemonic) {
  throw new Error("the written keystore does not round-trip to the same phrase");
}
const check = Wallet.restore(reopened, network);
if (check.currentReceiveAddress().address !== address.address) {
  throw new Error("the written keystore does NOT derive the advertised address");
}

// ── Report ────────────────────────────────────────────────────────────────
const line = "-".repeat(74);

console.log(line);
console.log("  WRITE THESE DOWN ON PAPER. PRINTED ONCE, STORED NOWHERE.");
console.log(line);
console.log("\n  RECOVERY PHRASE (24 words) - the last resort if the passphrase is lost\n");

const words = mnemonic.split(" ");
for (let i = 0; i < words.length; i += 4) {
  const row = words
    .slice(i, i + 4)
    .map((word, j) => `${String(i + j + 1).padStart(2)}. ${word.padEnd(9)}`)
    .join(" ");
  console.log(`    ${row}`);
}

console.log("\n  PASSPHRASE (12 words, ~132 bits) - what the challenge actually tests\n");
console.log(`    ${passphrase}\n`);
console.log(line);
console.log(`
  Keystore written    challenge/keystore.json   (commit and publish this)
  Network             ${network.name}${network.isMainnet ? "   << REAL BITCOIN" : "   (test coins, no value)"}
  Fingerprint         ${wallet.account.node.identifier}
  Derivation path     ${address.path}
  Verified            keystore reopens and derives the address below

  FUND THIS ADDRESS
    ${address.address}
`);
console.log(line);
console.log(`
  Next:
    1. Write the phrase and the passphrase on paper. Store them offline.
       Neither is recoverable and neither is saved by this script.
    2. Clear your terminal scrollback - both are sitting in it right now.
    3. Send ~$10 of BTC to the address above.
    4. Paste the address and the contents of challenge/keystore.json into the
       placeholders in README.md and SECURITY.md.
    5. Commit challenge/keystore.json.
`);
