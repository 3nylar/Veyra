/**
 * Veyra demo — the full Phase 1 pipeline, end to end.
 *
 *   entropy → mnemonic → seed → master key → account → address
 *
 * Run:  npx tsx scripts/demo.ts
 *
 * ⚠️  This prints a REAL mnemonic to your terminal. It is a testnet/regtest
 * wallet with no funds, but treat the habit as dangerous: never do this with
 * a wallet you intend to use. Terminal scrollback, shell history, and screen
 * recordings all persist.
 */
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from "../core/mnemonic/index.js";
import { ExtendedKey } from "../core/derivation/bip32.js";
import { Bip84Account } from "../core/addresses/bip84.js";
import { TESTNET } from "../core/bitcoin/networks.js";

const line = (label: string, value: string) =>
  console.log(`  ${label.padEnd(18)} ${value}`);

console.log("\n══ VEYRA — Phase 1 pipeline ══\n");

// 1. Generate a mnemonic from OS entropy.
const mnemonic = generateMnemonic(12);
console.log("1. MNEMONIC (BIP-39)");
line("valid", String(validateMnemonic(mnemonic)));
line("words", mnemonic);
console.log();

// 2. Stretch it into a 512-bit seed.
const seed = mnemonicToSeed(mnemonic);
console.log("2. SEED (PBKDF2-HMAC-SHA512, 2048 rounds)");
line("bytes", String(seed.length));
line("seed", Buffer.from(seed).toString("hex").slice(0, 32) + "…");
console.log();

// 3. Derive the master node.
const master = ExtendedKey.fromSeed(seed);
console.log("3. MASTER KEY (BIP-32)");
line("fingerprint", master.identifier);
line("logged form", String(master)); // redacted, by design
console.log();

// 4. Derive the BIP-84 testnet account.
const account = Bip84Account.fromMasterKey(master, TESTNET, 0);
console.log("4. ACCOUNT (BIP-84)");
line("path", account.path);
line("network", TESTNET.name);
console.log();

// 5. Addresses.
console.log("5. RECEIVE ADDRESSES");
for (let i = 0; i < 3; i++) {
  const a = account.receiveAddress(i);
  line(`  ${a.path}`, a.address);
}
console.log("\n6. CHANGE ADDRESSES");
for (let i = 0; i < 2; i++) {
  const a = account.changeAddress(i);
  line(`  ${a.path}`, a.address);
}

// 7. Watch-only: the same addresses, no spending authority.
const watchOnly = account.neutered();
console.log("\n7. WATCH-ONLY (xpub-equivalent)");
line("same address", String(watchOnly.receiveAddress(0).address === account.receiveAddress(0).address));
line("has priv key", String(watchOnly.node.hasPrivateKey));
try {
  watchOnly.node.derive(0x80000000);
} catch (e) {
  line("hardened deriv", `blocked — ${(e as Error).message.slice(0, 45)}…`);
}

console.log("\nThese are TESTNET addresses. Fund them from a testnet faucet only.\n");

// ──────────────────────────────────────────────────────────────────────────
// 8. Build, sign, and verify a transaction.
// ──────────────────────────────────────────────────────────────────────────
import { Transaction, TxInput, TxOutput, SEQUENCE_RBF } from "../core/transactions/transaction.js";
import { signTransaction, verifyTransaction, calculateFee, feeRate } from "../core/signing/signer.js";
import { p2wpkhScriptPubKey } from "../core/addresses/bip84.js";
import { PublicKey } from "../core/keys/publicKey.js";

console.log("══ SPENDING ══\n");

// Pretend we hold a 100,000 sat UTXO at m/84'/1'/0'/0/0.
const spendNode = master.derivePath("m/84'/1'/0'/0/0");
const changeNode = master.derivePath("m/84'/1'/0'/1/0");
const recipient = PublicKey.fromPrivateKey(
  ExtendedKey.fromSeed(mnemonicToSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")).privateKey,
);

const UTXO_VALUE = 100_000n;
const SEND = 60_000n;
const FEE = 1_000n;
const CHANGE = UTXO_VALUE - SEND - FEE;

const unsigned = new Transaction(
  2,
  [new TxInput({ txid: "ab".repeat(32), vout: 0 }, new Uint8Array(0), SEQUENCE_RBF)],
  [
    new TxOutput(SEND, p2wpkhScriptPubKey(recipient)),
    new TxOutput(CHANGE, p2wpkhScriptPubKey(changeNode.publicKey)),
  ],
  0,
);

console.log("8. UNSIGNED TRANSACTION");
line("txid", unsigned.txid());
line("inputs", `1 x ${UTXO_VALUE} sat`);
line("send", `${SEND} sat`);
line("change", `${CHANGE} sat`);
line("fee", `${FEE} sat`);
console.log();

const signed = signTransaction(unsigned, [{ value: UTXO_VALUE, privateKey: spendNode.privateKey }]);

console.log("9. SIGNED");
line("txid", signed.txid());
line("txid unchanged", String(signed.txid() === unsigned.txid()));  // SegWit: yes
line("wtxid", signed.wtxid());
line("verifies", String(verifyTransaction(signed, [UTXO_VALUE])));
line("fee", `${calculateFee(signed, [UTXO_VALUE])} sat`);
line("vsize", `${signed.vsize()} vbytes`);
line("fee rate", `${feeRate(signed, [UTXO_VALUE]).toFixed(2)} sat/vB`);
console.log();

// 10. Tamper with it and watch verification fail.
console.log("10. TAMPER CHECK");
const stolen = new Transaction(
  signed.version,
  signed.inputs,
  [new TxOutput(SEND, p2wpkhScriptPubKey(changeNode.publicKey)), signed.outputs[1]!],
  signed.locktime,
);
line("redirected", String(verifyTransaction(stolen, [UTXO_VALUE])));
line("lied on value", String(verifyTransaction(signed, [UTXO_VALUE + 1n])));

console.log("\nNothing was broadcast. These are unfunded testnet coins.\n");
