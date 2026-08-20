/**
 * Veyra wallet demo — a complete send flow.
 *
 *   create wallet -> receive address -> load UTXOs -> review -> sign -> verify
 *
 * Run:  npm run demo:wallet
 *
 * Nothing here touches a network. The UTXOs are fabricated for illustration,
 * because Veyra has no blockchain connectivity yet and will not pretend to.
 */
import { Wallet } from "../core/wallet/wallet.js";
import { TESTNET } from "../core/bitcoin/networks.js";
import { verifyTransaction } from "../core/signing/signer.js";
import { FEE_RATE_PRESETS } from "../core/utxo/fees.js";
import type { Utxo } from "../core/utxo/utxo.js";

const sat = (n: bigint) => `${n.toLocaleString()} sat`;
const line = (label: string, value: string) => console.log(`  ${label.padEnd(20)} ${value}`);

console.log("\n══ VEYRA WALLET ══\n");

// 1. Create.
const { wallet, mnemonic } = Wallet.create(TESTNET, 12);
console.log("1. NEW WALLET");
line("network", TESTNET.name);
line("path", wallet.path);
line("fingerprint", wallet.fingerprint);
line("backup phrase", mnemonic.split(" ").slice(0, 4).join(" ") + " … (12 words)");
console.log("   ^ shown once. There is no getMnemonic(); lose it and the funds are gone.\n");

// 2. Receive.
const receive = wallet.currentReceiveAddress();
console.log("2. RECEIVE");
line("address", receive.address);
line("path", receive.path);
console.log();

// 3. Fabricated UTXOs, as if the address had been funded.
const addresses = wallet.receiveAddresses(3);
const utxos: Utxo[] = [
  { txid: "01".repeat(32), vout: 0, value: 150_000n, derivationPath: addresses[0]!.path, address: addresses[0]!.address, confirmations: 6 },
  { txid: "02".repeat(32), vout: 1, value: 80_000n, derivationPath: addresses[1]!.path, address: addresses[1]!.address, confirmations: 3 },
  { txid: "03".repeat(32), vout: 0, value: 25_000n, derivationPath: addresses[2]!.path, address: addresses[2]!.address, confirmations: 0 },
];
wallet.setUtxos(utxos);

const balance = wallet.balance();
console.log("3. BALANCE");
line("total", sat(balance.total));
line("spendable", sat(balance.spendable));
line("unconfirmed", sat(balance.unconfirmed));
line("coins", String(balance.utxoCount));
console.log();

// 4. Review a payment before committing to it.
const recipient = Wallet.create(TESTNET, 12).wallet.currentReceiveAddress().address;
const prepared = wallet.send({ to: recipient, amount: 100_000n, feeRate: FEE_RATE_PRESETS.medium });

console.log("4. REVIEW  (§16: never hide fees)");
line("to", prepared.recipient);
line("amount", sat(prepared.amount));
line("network fee", sat(prepared.fee));
line("TOTAL", sat(prepared.total));
line("remaining", sat(prepared.remainingBalance));
console.log();
line("inputs used", `${prepared.inputs.length} of ${balance.utxoCount}`);
line("strategy", prepared.strategy);
line("change", prepared.change > 0n ? `${sat(prepared.change)} -> ${prepared.changeAddress}` : "none (changeless)");
line("size", `${prepared.vsize} vbytes @ ${prepared.feeRate.toFixed(2)} sat/vB`);
console.log();

// 5. Signed and verified.
console.log("5. SIGNED");
line("txid", prepared.txid);
line("verifies", String(verifyTransaction(prepared.transaction, prepared.inputs.map((u) => u.value))));
line("raw hex", prepared.hex.slice(0, 48) + "…");
console.log();

// 6. Guards.
console.log("6. GUARDS");
for (const [label, attempt] of [
  ["overspend", () => wallet.send({ to: recipient, amount: 500_000n, feeRate: 8 })],
  ["dust amount", () => wallet.send({ to: recipient, amount: 100n, feeRate: 8 })],
  ["mainnet address", () => wallet.send({ to: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", amount: 10_000n, feeRate: 8 })],
  ["sub-relay fee", () => wallet.send({ to: recipient, amount: 10_000n, feeRate: 0.5 })],
] as const) {
  try {
    attempt();
    line(label, "!! ALLOWED — this is a bug");
  } catch (error) {
    line(label, `blocked — ${(error as Error).message.slice(0, 52)}…`);
  }
}

console.log("\nState is unchanged; nothing was broadcast. send() does not spend.\n");
line("balance still", sat(wallet.balance().spendable));
console.log();
