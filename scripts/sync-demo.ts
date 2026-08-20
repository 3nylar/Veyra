/**
 * Veyra sync demo — discovery, spending, and broadcast against a simulated chain.
 *
 * Run:  npm run demo:sync
 *
 * Uses MemoryChainSource, NOT a real network. It is not a Bitcoin node: it
 * does not validate consensus rules, so a broadcast succeeding here means
 * nothing about whether the real network would accept the transaction.
 */
import { Wallet } from "../core/wallet/wallet.js";
import { MemoryChainSource } from "../core/chain/memory.js";
import { EsploraChainSource, PUBLIC_ESPLORA } from "../core/chain/esplora.js";
import { TESTNET } from "../core/bitcoin/networks.js";

const sat = (n: bigint) => `${n.toLocaleString()} sat`;
const line = (label: string, value: string) => console.log(`  ${label.padEnd(20)} ${value}`);

console.log("\n══ VEYRA SYNC ══\n");

const wallet = Wallet.restore(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  TESTNET,
);
const chain = new MemoryChainSource("testnet", 800_000);

// Simulate history: address 0 funded, 1 used-and-emptied, 5 funded.
const addresses = wallet.receiveAddresses(10);
chain.fund(addresses[0]!.address, "11".repeat(32), 0, 150_000n, 12);
chain.markUsed(addresses[1]!.address);
chain.fund(addresses[5]!.address, "22".repeat(32), 1, 90_000n, 3);
chain.fund(addresses[5]!.address, "33".repeat(32), 0, 40_000n, 0);

console.log("1. SCAN  (gap limit 20, stops after 20 consecutive unused)");
const synced = await wallet.sync(chain);
line("addresses scanned", String(synced.addressesScanned));
line("utxos found", String(synced.utxos));
line("requests made", String(chain.requestCount));
console.log();

console.log("2. BALANCE");
line("total", sat(synced.balance.total));
line("spendable", sat(synced.balance.spendable));
line("unconfirmed", sat(synced.balance.unconfirmed));
console.log();

console.log("3. NEXT RECEIVE  (past the used ones)");
line("address", wallet.currentReceiveAddress().address);
line("path", wallet.currentReceiveAddress().path);
console.log();

const recipient = Wallet.create(TESTNET, 12).wallet.currentReceiveAddress().address;
const prepared = wallet.send({ to: recipient, amount: 100_000n, feeRate: 6 });

console.log("4. REVIEW");
line("amount", sat(prepared.amount));
line("fee", sat(prepared.fee));
line("total", sat(prepared.total));
line("remaining", sat(prepared.remainingBalance));
console.log();

console.log("5. BROADCAST");
const broadcastTxid = await wallet.broadcast(chain, prepared);
line("txid", broadcastTxid);
line("matches local", String(broadcastTxid === prepared.txid));
line("balance now", sat(wallet.balance().spendable));
console.log();

console.log("6. HOSTILE SERVER: wrong txid returned");
chain.fund(wallet.receiveAddresses(10)[7]!.address, "44".repeat(32), 0, 200_000n, 10);
await wallet.sync(chain);
const second = wallet.send({ to: recipient, amount: 50_000n, feeRate: 6 });
chain.broadcastTxidOverride = "de".repeat(32);
const balanceBefore = wallet.balance().spendable;
try {
  await wallet.broadcast(chain, second);
  line("result", "!! ACCEPTED — this is a bug");
} catch (error) {
  line("result", `rejected — ${(error as Error).message.slice(0, 44)}…`);
  line("coins spent?", String(wallet.balance().spendable !== balanceBefore));
}
console.log();

console.log("7. PRIVACY  (a real public server)");
const remote = new EsploraChainSource({ baseUrl: PUBLIC_ESPLORA.testnet, network: "testnet" });
console.log(`  ${remote.privacyWarning}`);
console.log("\n  Nothing above touched a real network.\n");
