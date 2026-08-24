/**
 * Print the account-level xpub for a watch-only deployment.
 *
 * Run LOCALLY, never on the server. The xpub is safe to send to a host; the
 * mnemonic that produced it is not, and this script never prints it.
 */
import { Wallet } from "../core/wallet/wallet.js";
import { ExtendedKey } from "../core/derivation/bip32.js";
import { mnemonicToSeed, validateMnemonic } from "../core/mnemonic/index.js";
import { networkByName } from "../core/bitcoin/networks.js";

const network = networkByName(process.env.VEYRA_NETWORK ?? "regtest");
const mnemonic = process.env.VEYRA_MNEMONIC;

if (!mnemonic) {
  console.error(
    "Set VEYRA_MNEMONIC to the wallet you want to watch.\n" +
      "⚠️  Prefer a .env file over a shell command — shell history persists.",
  );
  process.exit(1);
}
if (!validateMnemonic(mnemonic)) {
  console.error("That mnemonic fails its checksum — check for mistyped words.");
  process.exit(1);
}

const master = ExtendedKey.fromSeed(mnemonicToSeed(mnemonic, process.env.VEYRA_PASSPHRASE ?? ""));
const account = master.derivePath(`m/84'/${network.coinType}'/0'`);
const wallet = Wallet.restore(mnemonic, network, process.env.VEYRA_PASSPHRASE ?? "");

console.log(`\nAccount xpub — ${network.name}`);
console.log(`  path         m/84'/${network.coinType}'/0'`);
console.log(`  fingerprint  ${account.identifier}`);
console.log(`  first addr   ${wallet.currentReceiveAddress().address}`);
console.log(`\n${account.toExtendedPublicKey(network.isMainnet ? "mainnet" : "testnet")}\n`);
console.log("Set this as VEYRA_XPUB on the host. It cannot spend.");
console.log("It CAN see every address and balance in the account — see docs/DEPLOYMENT.md.\n");
