/**
 * API ENTRY POINT
 *
 * ⚠️ This starts a server holding private keys in memory. Read api/README.md
 * before running it anywhere but localhost.
 */
import { createApiServer } from "./server.js";
import { WalletService } from "./services/walletService.js";
import { generateApiToken } from "./middleware.js";
import { Wallet } from "../../core/wallet/wallet.js";
import { networkByName } from "../../core/bitcoin/networks.js";
import { EsploraChainSource } from "../../core/chain/esplora.js";
import { BitcoinRpcChainSource } from "../../core/chain/bitcoinRpc.js";
import type { ChainSource } from "../../core/chain/types.js";

function env(name: string): string | undefined {
  const value = process.env[name];
  return value && value.length > 0 ? value : undefined;
}

function buildChainSource(network: string): ChainSource | undefined {
  const rpcUrl = env("VEYRA_RPC_URL");
  if (rpcUrl) {
    const username = env("VEYRA_RPC_USER");
    const password = env("VEYRA_RPC_PASSWORD");
    if (!username || !password) {
      throw new Error("VEYRA_RPC_URL is set but VEYRA_RPC_USER/PASSWORD are missing");
    }
    return new BitcoinRpcChainSource({ url: rpcUrl, username, password, network });
  }
  const esploraUrl = env("VEYRA_ESPLORA_URL");
  if (esploraUrl) return new EsploraChainSource({ baseUrl: esploraUrl, network });
  return undefined;
}

async function main(): Promise<void> {
  const network = networkByName(env("VEYRA_NETWORK") ?? "regtest");
  const watchOnly = env("VEYRA_WATCH_ONLY") === "true" || env("VEYRA_XPUB") !== undefined;

  // ── The hosting rule ──────────────────────────────────────────────────
  // A hosted process holding a seed is a custodial service whether or not
  // anyone calls it that: compromise of the host is total loss. Refusing the
  // combination outright is the only way to keep that from happening by
  // accident — through a copied .env, a leftover variable, or a container
  // image that ends up in a registry.
  if (watchOnly && env("VEYRA_MNEMONIC")) {
    throw new Error(
      "VEYRA_WATCH_ONLY is set but VEYRA_MNEMONIC is also present. A watch-only " +
        "deployment must hold no seed — remove VEYRA_MNEMONIC, or unset " +
        "VEYRA_WATCH_ONLY if you intend to run a signing wallet locally.",
    );
  }
  if (watchOnly && !env("VEYRA_XPUB")) {
    throw new Error("VEYRA_WATCH_ONLY requires VEYRA_XPUB (an account-level extended public key)");
  }

  // Refuse mainnet without an explicit, deliberate opt-in. Starting a
  // key-holding server against real funds must never be the result of a
  // default or a forgotten variable.
  if (network.isMainnet && env("VEYRA_I_UNDERSTAND_MAINNET_RISK") !== "yes") {
    throw new Error(
      "Refusing to start on mainnet. This server holds private keys in memory " +
      "and has not been audited. Set VEYRA_I_UNDERSTAND_MAINNET_RISK=yes only " +
      "if you accept total loss of any funds involved.",
    );
  }

  if (watchOnly) {
    return startWatchOnly(network);
  }

  const mnemonic = env("VEYRA_MNEMONIC");
  let wallet: Wallet;
  let generatedMnemonic: string | undefined;

  if (mnemonic) {
    wallet = Wallet.restore(mnemonic, network, env("VEYRA_PASSPHRASE") ?? "");
  } else {
    const created = Wallet.create(network, 12);
    wallet = created.wallet;
    generatedMnemonic = created.mnemonic;
  }

  const chain = buildChainSource(network.name);
  const service = new WalletService(wallet, chain);

  // A generated token is printed once. Requiring the operator to copy it means
  // there is no default credential to forget to change.
  const token = env("VEYRA_API_TOKEN") ?? generateApiToken();

  const port = Number(env("VEYRA_PORT") ?? 3000);
  const host = env("VEYRA_HOST") ?? "127.0.0.1";

  // Extra browser origins may be permitted explicitly. The defaults cover the
  // Vite dev server; a deployed UI on another origin must be named.
  const extraOrigins = env("VEYRA_ALLOWED_ORIGINS")
    ?.split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  const server = createApiServer({
    service,
    auth: { token },
    ...(extraOrigins ? { allowedOrigins: extraOrigins } : {}),
    log: (level, message) => console.error(`[${level}] ${message}`),
  });

  server.listen(port, host, () => {
    console.log(`\nVeyra API — ${network.name}`);
    console.log(`  listening   http://${host}:${port}`);
    console.log(`  wallet      ${wallet.path}  (${wallet.fingerprint})`);
    console.log(`  chain       ${chain?.name ?? "none — balances will be empty"}`);
    console.log(`  ui origins  ${(extraOrigins ?? ["http://localhost:5173", "http://127.0.0.1:5173"]).join(", ")}`);
    if (!env("VEYRA_API_TOKEN")) {
      console.log(`\n  API token (generated, shown once):\n    ${token}`);
    }
    if (generatedMnemonic) {
      console.log(`\n  ⚠️  Wallet mnemonic (generated, shown once — not recoverable):`);
      console.log(`    ${generatedMnemonic}`);
    }
    if (host !== "127.0.0.1" && host !== "localhost") {
      console.log(`\n  ⚠️  Bound to ${host}, not localhost. This process holds private`);
      console.log(`      keys and speaks plain HTTP. Put TLS in front of it.`);
    }
    console.log();
  });
}

/**
 * Start in watch-only mode.
 *
 * The process holds an xpub and nothing else. It can show balances and build
 * unsigned PSBTs; signing happens wherever the seed lives.
 */
async function startWatchOnly(network: ReturnType<typeof networkByName>): Promise<void> {
  const { WatchOnlyWallet } = await import("../../core/wallet/watchOnly.js");
  const { WatchOnlyService } = await import("./services/watchOnlyService.js");

  const wallet = WatchOnlyWallet.fromExtendedPublicKey(env("VEYRA_XPUB")!, network);
  const chain = buildChainSource(network.name);
  const service = new WatchOnlyService(wallet, chain);

  const token = env("VEYRA_API_TOKEN") ?? generateApiToken();
  const port = Number(env("VEYRA_PORT") ?? 3000);
  const host = env("VEYRA_HOST") ?? "127.0.0.1";

  const extraOrigins = env("VEYRA_ALLOWED_ORIGINS")
    ?.split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  const server = createApiServer({
    service,
    auth: { token },
    ...(extraOrigins ? { allowedOrigins: extraOrigins } : {}),
    log: (level, message) => console.error(`[${level}] ${message}`),
  });

  server.listen(port, host, () => {
    console.log(`\nVeyra API — ${network.name} — WATCH-ONLY`);
    console.log(`  listening   http://${host}:${port}`);
    console.log(`  watching    ${wallet.path}  (${wallet.fingerprint})`);
    console.log(`  chain       ${chain?.name ?? "none — balances will be empty"}`);
    console.log(`  can sign    NO — this process holds no private key`);
    if (!env("VEYRA_API_TOKEN")) {
      console.log(`\n  API token (generated, shown once):\n    ${token}`);
    }
    console.log(
      `\n  This server can see every address and balance in the account, ` +
        `\n  but cannot spend. Signing happens wherever the seed lives.\n`,
    );
  });
}

main().catch((error: unknown) => {
  console.error(`Failed to start: ${(error as Error).message}`);
  process.exit(1);
});
