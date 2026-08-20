/**
 * NETWORK PARAMETERS
 *
 * ─── Why this is a security module, not configuration ──────────────────────
 * The difference between networks is the difference between play money and
 * real money. Two failure modes matter:
 *
 *   1. Sending real BTC to an address the user believed was testnet.
 *   2. Developing against mainnet by accident, and burning real funds during
 *      a test run.
 *
 * Both are silent. Bitcoin has no confirmation dialogue and no undo.
 *
 * Veyra's mitigations:
 *   - The HRP differs per network ("bc" vs "tb"), and it is folded into the
 *     Bech32 checksum. A mainnet address therefore fails checksum validation
 *     when decoded as testnet, rather than decoding to a wrong-but-plausible
 *     result. The address format itself enforces the separation.
 *   - The coin type in the derivation path differs (0' mainnet, 1' for all
 *     test networks, per SLIP-44), so the key trees are entirely disjoint.
 *     A testnet wallet and a mainnet wallet from the same seed share no keys.
 *   - `REGTEST` is the default everywhere in Phase 1. Selecting mainnet must
 *     be a deliberate, explicit act.
 *
 * ─── On signet and regtest sharing testnet's HRP ───────────────────────────
 * Signet and regtest use "tb" and "bcrt" respectively. Note that signet
 * shares testnet's HRP and coin type completely — an address is
 * indistinguishable between them. They are separate chains with separate
 * UTXO sets, so funds are not interchangeable, but no encoding-level check
 * will catch the confusion. This is a real limitation of the format and is
 * recorded here rather than papered over.
 */

export type NetworkName = "mainnet" | "testnet" | "signet" | "regtest";

export interface Network {
  /** Human-readable name. */
  readonly name: NetworkName;
  /** Bech32 human-readable part, folded into the address checksum. */
  readonly bech32Hrp: string;
  /** SLIP-44 coin type used at derivation depth 2. */
  readonly coinType: number;
  /** Base58 version byte for P2PKH addresses. Kept for parsing legacy input. */
  readonly p2pkhVersion: number;
  /** Base58 version byte for P2SH addresses. */
  readonly p2shVersion: number;
  /** True only for mainnet. Used to gate irreversible actions. */
  readonly isMainnet: boolean;
}

export const MAINNET: Network = Object.freeze({
  name: "mainnet",
  bech32Hrp: "bc",
  coinType: 0,
  p2pkhVersion: 0x00,
  p2shVersion: 0x05,
  isMainnet: true,
});

export const TESTNET: Network = Object.freeze({
  name: "testnet",
  bech32Hrp: "tb",
  coinType: 1,
  p2pkhVersion: 0x6f,
  p2shVersion: 0xc4,
  isMainnet: false,
});

/** Signet is byte-identical to testnet at the address layer. See the note above. */
export const SIGNET: Network = Object.freeze({
  name: "signet",
  bech32Hrp: "tb",
  coinType: 1,
  p2pkhVersion: 0x6f,
  p2shVersion: 0xc4,
  isMainnet: false,
});

export const REGTEST: Network = Object.freeze({
  name: "regtest",
  bech32Hrp: "bcrt",
  coinType: 1,
  p2pkhVersion: 0x6f,
  p2shVersion: 0xc4,
  isMainnet: false,
});

export const NETWORKS: Readonly<Record<NetworkName, Network>> = Object.freeze({
  mainnet: MAINNET,
  testnet: TESTNET,
  signet: SIGNET,
  regtest: REGTEST,
});

/**
 * The default network for all of Phase 1.
 *
 * Deliberately regtest. Development defaults must never be mainnet — a
 * misconfigured environment variable should produce a useless wallet, not an
 * expensive one.
 */
export const DEFAULT_NETWORK: Network = REGTEST;

export function networkByName(name: string): Network {
  const network = (NETWORKS as Record<string, Network | undefined>)[name];
  if (!network) {
    throw new Error(
      `Unknown network '${name}'. Expected one of: ${Object.keys(NETWORKS).join(", ")}`,
    );
  }
  return network;
}
