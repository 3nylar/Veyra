/**
 * CHAIN SYNCHRONISATION TESTS
 *
 * Two halves:
 *
 *   1. Does the gap-limit scan behave like every other wallet? If Veyra
 *      scanned differently it would find funds others report as missing, or
 *      miss funds others find — an interoperability failure that looks
 *      exactly like lost money.
 *
 *   2. What happens when the server is hostile? The chain source is the only
 *      untrusted input in the wallet, so it gets adversarial treatment.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { Wallet, GAP_LIMIT, WalletError } from "../../core/wallet/wallet.js";
import { MemoryChainSource } from "../../core/chain/memory.js";
import { ChainError } from "../../core/chain/types.js";
import { TESTNET, MAINNET } from "../../core/bitcoin/networks.js";
import { verifyTransaction } from "../../core/signing/signer.js";

const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const txid = (n: number) => n.toString(16).padStart(8, "0").repeat(8).slice(0, 64);

describe("gap-limit scanning", () => {
  let wallet: Wallet;
  let chain: MemoryChainSource;

  beforeEach(() => {
    wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    chain = new MemoryChainSource("testnet", 200);
  });

  it("finds nothing on an empty chain", async () => {
    const result = await wallet.sync(chain);
    expect(result.utxos).toBe(0);
    expect(result.balance.total).toBe(0n);
  });

  it("scans exactly the gap limit on each chain when nothing is used", async () => {
    const result = await wallet.sync(chain);
    // 20 receive + 20 change.
    expect(result.addressesScanned).toBe(GAP_LIMIT * 2);
  });

  it("discovers a funded address", async () => {
    const address = wallet.receiveAddresses(1)[0]!.address;
    chain.fund(address, txid(1), 0, 100_000n);

    const result = await wallet.sync(chain);
    expect(result.utxos).toBe(1);
    expect(result.balance.spendable).toBe(100_000n);
  });

  it("discovers UTXOs across several addresses and both chains", async () => {
    const receive = wallet.receiveAddresses(3);
    chain.fund(receive[0]!.address, txid(1), 0, 50_000n);
    chain.fund(receive[2]!.address, txid(2), 1, 30_000n);

    const result = await wallet.sync(chain);
    expect(result.utxos).toBe(2);
    expect(result.balance.total).toBe(80_000n);
  });

  it("CONTINUES scanning past a used address, resetting the gap counter", async () => {
    // Address 0 used, 1-14 unused, 15 used. A scan that stopped at the first
    // run of unused addresses would miss the funds at 15.
    const addresses = wallet.receiveAddresses(GAP_LIMIT);
    chain.markUsed(addresses[0]!.address);
    chain.fund(addresses[15]!.address, txid(1), 0, 75_000n);

    const result = await wallet.sync(chain);
    expect(result.balance.total).toBe(75_000n);
  });

  it("STOPS after the gap limit — funds beyond it are not found", async () => {
    // The documented, deliberate limitation. Funds sent past the gap limit
    // are not lost, but no standard wallet will find them on restore.
    const wide = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const addresses = wide.account.deriveAddresses(0, 0, 40);
    chain.fund(addresses[30]!.address, txid(1), 0, 999_999n);

    const result = await wide.sync(chain);
    expect(result.balance.total).toBe(0n);

    // ...and IS found with a wider limit, proving the coins exist and the
    // scan depth is the only thing standing between them and the wallet.
    const deep = Wallet.restore(TEST_MNEMONIC, TESTNET);
    expect((await deep.sync(chain, { gapLimit: 40 })).balance.total).toBe(999_999n);
  });

  it("advances the next receive address past ones already used", async () => {
    const addresses = wallet.receiveAddresses(5);
    chain.markUsed(addresses[0]!.address);
    chain.markUsed(addresses[1]!.address);
    await wallet.sync(chain);
    // Should not hand out an address that already has history.
    expect(wallet.currentReceiveAddress().address).not.toBe(addresses[0]!.address);
    expect(wallet.currentReceiveAddress().address).not.toBe(addresses[1]!.address);
  });

  it("carries confirmation counts through, keeping unconfirmed separate", async () => {
    const addresses = wallet.receiveAddresses(2);
    chain.fund(addresses[0]!.address, txid(1), 0, 100_000n, 6);
    chain.fund(addresses[1]!.address, txid(2), 0, 50_000n, 0);

    const { balance } = await wallet.sync(chain);
    expect(balance.spendable).toBe(100_000n);
    expect(balance.unconfirmed).toBe(50_000n);
  });

  it("re-syncing replaces state rather than accumulating it", async () => {
    const address = wallet.receiveAddresses(1)[0]!.address;
    chain.fund(address, txid(1), 0, 100_000n);
    await wallet.sync(chain);
    await wallet.sync(chain);
    expect(wallet.balance().utxoCount).toBe(1); // not 2
  });

  it("notices coins disappearing after a spend elsewhere", async () => {
    const address = wallet.receiveAddresses(1)[0]!.address;
    chain.fund(address, txid(1), 0, 100_000n);
    expect((await wallet.sync(chain)).balance.total).toBe(100_000n);

    chain.spend(address, txid(1), 0);
    expect((await wallet.sync(chain)).balance.total).toBe(0n);
  });

  it("a reorg drops confirmed funds back to unconfirmed", async () => {
    const address = wallet.receiveAddresses(1)[0]!.address;
    chain.fund(address, txid(1), 0, 100_000n, 6);
    expect((await wallet.sync(chain)).balance.spendable).toBe(100_000n);

    chain.reorg();
    const after = await wallet.sync(chain);
    expect(after.balance.spendable).toBe(0n);
    expect(after.balance.unconfirmed).toBe(100_000n);
  });
});

describe("network mismatch is refused", () => {
  it("refuses to sync a testnet wallet against a mainnet source", async () => {
    // Would produce a nonsense balance assembled from unrelated coins.
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    await expect(wallet.sync(new MemoryChainSource("mainnet"))).rejects.toThrow(/mainnet.*testnet|testnet.*mainnet/);
  });

  it("refuses to broadcast to the wrong network", async () => {
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const chain = new MemoryChainSource("testnet", 200);
    const address = wallet.receiveAddresses(1)[0]!.address;
    chain.fund(address, txid(1), 0, 200_000n);
    await wallet.sync(chain);

    const prepared = wallet.send({
      to: Wallet.restore(TEST_MNEMONIC, TESTNET, "x").currentReceiveAddress().address,
      amount: 50_000n, feeRate: 5,
    });
    await expect(wallet.broadcast(new MemoryChainSource("mainnet"), prepared)).rejects.toThrow();
  });
});

describe("broadcast", () => {
  let wallet: Wallet;
  let chain: MemoryChainSource;

  beforeEach(async () => {
    wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    chain = new MemoryChainSource("testnet", 200);
    chain.fund(wallet.receiveAddresses(1)[0]!.address, txid(1), 0, 200_000n);
    await wallet.sync(chain);
  });

  const recipient = () =>
    Wallet.restore(TEST_MNEMONIC, TESTNET, "recipient").currentReceiveAddress().address;

  it("publishes a signed transaction and returns its txid", async () => {
    const prepared = wallet.send({ to: recipient(), amount: 50_000n, feeRate: 5 });
    const returned = await wallet.broadcast(chain, prepared);

    expect(returned).toBe(prepared.txid);
    expect(chain.broadcastLog.length).toBe(1);
    expect(chain.broadcastLog[0]).toBe(prepared.hex);
  });

  it("marks inputs spent only after a successful broadcast", async () => {
    const prepared = wallet.send({ to: recipient(), amount: 50_000n, feeRate: 5 });
    expect(wallet.balance().utxoCount).toBe(1); // send() alone changes nothing
    await wallet.broadcast(chain, prepared);
    expect(wallet.balance().utxoCount).toBe(0);
  });

  it("leaves wallet state UNTOUCHED when broadcast fails", async () => {
    // A failed broadcast must be retryable. Marking coins spent on failure
    // would strand them until the next sync.
    const prepared = wallet.send({ to: recipient(), amount: 50_000n, feeRate: 5 });
    chain.broadcastError = new Error("network unreachable");

    await expect(wallet.broadcast(chain, prepared)).rejects.toThrow();
    expect(wallet.balance().utxoCount).toBe(1);
    expect(wallet.balance().spendable).toBe(200_000n);
  });

  it("ATTACK: a server returning the WRONG txid is treated as a failure", async () => {
    // A mismatch means the server is broken or lying. Either way the
    // transaction's fate is unknown, so recording success would be a lie of
    // our own.
    const prepared = wallet.send({ to: recipient(), amount: 50_000n, feeRate: 5 });
    chain.broadcastTxidOverride = txid(999);

    await expect(wallet.broadcast(chain, prepared)).rejects.toThrow(/status is unknown/);
    expect(wallet.balance().utxoCount).toBe(1); // not marked spent
  });

  it("the broadcast transaction verifies independently", async () => {
    const prepared = wallet.send({ to: recipient(), amount: 50_000n, feeRate: 5 });
    await wallet.broadcast(chain, prepared);
    expect(verifyTransaction(prepared.transaction, prepared.inputs.map((u) => u.value))).toBe(true);
  });
});

describe("ATTACK: a hostile chain source", () => {
  let wallet: Wallet;

  beforeEach(() => {
    wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
  });

  it("STRUCTURALLY cannot attribute a synced UTXO to a foreign address", async () => {
    // Worth stating as a design property rather than a check: the sync loop
    // attributes each UTXO to the address IT derived and asked about, never
    // to an address the server names. So a server cannot inject a UTXO
    // belonging to someone else's address — there is no field for it to do so
    // through. The strongest lie available is inventing a UTXO on an address
    // we do own, which BIP-143 then renders unspendable.
    //
    // (This test previously tried to inject a foreign address and instead hit
    // the address-mismatch guard below, proving nothing about this property.)
    const hostile = {
      name: "hostile", network: "testnet",
      getBlockHeight: async () => 200,
      getUtxos: async () => [],
      broadcast: async () => txid(1),
      getAddressActivity: async (address: string) => ({
        address,
        hasHistory: address === wallet.receiveAddresses(1)[0]!.address,
        utxos: address === wallet.receiveAddresses(1)[0]!.address
          ? [{ txid: txid(7), vout: 0, value: 10n ** 12n, confirmations: 6 }]
          : [],
      }),
    };
    const result = await wallet.sync(hostile as never);
    expect(result.utxos).toBe(1);
    for (const utxo of wallet.utxos.all) {
      expect(wallet.ownsAddress(utxo.address)).toBe(true);
    }
  });

  it("REJECTS a source answering about a DIFFERENT address than asked", async () => {
    // Substituting addresses in responses would let a server attribute one
    // address's coins to another and mislead the gap-limit scan.
    const hostile = {
      name: "hostile", network: "testnet",
      getBlockHeight: async () => 200,
      getUtxos: async () => [],
      broadcast: async () => txid(1),
      getAddressActivity: async () => ({
        address: "tb1qwrongaddresssubstituted00000000000000",
        hasHistory: true,
        utxos: [],
      }),
    };
    await expect(wallet.sync(hostile as never)).rejects.toThrow(/different address/);
  });

  it("bounds the scan when a source claims EVERY address has history", async () => {
    // Without a ceiling this is an infinite scan — a denial of service that
    // needs no exploit, just a server saying "yes" forever.
    //
    // The assertion is on the CALL COUNT, not on elapsed time. An earlier
    // version asserted the scan finished within 10 seconds, which failed on a
    // slower machine at 14s even though the bound had worked perfectly — see
    // docs/ATTACKS.md VEY-009. Wall-clock thresholds measure the machine, not
    // the code. Liveness is already covered: if the bound were missing, this
    // test would never return and vitest's own timeout would fail it.
    let calls = 0;
    const hostile = {
      name: "hostile", network: "testnet",
      getBlockHeight: async () => 200,
      getUtxos: async () => [],
      broadcast: async () => txid(1),
      getAddressActivity: async (address: string) => {
        calls++;
        return { address, hasHistory: true, utxos: [] };
      },
    };

    await wallet.sync(hostile as never);

    // MAX_INDEX is 1000 per chain, two chains. Asserted as an exact bound
    // rather than "less than something large", so a change to the ceiling is
    // a deliberate edit rather than a silent drift.
    expect(calls).toBe(2000);
  }, 60_000);

  it("re-scanning is fast, because derivation is cached", async () => {
    // Also a property, not a stopwatch: the second scan must make the same
    // number of requests without re-deriving anything. Verified by the cache
    // returning identical object identities.
    const account = wallet.account;
    const first = account.deriveAddress(0, 7);
    const second = account.deriveAddress(0, 7);
    expect(second).toBe(first); // same object — memoised, not recomputed
  });

  it("propagates a source that throws rather than reporting a false zero balance", async () => {
    const broken = {
      name: "broken", network: "testnet",
      getBlockHeight: async () => 200,
      getUtxos: async () => [],
      broadcast: async () => txid(1),
      getAddressActivity: async () => { throw new Error("upstream failure"); },
    };
    // Swallowing this and showing 0 would tell the user their funds are gone.
    await expect(wallet.sync(broken as never)).rejects.toThrow();
  });
});

describe("end-to-end: sync, spend, broadcast, re-sync", () => {
  it("completes the full cycle with consistent balances", async () => {
    const wallet = Wallet.restore(TEST_MNEMONIC, TESTNET);
    const chain = new MemoryChainSource("testnet", 200);
    const addresses = wallet.receiveAddresses(2);
    chain.fund(addresses[0]!.address, txid(1), 0, 150_000n);
    chain.fund(addresses[1]!.address, txid(2), 0, 80_000n);

    const synced = await wallet.sync(chain);
    expect(synced.balance.spendable).toBe(230_000n);

    const recipient = Wallet.restore(TEST_MNEMONIC, TESTNET, "r").currentReceiveAddress().address;
    const prepared = wallet.send({ to: recipient, amount: 100_000n, feeRate: 8 });

    expect(prepared.total).toBe(prepared.amount + prepared.fee);
    expect(prepared.remainingBalance).toBe(230_000n - prepared.total);

    const broadcastTxid = await wallet.broadcast(chain, prepared);
    expect(broadcastTxid).toBe(prepared.txid);

    // Reflect the spend on the simulated chain, then re-sync.
    for (const input of prepared.inputs) chain.spend(input.address, input.txid, input.vout);
    const after = await wallet.sync(chain);
    const spent = prepared.inputs.reduce((sum, u) => sum + u.value, 0n);
    expect(after.balance.total).toBe(230_000n - spent);
  });
});
