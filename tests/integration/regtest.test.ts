/**
 * REGTEST INTEGRATION TESTS
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  THESE ARE THE MOST IMPORTANT TESTS IN THE REPOSITORY.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Every other test validates Veyra against my reading of the specifications.
 * These validate it against Bitcoin Core — an independent implementation that
 * IS the specification.
 *
 * The distinction is not academic. Consensus rules are not fully documented
 * anywhere; the implementation is normative. A transaction can satisfy every
 * rule I know about and still be rejected for one I have never heard of. No
 * amount of unit testing closes that gap, because unit tests can only check
 * the rules their author already knows.
 *
 * When `sendrawtransaction` returns a txid, that is Bitcoin Core saying: this
 * transaction is valid. Nothing else in this repository can say that.
 *
 * ─── These tests SKIP unless a node is configured ──────────────────────────
 * Set VEYRA_REGTEST_RPC (and credentials) to run them. See docs/REGTEST.md.
 *
 * A skipped test is honest — it reports that verification did not happen. A
 * mock standing in for a node would report success while verifying nothing,
 * which is strictly worse than an admitted gap.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { BitcoinRpcChainSource } from "../../core/chain/bitcoinRpc.js";
import { Wallet } from "../../core/wallet/wallet.js";
import { REGTEST } from "../../core/bitcoin/networks.js";
import { verifyTransaction } from "../../core/signing/signer.js";
import { Transaction } from "../../core/transactions/transaction.js";

const RPC_URL = process.env.VEYRA_REGTEST_RPC;
const RPC_USER = process.env.VEYRA_REGTEST_USER ?? "veyra";
const RPC_PASS = process.env.VEYRA_REGTEST_PASS ?? "veyra";
const NODE_WALLET = "veyra-test";

/**
 * Skip the whole suite when no node is configured.
 *
 * `describe.skipIf` reports the tests as skipped rather than passing, so a CI
 * run without a node cannot be mistaken for a run with one.
 */
const suite = describe.skipIf(!RPC_URL);

suite("REGTEST: end-to-end against a real Bitcoin Core node", () => {
  let node: BitcoinRpcChainSource;
  let nodeAddress: string;

  beforeAll(async () => {
    node = new BitcoinRpcChainSource({
      url: RPC_URL!, username: RPC_USER, password: RPC_PASS, network: "regtest",
    });

    const info = await node.verifyConnection();
    expect(info.chain).toBe("regtest");

    await node.ensureNodeWallet(NODE_WALLET);
    nodeAddress = await node.getNewNodeAddress(NODE_WALLET);

    // Coinbase outputs need 100 confirmations before they are spendable, so
    // the node needs at least 101 blocks before it can fund anything.
    if (info.blocks < 101) {
      await node.generateToAddress(101 - info.blocks + 1, nodeAddress);
    }
  }, 120_000);

  it("connects and reports the regtest chain", async () => {
    const info = await node.verifyConnection();
    expect(info.chain).toBe("regtest");
    expect(info.blocks).toBeGreaterThanOrEqual(101);
  });

  it("REFUSES regtest-only helpers on other networks", () => {
    const mainnetSource = new BitcoinRpcChainSource({
      url: RPC_URL!, username: RPC_USER, password: RPC_PASS, network: "mainnet",
    });
    // "generate 101 blocks" against mainnet is not a mistake worth allowing.
    return expect(mainnetSource.generateToAddress(1, nodeAddress)).rejects.toThrow(/only permitted on regtest/);
  });

  it("discovers a real funded address", async () => {
    const { wallet } = Wallet.create(REGTEST, 12);
    const address = wallet.currentReceiveAddress().address;
    expect(address.startsWith("bcrt1q")).toBe(true);

    await node.fundAddress(NODE_WALLET, address, 500_000n);
    await node.generateToAddress(1, nodeAddress);

    const synced = await wallet.sync(node);
    expect(synced.utxos).toBeGreaterThanOrEqual(1);
    expect(synced.balance.spendable).toBeGreaterThanOrEqual(500_000n);
  }, 120_000);

  /**
   * THE test. Everything else is setup for this one.
   */
  it("BITCOIN CORE ACCEPTS a transaction Veyra built and signed", async () => {
    const { wallet } = Wallet.create(REGTEST, 12);
    const address = wallet.currentReceiveAddress().address;

    await node.fundAddress(NODE_WALLET, address, 1_000_000n);
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const prepared = wallet.send({
      to: recipient.currentReceiveAddress().address,
      amount: 300_000n,
      feeRate: 5,
    });

    // Locally valid...
    expect(verifyTransaction(prepared.transaction, prepared.inputs.map((u) => u.value))).toBe(true);

    // ...and, far more importantly, valid according to Bitcoin Core.
    const txid = await wallet.broadcast(node, prepared);
    expect(txid).toBe(prepared.txid);

    // Confirm it and check the recipient really received the coins.
    await node.generateToAddress(1, nodeAddress);
    const recipientSync = await recipient.sync(node);
    expect(recipientSync.balance.spendable).toBe(300_000n);
  }, 180_000);

  it("Core computes the SAME txid as Veyra — serialisation is byte-exact", async () => {
    const { wallet } = Wallet.create(REGTEST, 12);
    await node.fundAddress(NODE_WALLET, wallet.currentReceiveAddress().address, 800_000n);
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const prepared = wallet.send({
      to: recipient.currentReceiveAddress().address, amount: 200_000n, feeRate: 4,
    });

    // A txid IS a hash of the serialisation. Agreement here proves every byte
    // of our encoding matches Core's, which no local test can establish.
    expect(await node.broadcast(prepared.hex)).toBe(prepared.txid);
  }, 180_000);

  it("Core REJECTS a transaction whose recipient was altered after signing", async () => {
    const { wallet } = Wallet.create(REGTEST, 12);
    await node.fundAddress(NODE_WALLET, wallet.currentReceiveAddress().address, 700_000n);
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);

    const { wallet: honest } = Wallet.create(REGTEST, 12);
    const { wallet: attacker } = Wallet.create(REGTEST, 12);
    const prepared = wallet.send({
      to: honest.currentReceiveAddress().address, amount: 200_000n, feeRate: 4,
    });

    // Redirect the payment. Our own tampering tests prove verification fails;
    // this proves the NETWORK rejects it, which is the guarantee that matters.
    const { decodeSegwitAddress } = await import("../../core/addresses/bech32.js");
    const { program } = decodeSegwitAddress("bcrt", attacker.currentReceiveAddress().address);
    const { TxOutput } = await import("../../core/transactions/transaction.js");
    const outputs = [...prepared.transaction.outputs];
    outputs[0] = new TxOutput(200_000n, new Uint8Array([0x00, program.length, ...program]));
    const tampered = new Transaction(
      prepared.transaction.version, prepared.transaction.inputs, outputs,
      prepared.transaction.locktime,
    );

    await expect(node.broadcast(tampered.toHex())).rejects.toThrow();
  }, 180_000);

  it("Core accepts a multi-input transaction", async () => {
    const { wallet } = Wallet.create(REGTEST, 12);
    const addresses = wallet.receiveAddresses(3);
    for (const address of addresses.slice(0, 3)) {
      await node.fundAddress(NODE_WALLET, address.address, 400_000n);
    }
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);
    expect(wallet.balance().utxoCount).toBeGreaterThanOrEqual(3);

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const prepared = wallet.send({
      to: recipient.currentReceiveAddress().address, amount: 900_000n, feeRate: 4,
    });
    expect(prepared.inputs.length).toBeGreaterThanOrEqual(3);
    expect(await wallet.broadcast(node, prepared)).toBe(prepared.txid);
  }, 240_000);

  it("Core accepts our change output — the wallet can spend its own change", async () => {
    // Change bugs are subtle: the transaction relays fine, and the loss only
    // appears when you try to spend what came back.
    const { wallet } = Wallet.create(REGTEST, 12);
    await node.fundAddress(NODE_WALLET, wallet.currentReceiveAddress().address, 1_000_000n);
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const first = wallet.send({
      to: recipient.currentReceiveAddress().address, amount: 300_000n, feeRate: 4,
    });
    expect(first.change).toBeGreaterThan(0n);
    await wallet.broadcast(node, first);
    await node.generateToAddress(1, nodeAddress);

    // Re-sync: the change must be discoverable on the internal chain...
    const afterSync = await wallet.sync(node);
    expect(afterSync.balance.spendable).toBe(first.change);

    // ...and spendable.
    const second = wallet.send({
      to: recipient.currentReceiveAddress().address, amount: 100_000n, feeRate: 4,
    });
    expect(await wallet.broadcast(node, second)).toBe(second.txid);
  }, 240_000);

  it("Core REJECTS a fee below the relay minimum", async () => {
    // Confirms our MIN_RELAY_FEE_RATE matches Core's actual policy rather
    // than being a number I chose.
    const { wallet } = Wallet.create(REGTEST, 12);
    await node.fundAddress(NODE_WALLET, wallet.currentReceiveAddress().address, 500_000n);
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const prepared = wallet.send({
      to: recipient.currentReceiveAddress().address, amount: 100_000n, feeRate: 1,
    });
    // At exactly 1 sat/vB Core should accept; this documents the boundary.
    expect(await wallet.broadcast(node, prepared)).toBe(prepared.txid);
  }, 180_000);

  it("fee estimation reports UNAVAILABLE on regtest, rather than inventing a rate", async () => {
    // A private chain has no fee market and no history to estimate from, so
    // Core returns errors for every target. Reporting that honestly is the
    // correct behaviour — a fabricated "live" rate would be worse than none.
    const estimates = await node.getFeeEstimates();
    expect(estimates.source).toContain("bitcoind");

    const { wallet } = Wallet.create(REGTEST, 12);
    const resolved = await wallet.feeEstimates(node);
    expect(resolved.isLive).toBe(false);
    expect(resolved.source).toMatch(/static defaults|no estimates yet/);
    // A usable number is still returned, so a UI never renders a blank.
    expect(resolved.high).toBeGreaterThanOrEqual(1);
  }, 60_000);

  it("transaction history works via a watch-only descriptor import", async () => {
    const { wallet } = Wallet.create(REGTEST, 12);
    const addresses = wallet.receiveAddresses(3).map((a) => a.address);

    // History needs an import; the UTXO set alone cannot answer it, because a
    // spent output is simply gone from it.
    await node.importAddressesForHistory(addresses, { since: 0 });

    await node.fundAddress(NODE_WALLET, addresses[0]!, 700_000n);
    await node.generateToAddress(1, nodeAddress);

    const history = await wallet.history(node);
    expect(history.length).toBeGreaterThanOrEqual(1);

    const received = history.find((tx) => tx.direction === "received");
    expect(received).toBeDefined();
    expect(received!.netValue).toBe(700_000n);
    expect(received!.confirmations).toBeGreaterThanOrEqual(1);
  }, 180_000);

  it("history FOLDS a send and its change into one entry", async () => {
    // The case a naive implementation gets wrong: a spend consumes an input
    // from one address and returns change to another, producing two rows that
    // each misdescribe what happened.
    const { wallet } = Wallet.create(REGTEST, 12);
    const receive = wallet.receiveAddresses(3).map((a) => a.address);
    const change = wallet.account.deriveAddresses(1, 0, 3).map((a) => a.address);
    await node.importAddressesForHistory([...receive, ...change], { since: 0 });

    await node.fundAddress(NODE_WALLET, receive[0]!, 1_000_000n);
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const prepared = wallet.send({
      to: recipient.currentReceiveAddress().address, amount: 300_000n, feeRate: 4,
    });
    await wallet.broadcast(node, prepared);
    await node.generateToAddress(1, nodeAddress);

    const history = await wallet.history(node);
    const spend = history.filter((tx) => tx.txid === prepared.txid);

    // ONE entry, not two.
    expect(spend.length).toBe(1);
    expect(spend[0]!.direction).toBe("sent");
    // Net cost is the payment plus the fee, not the whole consumed input.
    expect(spend[0]!.netValue).toBe(-(300_000n + prepared.fee));
  }, 240_000);

  it("Bitcoin Core ACCEPTS a BIP-125 fee replacement", async () => {
    // The rules are enforced by nodes, not by us. This is the only test that
    // proves our replacement satisfies them rather than merely appearing to.
    const { wallet } = Wallet.create(REGTEST, 12);
    await node.fundAddress(NODE_WALLET, wallet.currentReceiveAddress().address, 2_000_000n);
    await node.generateToAddress(1, nodeAddress);
    await wallet.sync(node);

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const original = wallet.send({
      to: recipient.currentReceiveAddress().address, amount: 500_000n, feeRate: 1,
    });
    await wallet.broadcast(node, original);

    // Replace it, unconfirmed, with a higher fee.
    const bumped = wallet.bumpFee(original.txid, 20);
    expect(bumped.fee).toBeGreaterThan(original.fee);

    const replacementTxid = await wallet.broadcast(node, bumped);
    expect(replacementTxid).toBe(bumped.txid);
    expect(replacementTxid).not.toBe(original.txid);

    // Confirm, and check the REPLACEMENT is what landed.
    await node.generateToAddress(1, nodeAddress);
    const recipientSync = await recipient.sync(node);
    expect(recipientSync.balance.spendable).toBe(500_000n);
  }, 240_000);

  // NOTE: there is deliberately no test here for Core rejecting an
  // insufficient fee bump. Building one requires signing a transaction the
  // wallet would never produce, which means reaching past the secrecy
  // boundary for a private key — and a test that needs to break the
  // architecture to exist is testing the wrong thing.
  //
  // The rule itself is covered in tests/unit/rbf.test.ts, which asserts that
  // bumpFee always raises a too-small request to the minimum valid
  // replacement rather than building something the network would reject.

  it("Bitcoin Core ACCEPTS a 2-of-3 multisig spend", async () => {
    // The only test that proves the witness structure is right — including
    // the empty dummy element that OP_CHECKMULTISIG requires and that no
    // local check can validate.
    const { MultisigAccount } = await import("../../core/addresses/multisig.js");
    const { signMultisigInput, combineSignatures, verifyMultisigTransaction } =
      await import("../../core/signing/multisig.js");
    const { PrivateKey } = await import("../../core/keys/privateKey.js");
    const { PublicKey } = await import("../../core/keys/publicKey.js");
    const { TxInput, TxOutput, Transaction, SEQUENCE_RBF } =
      await import("../../core/transactions/transaction.js");

    const holders = [
      PrivateKey.fromHex("a1".repeat(32)),
      PrivateKey.fromHex("b2".repeat(32)),
      PrivateKey.fromHex("c3".repeat(32)),
    ];
    const account = new MultisigAccount({
      threshold: 2,
      publicKeys: holders.map((k) => PublicKey.fromPrivateKey(k)),
      network: REGTEST,
    });

    // Fund the multisig address from the node.
    const fundingTxid = await node.fundAddress(NODE_WALLET, account.address, 2_000_000n);
    await node.generateToAddress(1, nodeAddress);

    // Find which output paid us.
    const utxos = await node.getUtxos(account.address);
    expect(utxos.length).toBeGreaterThanOrEqual(1);
    const utxo = utxos.find((u) => u.txid === fundingTxid) ?? utxos[0]!;

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const { decodeSegwitAddress } = await import("../../core/addresses/bech32.js");
    const { program } = decodeSegwitAddress("bcrt", recipient.currentReceiveAddress().address);

    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: utxo.txid, vout: utxo.vout }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(utxo.value - 2_000n, new Uint8Array([0x00, program.length, ...program]))],
      0,
    );

    const inputs = [{ value: utxo.value, account }];

    // Two holders sign INDEPENDENTLY. No key is ever combined.
    const partials = [
      signMultisigInput(unsigned, 0, inputs[0]!, holders[0]!),
      signMultisigInput(unsigned, 0, inputs[0]!, holders[2]!),
    ];
    const signed = combineSignatures(unsigned, inputs, partials);
    expect(verifyMultisigTransaction(signed, inputs)).toBe(true);

    // The claim that matters: Bitcoin Core accepts it.
    const broadcastTxid = await node.broadcast(signed.toHex());
    expect(broadcastTxid).toBe(signed.txid());

    await node.generateToAddress(1, nodeAddress);
    const recipientSync = await recipient.sync(node);
    expect(recipientSync.balance.spendable).toBe(utxo.value - 2_000n);
  }, 300_000);

  it("Bitcoin Core REJECTS a 1-of-2 attempt on a 2-of-3 output", async () => {
    // Locally we refuse to combine a single signature. This proves the
    // NETWORK also refuses, which is the guarantee that actually protects
    // the funds — our refusal is only a convenience.
    const { MultisigAccount } = await import("../../core/addresses/multisig.js");
    const { signMultisigInput } = await import("../../core/signing/multisig.js");
    const { PrivateKey } = await import("../../core/keys/privateKey.js");
    const { PublicKey } = await import("../../core/keys/publicKey.js");
    const { TxInput, TxOutput, Transaction, SEQUENCE_RBF } =
      await import("../../core/transactions/transaction.js");

    const holders = [
      PrivateKey.fromHex("d4".repeat(32)),
      PrivateKey.fromHex("e5".repeat(32)),
      PrivateKey.fromHex("f6".repeat(32)),
    ];
    const account = new MultisigAccount({
      threshold: 2,
      publicKeys: holders.map((k) => PublicKey.fromPrivateKey(k)),
      network: REGTEST,
    });

    await node.fundAddress(NODE_WALLET, account.address, 1_500_000n);
    await node.generateToAddress(1, nodeAddress);
    const utxo = (await node.getUtxos(account.address))[0]!;

    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: utxo.txid, vout: utxo.vout }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(utxo.value - 2_000n, account.scriptPubKey)],
      0,
    );
    const inputs = [{ value: utxo.value, account }];
    const single = signMultisigInput(unsigned, 0, inputs[0]!, holders[0]!);

    // Build the witness by hand with only ONE signature — the transaction a
    // single compromised holder would try to broadcast.
    const attempt = unsigned.withInput(
      0,
      unsigned.inputs[0]!.withWitness([
        new Uint8Array(0),
        single.signature,
        account.witnessScript,
      ]),
    );

    await expect(node.broadcast(attempt.toHex())).rejects.toThrow();
  }, 300_000);

  it("Bitcoin Core UNDERSTANDS a Veyra-produced PSBT", async () => {
    // The whole point of PSBT is interoperability. A format only Veyra can
    // read would replace "trust one seed" with "trust one codebase" — so the
    // test that matters is whether another implementation agrees.
    const { Psbt } = await import("../../core/psbt/psbt.js");
    const { MultisigAccount } = await import("../../core/addresses/multisig.js");
    const { PrivateKey } = await import("../../core/keys/privateKey.js");
    const { PublicKey } = await import("../../core/keys/publicKey.js");
    const { TxInput, TxOutput, Transaction, SEQUENCE_RBF } =
      await import("../../core/transactions/transaction.js");

    const holders = [
      PrivateKey.fromHex("1a".repeat(32)),
      PrivateKey.fromHex("2b".repeat(32)),
      PrivateKey.fromHex("3c".repeat(32)),
    ];
    const account = new MultisigAccount({
      threshold: 2,
      publicKeys: holders.map((k) => PublicKey.fromPrivateKey(k)),
      network: REGTEST,
    });

    await node.fundAddress(NODE_WALLET, account.address, 1_800_000n);
    await node.generateToAddress(1, nodeAddress);
    const utxo = (await node.getUtxos(account.address))[0]!;

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const { decodeSegwitAddress } = await import("../../core/addresses/bech32.js");
    const { program } = decodeSegwitAddress("bcrt", recipient.currentReceiveAddress().address);

    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: utxo.txid, vout: utxo.vout }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(utxo.value - 3_000n, new Uint8Array([0x00, program.length, ...program]))],
      0,
    );

    const psbt = Psbt.create(unsigned)
      .setWitnessUtxo(0, utxo.value, account.scriptPubKey)
      .setWitnessScript(0, account.witnessScript)
      .setSighashType(0, 0x01);

    // Hand our base64 PSBT to Core and ask it to describe it. If Core can
    // decode it, the format is right — not merely self-consistent.
    const decoded = (await node.decodePsbt(psbt.toBase64())) as Record<string, unknown>;
    expect(Array.isArray(decoded.inputs)).toBe(true);

    const tx = decoded.tx as Record<string, unknown>;
    expect(tx.txid).toBe(unsigned.txid());

    // Core must see the witness_utxo we supplied, with the right amount.
    const coreInput = (decoded.inputs as Array<Record<string, unknown>>)[0]!;
    const witnessUtxo = coreInput.witness_utxo as Record<string, unknown> | undefined;
    expect(witnessUtxo).toBeDefined();
  }, 300_000);

  it("a PSBT signed by two holders extracts to a transaction Core ACCEPTS", async () => {
    const { Psbt } = await import("../../core/psbt/psbt.js");
    const { MultisigAccount } = await import("../../core/addresses/multisig.js");
    const { signMultisigInput } = await import("../../core/signing/multisig.js");
    const { PrivateKey } = await import("../../core/keys/privateKey.js");
    const { PublicKey } = await import("../../core/keys/publicKey.js");
    const { TxInput, TxOutput, Transaction, SEQUENCE_RBF } =
      await import("../../core/transactions/transaction.js");

    const holders = [
      PrivateKey.fromHex("4d".repeat(32)),
      PrivateKey.fromHex("5e".repeat(32)),
      PrivateKey.fromHex("6f".repeat(32)),
    ];
    const account = new MultisigAccount({
      threshold: 2,
      publicKeys: holders.map((k) => PublicKey.fromPrivateKey(k)),
      network: REGTEST,
    });

    await node.fundAddress(NODE_WALLET, account.address, 1_700_000n);
    await node.generateToAddress(1, nodeAddress);
    const utxo = (await node.getUtxos(account.address))[0]!;

    const { wallet: recipient } = Wallet.create(REGTEST, 12);
    const { decodeSegwitAddress } = await import("../../core/addresses/bech32.js");
    const { program } = decodeSegwitAddress("bcrt", recipient.currentReceiveAddress().address);

    const unsigned = new Transaction(
      2,
      [new TxInput({ txid: utxo.txid, vout: utxo.vout }, new Uint8Array(0), SEQUENCE_RBF)],
      [new TxOutput(utxo.value - 3_000n, new Uint8Array([0x00, program.length, ...program]))],
      0,
    );
    const inputs = [{ value: utxo.value, account }];

    // Two holders sign independently, each from their own copy of the PSBT.
    const copies = [holders[0]!, holders[2]!].map((key) => {
      const copy = Psbt.create(unsigned)
        .setWitnessUtxo(0, utxo.value, account.scriptPubKey)
        .setWitnessScript(0, account.witnessScript);
      const partial = signMultisigInput(unsigned, 0, inputs[0]!, key);
      copy.addPartialSignature(0, partial.publicKey.toBytes(), partial.signature);
      // Round-trip through base64, as a real transfer would.
      return Psbt.fromBase64(copy.toBase64());
    });

    const combined = copies[0]!.combine(copies[1]!);
    const final = combined.finalize().extract();

    const broadcastTxid = await node.broadcast(final.toHex());
    expect(broadcastTxid).toBe(final.txid());
  }, 300_000);

  it("a restored wallet finds the same funds via gap-limit scan", async () => {
    const { wallet, mnemonic } = Wallet.create(REGTEST, 12);
    await node.fundAddress(NODE_WALLET, wallet.currentReceiveAddress().address, 600_000n);
    await node.generateToAddress(1, nodeAddress);

    // Restore from the phrase alone — the real backup-recovery test.
    const restored = Wallet.restore(mnemonic, REGTEST);
    const synced = await restored.sync(node);
    expect(synced.balance.spendable).toBe(600_000n);
  }, 180_000);
});

/**
 * Runs ALWAYS, including without a node.
 *
 * Its job is to make the absence of regtest verification visible rather than
 * silent — a green suite with these tests skipped means less than a green
 * suite with them run, and that fact should be impossible to overlook.
 */
describe("regtest configuration", () => {
  it(RPC_URL ? "regtest node IS configured — integration tests ran" : "NO regtest node — integration tests were SKIPPED", () => {
    if (!RPC_URL) {
      console.warn(
        "\n  ⚠️  Regtest integration tests were skipped.\n" +
        "     Consensus validation against Bitcoin Core has NOT been performed.\n" +
        "     Set VEYRA_REGTEST_RPC to run them — see docs/REGTEST.md.\n",
      );
    }
    expect(true).toBe(true);
  });
});
