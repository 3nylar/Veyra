# Regtest Integration Testing

> **Why this matters more than the other 519 tests.**
>
> Every other test in this repository validates Veyra against *my reading of
> the specifications*. These validate it against Bitcoin Core — an independent
> implementation that **is** the specification.
>
> Consensus rules are not fully documented anywhere. A transaction can satisfy
> every rule I know about and still be rejected for one I have never heard of.
> No amount of unit testing closes that gap, because unit tests only check the
> rules their author already knows.
>
> When `sendrawtransaction` returns a txid, that is Bitcoin Core saying: *this
> transaction is valid*. Nothing else in this repository can say that.

---

## What regtest is

A private Bitcoin network you run locally. Coins have no value, you mine blocks
on demand, and you control every variable — but it runs the **same consensus
code as mainnet**. That is the entire point: a transaction regtest accepts is a
transaction mainnet accepts, modulo relay policy.

---

## 1. Install Bitcoin Core

Download from **https://bitcoincore.org/en/download/** and verify the
signatures. (The download page links the `SHA256SUMS` file and its signature;
verifying is a good habit and takes two minutes.)

On Windows, `bitcoind.exe` installs to:

```
C:\Program Files\Bitcoin\daemon\bitcoind.exe
```

---

## 2. Create a regtest configuration

### ⚠️ Which directory?

Bitcoin Core's data directory on Windows differs by version:

| Version | Location |
| --- | --- |
| Older | `%APPDATA%\Bitcoin` (AppData\**Roaming**) |
| Recent | `%LOCALAPPDATA%\Bitcoin` (AppData\**Local**) |

The installer's welcome screen shows which one yours uses. Writing to the wrong
one produces `RPC authentication failed` — the node starts with no credentials
configured and rejects everything. See [ATTACKS.md](ATTACKS.md) VEY-010.

**Write to both.** Paste this into PowerShell:

```powershell
$conf = @"
regtest=1
server=1
fallbackfee=0.0001

[regtest]
rpcuser=veyra
rpcpassword=veyra
rpcport=18443
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
"@
foreach ($dir in @("$env:APPDATA\Bitcoin", "$env:LOCALAPPDATA\Bitcoin")) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $conf | Set-Content "$dir\bitcoin.conf"
}
```

Then verify the node reads it:

```powershell
& "C:\Program Files\Bitcoin\daemon\bitcoin-cli.exe" -regtest getblockchaininfo
```

Expect `"chain": "regtest"`. An auth error here means the config is still in the
wrong place.

<details><summary>Config file contents, for reference</summary>

```ini
regtest=1
server=1
fallbackfee=0.0001

[regtest]
rpcuser=veyra
rpcpassword=veyra
rpcport=18443
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

</details>

**`fallbackfee` is required.** Without it, the node has no fee estimates on a
fresh chain and wallet operations fail with a confusing error.

**These credentials are for regtest only.** They are deliberately trivial
because the coins are worthless and the node binds to localhost. Never reuse
this pattern for anything holding real funds — prefer `rpcauth` with a hashed
password there.

---

## 3. Start the node

```powershell
& "C:\Program Files\Bitcoin\daemon\bitcoind.exe" -regtest
```

Leave it running. In a second terminal, confirm it is alive:

```powershell
& "C:\Program Files\Bitcoin\daemon\bitcoin-cli.exe" -regtest getblockchaininfo
```

You should see `"chain": "regtest"`. A fresh regtest chain starts at block 0.

---

## 4. Run the integration tests

```powershell
$env:VEYRA_REGTEST_RPC = "http://127.0.0.1:18443"
$env:VEYRA_REGTEST_USER = "veyra"
$env:VEYRA_REGTEST_PASS = "veyra"

npm run test:regtest
```

The suite handles the rest: it creates a node wallet, mines the 101 blocks
needed to mature a coinbase output, funds Veyra addresses, and exercises the
full lifecycle.

**First run takes a couple of minutes** because of the initial mining.

---

## What the tests prove

| Test | What it establishes |
| --- | --- |
| Core accepts a Veyra transaction | **The headline result.** Our signing path produces something the real network accepts |
| Core computes the same txid | Our serialisation is byte-exact — no local test can prove this |
| Core rejects a tampered recipient | The network enforces what our signature commits to |
| Multi-input transactions | Per-input sighash construction is correct |
| Change is spendable | Change bugs are subtle: the transaction relays fine, and the loss only appears when you try to spend what came back |
| Restored wallet finds funds | The mnemonic is a real backup, not just a valid-looking phrase |
| 1 sat/vB is accepted | Our `MIN_RELAY_FEE_RATE` matches Core's policy rather than being a number I chose |

---

## Without a node

The suite **skips**, and says so loudly:

```
⚠️  Regtest integration tests were skipped.
   Consensus validation against Bitcoin Core has NOT been performed.
```

This is deliberate. A skipped test reports honestly that verification did not
happen. A mock standing in for a node would report success while verifying
nothing — strictly worse than an admitted gap.

`MemoryChainSource` is **not** a substitute. It does not validate transactions,
enforce consensus, or check signatures. A broadcast succeeding there means
nothing about the real network.

---

## Useful commands

```powershell
$cli = "C:\Program Files\Bitcoin\daemon\bitcoin-cli.exe"

# Mine blocks to an address
& $cli -regtest generatetoaddress 10 <address>

# Inspect a transaction Veyra produced
& $cli -regtest decoderawtransaction <hex>

# Ask why a transaction would be rejected, without broadcasting it
& $cli -regtest testmempoolaccept '["<hex>"]'

# Node wallet balance
& $cli -regtest -rpcwallet=veyra-test getbalance

# Start over completely
& $cli -regtest stop
Remove-Item -Recurse "$env:APPDATA\Bitcoin\regtest"
```

`testmempoolaccept` is the most useful of these when debugging: it returns
Core's exact rejection reason without publishing anything.

---

## Troubleshooting

**`RPC authentication failed`** — nine times out of ten the config file is in
the directory your Bitcoin Core version does not read. Write it to both (see
above). Otherwise: `rpcuser`/`rpcpassword` must be under the `[regtest]`
section, or before any section header.

**A "Welcome to Bitcoin Core" window appears, offering to download 856 GB** —
you launched `bitcoin-qt.exe`, the GUI wallet. Cancel it. You want
`bitcoind.exe`, in the `daemon` folder, which reads the regtest config and
downloads nothing.

**`Loading block index...`** — the node is still starting. Wait and retry.

**`Insufficient funds` from the node wallet** — fewer than 101 blocks exist, so
no coinbase output has matured. Mine more:
`& $cli -regtest generatetoaddress 101 <address>`

**`Fee estimation failed`** — `fallbackfee` is missing from `bitcoin.conf`.

**Tests hang** — `scantxoutset` scans the whole UTXO set on each address query.
On regtest this is fast; if it is slow, the chain has grown large and
`Remove-Item -Recurse "$env:APPDATA\Bitcoin\regtest"` will reset it.

---

## A known limitation of this chain source

`BitcoinRpcChainSource` uses `scantxoutset`, which sees **unspent outputs
only**. An address that received and then spent everything looks *unused* to
it, whereas Esplora would report history.

Consequence: the gap-limit scan may stop earlier against a node than against
Esplora, potentially missing funds beyond a fully-spent address. For regtest
testing this is acceptable. Production use against a real node would need
`importdescriptors` plus `listunspent` instead, which is **not implemented**.

The trade-off was deliberate: `scantxoutset` needs no wallet and mutates no
node state, so one test cannot leave imported descriptors behind to corrupt the
next. That is worth more in a test harness than query speed.
