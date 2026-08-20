/**
 * WALLET HOME (§22)
 *
 * Balance, send, receive, recent activity. Calm and minimal.
 *
 * The balance is shown broken into parts rather than as a single number.
 * "Your balance is X" when part of X is unconfirmed or frozen is a claim the
 * user discovers is false at the worst possible moment — when a send fails.
 */
import { formatBtc, formatSats, type Balance, type Utxo, type WalletSummary } from "../api/client.js";
import { Card, Button, Empty, Status } from "../components/Primitives.js";
import { AddressShort } from "../components/AddressDisplay.js";

export function Home({
  summary, balance, utxos, loading, onSend, onReceive, onSync,
}: {
  summary: WalletSummary | null;
  balance: Balance | null;
  utxos: Utxo[];
  loading: boolean;
  onSend: () => void;
  onReceive: () => void;
  onSync: () => void;
}) {
  return (
    <>
      <Card>
        <h2 className="card-label">Spendable balance</h2>
        <p className="balance-primary">
          {balance ? formatBtc(balance.spendable) : "—"}
          <span className="balance-unit">BTC</span>
        </p>
        <p className="balance-secondary">
          {balance ? `${formatSats(balance.spendable)} sat` : ""}
        </p>

        {balance ? (
          <div className="balance-breakdown">
            <div className="breakdown-item">
              <span className="breakdown-key">Total</span>
              <span className="breakdown-value">{formatBtc(balance.total)}</span>
            </div>
            {balance.unconfirmed > 0n ? (
              <div className="breakdown-item">
                <span className="breakdown-key">Unconfirmed</span>
                <span className="breakdown-value" style={{ color: "var(--warning)" }}>
                  {formatBtc(balance.unconfirmed)}
                </span>
              </div>
            ) : null}
            {balance.unavailable > 0n ? (
              <div className="breakdown-item">
                <span className="breakdown-key">Unavailable</span>
                <span className="breakdown-value" style={{ color: "var(--text-muted)" }}>
                  {formatBtc(balance.unavailable)}
                </span>
              </div>
            ) : null}
            <div className="breakdown-item">
              <span className="breakdown-key">Coins</span>
              <span className="breakdown-value">{balance.utxoCount}</span>
            </div>
          </div>
        ) : null}

        <div className="spacer" />
        <div className="btn-row">
          <Button variant="primary" onClick={onSend} disabled={!balance || balance.spendable === 0n}>
            Send
          </Button>
          <Button onClick={onReceive}>Receive</Button>
        </div>
      </Card>

      <Card label="Coins">
        {utxos.length === 0 ? (
          <Empty>
            No coins yet. Use Receive to get an address, then sync once it has been paid.
          </Empty>
        ) : (
          utxos.map((utxo) => (
            <div className="activity-item" key={`${utxo.txid}:${utxo.vout}`}>
              <div>
                <div className="activity-id">
                  <AddressShort address={utxo.txid} />
                  <span style={{ color: "var(--text-dim)" }}>:{utxo.vout}</span>
                </div>
                <div className="activity-meta">
                  {utxo.confirmations === 0
                    ? "In the mempool — not yet confirmed"
                    : `${utxo.confirmations} confirmation${utxo.confirmations === 1 ? "" : "s"}`}
                  {utxo.frozen ? " · frozen" : ""}
                </div>
              </div>
              <span className="activity-amount">{formatBtc(utxo.value)}</span>
            </div>
          ))
        )}
        <div className="spacer" />
        <div className="btn-row">
          <Button onClick={onSync} disabled={loading}>
            {loading ? "Syncing…" : "Sync with the chain"}
          </Button>
        </div>
      </Card>

      {summary ? (
        <Card label="Wallet">
          <Status tone="healthy">
            {summary.addressType} · {summary.derivationPath} · {summary.fingerprint}
          </Status>
        </Card>
      ) : null}
    </>
  );
}
