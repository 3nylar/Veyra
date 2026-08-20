/**
 * SECURITY CENTRE (§26)
 *
 * Verifiable facts only.
 *
 * There is deliberately no score. "92% secure" implies a measurement nobody
 * performed, and its real effect is to make the user stop reading — which is
 * the opposite of what a security screen is for. Every line here is something
 * the user could check themselves against the source.
 *
 * The warnings are not hidden behind a disclosure. If this software is holding
 * keys in process memory and has never been audited, the place to say so is
 * where someone deciding whether to trust it will look.
 */
import type { SecurityStatus, WalletSummary } from "../api/client.js";
import { Card, Notice, Row, Status } from "../components/Primitives.js";

export function Security({
  status, summary, onBack,
}: {
  status: SecurityStatus | null;
  summary: WalletSummary | null;
  onBack: () => void;
}) {
  if (!status) {
    return (
      <Card label="Security">
        <p className="empty">Loading…</p>
      </Card>
    );
  }

  return (
    <>
      {status.isMainnet ? (
        <Notice tone="danger">
          <strong>Mainnet.</strong> This wallet controls real bitcoin.
        </Notice>
      ) : (
        <Notice tone="info">
          <strong>{status.network}.</strong> Coins on this network have no
          value, which is what makes it safe to experiment.
        </Notice>
      )}

      <Card label="Wallet">
        <Row label="Network" value={status.network} />
        <Row label="Type" value={status.walletType} />
        {summary ? <Row label="Derivation path" value={summary.derivationPath} /> : null}
        {summary ? <Row label="Fingerprint" value={summary.fingerprint} /> : null}
        {summary ? <Row label="Address type" value={summary.addressType} /> : null}
      </Card>

      <Card label="Key management">
        <Row label="Keys held by" value={status.keysHeldBy} />
        <Row label="Backup" value="The mnemonic shown once at creation" tone="muted" />
        <Row label="Recoverable by Veyra" value="No" tone="danger" />
        <p className="field-hint" style={{ marginTop: "var(--s3)" }}>
          Nobody can restore this wallet from anything but the phrase. That is
          what self-custodial means: there is no account to recover, and no
          support desk that can help.
        </p>
      </Card>

      <Card label="Chain source">
        {status.chainSource ? (
          <>
            <Row label="Connected to" value={status.chainSource} />
            {/* Spread rather than passing `undefined`: under
                exactOptionalPropertyTypes an optional prop must be ABSENT,
                not present-and-undefined. */}
            <Row
              label="Operated by"
              value={status.chainSourceIsThirdParty ? "A third party" : "You"}
              {...(status.chainSourceIsThirdParty ? { tone: "danger" as const } : {})}
            />
            {status.privacyWarning ? (
              <>
                <div className="spacer" />
                <Notice tone="warning">{status.privacyWarning}</Notice>
              </>
            ) : null}
          </>
        ) : (
          <>
            <Status tone="warning">No chain source configured</Status>
            <p className="field-hint" style={{ marginTop: "var(--s3)" }}>
              Balances will stay empty until one is set. Nothing contacts a
              third party unless you configure it.
            </p>
          </>
        )}
      </Card>

      <Card label="What you should know">
        {status.warnings.map((warning) => (
          <div className="row" key={warning}>
            <span className="row-key" style={{ flex: 1, textAlign: "left" }}>
              {warning}
            </span>
          </div>
        ))}
      </Card>

      <Card label="Not verified">
        <p className="field-hint" style={{ marginTop: 0 }}>
          This software has never handled real funds, has not been independently
          reviewed, and no transaction it produced has yet been accepted by
          Bitcoin Core. Those gaps are recorded in the project's threat model
          rather than left for you to discover.
        </p>
      </Card>

      <button className="btn" data-variant="ghost" onClick={onBack}>
        ← Back to wallet
      </button>
    </>
  );
}
