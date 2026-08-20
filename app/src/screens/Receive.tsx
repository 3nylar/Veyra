/**
 * RECEIVE (§23)
 *
 * Address, QR, network, copy, and the verification the address carries.
 *
 * The network is stated in words rather than implied by the address prefix.
 * "bcrt1q…" means regtest to someone who already knows; a person who does not
 * know is exactly the person who needs telling.
 */
import type { AddressInfo } from "../api/client.js";
import { Card, Button, Notice } from "../components/Primitives.js";
import { AddressDisplay } from "../components/AddressDisplay.js";
import { CopyButton } from "../components/CopyButton.js";
import { QrCode } from "../components/QrCode.js";

export function Receive({
  address, isMainnet, onNext, onBack,
}: {
  address: AddressInfo | null;
  isMainnet: boolean;
  onNext: () => void;
  onBack: () => void;
}) {
  if (!address) {
    return (
      <Card label="Receive">
        <p className="empty">Loading an address…</p>
      </Card>
    );
  }

  return (
    <>
      {isMainnet ? (
        <Notice tone="danger">
          This is a <strong>mainnet</strong> address. Bitcoin sent here is real
          and cannot be reversed.
        </Notice>
      ) : (
        <Notice tone="info">
          This is a <strong>{address.network}</strong> address. It only accepts{" "}
          {address.network} coins, which have no value. Sending real bitcoin
          here would lose it permanently.
        </Notice>
      )}

      <Card label={`Receive on ${address.network}`}>
        <QrCode value={address.address} />
        <AddressDisplay address={address.address} explain />

        <div className="spacer" />
        <div className="btn-row">
          <CopyButton value={address.address} label="Copy address" />
          <Button onClick={onNext}>New address</Button>
        </div>

        <div className="spacer" />
        <p className="field-hint">
          Derivation path <code style={{ fontFamily: "var(--mono)" }}>{address.path}</code>.
          A fresh address for each payment keeps them from being linked to each
          other on the blockchain.
        </p>
      </Card>

      <Button variant="ghost" onClick={onBack}>
        ← Back to wallet
      </Button>
    </>
  );
}
