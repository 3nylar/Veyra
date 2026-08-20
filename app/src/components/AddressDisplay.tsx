/**
 * ADDRESS DISPLAY — the one piece of cryptographic structure this interface
 * makes visible.
 *
 * A Bech32 address has three parts, and every wallet renders them as one
 * undifferentiated string:
 *
 *     bcrt1q  w508d6qejxtdg4y5r3zarvary0c5xw7k  ygt080
 *     ─────   ────────────────────────────────  ──────
 *     HRP     witness program (the payload)     BCH checksum
 *
 * Those last six characters are not part of the address in any meaningful
 * sense — they are an error-detecting code with a *proven* bound: any four or
 * fewer mistyped characters are guaranteed to be caught, and longer errors
 * escape with probability around one in a billion.
 *
 * That is the single most user-protective property of the format, and it is
 * completely invisible in every wallet interface. Showing it costs nothing and
 * tells the user something true: the reason a typo cannot quietly send their
 * money to a stranger.
 *
 * The HRP is tinted because it is what distinguishes networks — and because
 * the HRP is folded INTO the checksum, so a mainnet address does not merely
 * look wrong on testnet, it fails validation outright.
 */

const CHECKSUM_LENGTH = 6;

export function AddressDisplay({
  address,
  explain = false,
}: {
  address: string;
  explain?: boolean;
}) {
  const separator = address.lastIndexOf("1");

  // Not Bech32 — render plainly rather than mislabelling parts of it.
  if (separator < 1 || address.length < separator + 1 + CHECKSUM_LENGTH) {
    return <div className="address">{address}</div>;
  }

  const hrp = address.slice(0, separator + 1);
  const body = address.slice(separator + 1, address.length - CHECKSUM_LENGTH);
  const checksum = address.slice(address.length - CHECKSUM_LENGTH);

  return (
    <>
      <div className="address">
        <span className="address-hrp">{hrp}</span>
        <span className="address-body">{body}</span>
        <span className="address-checksum" title="Bech32 checksum">
          {checksum}
        </span>
      </div>
      {explain ? (
        <p className="address-note">
          The underlined last six characters are a checksum. They catch any four
          or fewer mistyped characters, so a typo cannot quietly send your
          bitcoin somewhere else.
        </p>
      ) : null}
    </>
  );
}

/** A shortened address for lists, where the full string would crowd everything. */
export function AddressShort({ address }: { address: string }) {
  if (address.length <= 20) return <span className="address">{address}</span>;
  return (
    <span className="address" title={address}>
      {address.slice(0, 10)}…{address.slice(-8)}
    </span>
  );
}
