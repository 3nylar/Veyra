/**
 * ACTIVITY — transaction history (§25).
 *
 * Direction is the point. A list showing "0.50000000" tells a user nothing
 * they could act on; "−0.50000000 sent" does. Colour reinforces it but never
 * carries it alone — the sign and the word are both present, so the meaning
 * survives greyscale and colour-blindness.
 */
import { formatBtc, type HistoryEntry } from "../api/client.js";
import { AddressShort } from "./AddressDisplay.js";
import { Empty, Notice } from "./Primitives.js";

function when(entry: HistoryEntry): string {
  if (entry.confirmations === 0) return "In the mempool — not yet confirmed";
  const confirmations = `${entry.confirmations} confirmation${entry.confirmations === 1 ? "" : "s"}`;
  if (!entry.blockTime) return confirmations;
  const date = new Date(entry.blockTime * 1000);
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} · ${confirmations}`;
}

export function Activity({
  entries, unavailable,
}: {
  entries: HistoryEntry[];
  unavailable: boolean;
}) {
  if (unavailable) {
    // Distinguished from "no transactions" deliberately. Saying someone has no
    // history when the lookup failed is a damaging thing to get wrong.
    return (
      <Notice tone="warning">
        Transaction history is unavailable. A Bitcoin Core node needs its
        addresses imported first; Esplora provides history directly.
      </Notice>
    );
  }

  if (entries.length === 0) {
    return <Empty>No transactions yet.</Empty>;
  }

  return (
    <>
      {entries.map((entry) => {
        const value = entry.netValue ?? 0n;
        const sent = value < 0n;
        const internal = entry.direction === "internal";

        return (
          <div className="activity-item" key={entry.txid}>
            <div style={{ minWidth: 0 }}>
              <div className="activity-id">
                <AddressShort address={entry.txid} />
              </div>
              <div className="activity-meta">
                {internal ? "Moved within this wallet" : sent ? "Sent" : "Received"}
                {" · "}
                {when(entry)}
                {entry.fee !== null && sent ? ` · fee ${formatBtc(entry.fee)}` : ""}
              </div>
            </div>
            <span
              className="activity-amount"
              style={{
                color: internal
                  ? "var(--text-muted)"
                  : sent
                    ? "var(--off-white)"
                    : "var(--teal)",
              }}
            >
              {/* The sign is explicit, so meaning does not depend on colour. */}
              {internal ? "" : sent ? "−" : "+"}
              {formatBtc(value < 0n ? -value : value)}
            </span>
          </div>
        );
      })}
    </>
  );
}
