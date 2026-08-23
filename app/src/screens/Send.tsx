/**
 * SEND (§24)
 *
 *     Recipient → Amount → Fee → Review → Confirm → Broadcast → Result
 *
 * The flow is a genuine sequence, so the step markers encode something true
 * rather than decorating: each stage is a decision that constrains the next,
 * and the user can go back until the moment of confirmation but not after.
 *
 * ─── Why review is a separate, server-authored step ────────────────────────
 * "Never immediately broadcast from the first input screen." The review is not
 * a summary the UI composes from what was typed — it is the *server's* account
 * of the transaction it has already built and signed, including the fee it
 * actually computed and the change it actually created.
 *
 * That distinction matters. A UI-composed summary shows what the user asked
 * for; a server-authored one shows what will happen. Where they differ, the
 * second is the truth, and the difference is exactly where a bug or an attack
 * would hide.
 *
 * Confirming sends only the prepared transaction's id. There is no field
 * through which the broadcast could differ from what was displayed.
 */
import { useState } from "react";
import {
  VeyraApi, ApiClientError, formatBtc, formatSats, parseBtc,
  type TransactionReview, type FeeEstimates,
} from "../api/client.js";
import { Card, Button, Field, Notice, Row } from "../components/Primitives.js";
import { AddressDisplay } from "../components/AddressDisplay.js";

type Stage = "compose" | "review" | "sending" | "result" | "failed";

/** Fallback presets, used only when the API has no live estimates. */
const STATIC_PRESETS = [
  { key: "low" as const, label: "Economy", rate: 2, note: "hours to a day" },
  { key: "medium" as const, label: "Standard", rate: 8, note: "within a few blocks" },
  { key: "high" as const, label: "Priority", rate: 20, note: "next block or two" },
];

/**
 * Build the fee options from live estimates when available.
 *
 * When they are not, the static rates are still shown — a user must always be
 * able to send — but the interface says plainly that they are not live. A
 * static guess presented as a network rate leads someone to set a fee
 * believing it was informed.
 */
function feeOptions(fees: FeeEstimates | null) {
  if (!fees) return STATIC_PRESETS;
  return STATIC_PRESETS.map((preset) => ({ ...preset, rate: fees[preset.key] ?? preset.rate }));
}

export function Send({
  api, isMainnet, spendable, fees, onDone, onBack,
}: {
  api: VeyraApi;
  isMainnet: boolean;
  spendable: bigint;
  fees: FeeEstimates | null;
  onDone: () => void;
  onBack: () => void;
}) {
  const presets = feeOptions(fees);
  const [stage, setStage] = useState<Stage>("compose");
  const [recipient, setRecipient] = useState("");
  const [amountText, setAmountText] = useState("");
  const [feeRate, setFeeRate] = useState(presets[1]!.rate);
  const [review, setReview] = useState<TransactionReview | null>(null);
  const [txid, setTxid] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | null>(null);

  async function prepare() {
    setError(null);
    setFieldError(null);

    let amount: bigint;
    try {
      amount = parseBtc(amountText);
    } catch (parseError) {
      setFieldError((parseError as Error).message);
      return;
    }
    if (amount <= 0n) {
      setFieldError("Enter an amount greater than zero");
      return;
    }

    try {
      const prepared = await api.prepare({ to: recipient.trim(), amount, feeRate });
      setReview(prepared);
      setStage("review");
    } catch (prepareError) {
      // The server's message is written for a person and is safe to show —
      // "insufficient funds", "below the dust threshold", "invalid testnet
      // address". Restating it in our own words would only lose detail.
      setError(
        prepareError instanceof ApiClientError
          ? prepareError.message
          : "Could not prepare this transaction.",
      );
    }
  }

  async function confirm() {
    if (!review) return;
    setStage("sending");
    setError(null);
    try {
      const result = await api.send(review.id);
      setTxid(result.txid);
      setStage("result");
    } catch (sendError) {
      setError(
        sendError instanceof ApiClientError
          ? sendError.message
          : "The broadcast failed.",
      );
      setStage("failed");
    }
  }

  async function cancel() {
    if (review) {
      // Release the held coins rather than leaving them locked until expiry.
      try { await api.cancel(review.id); } catch { /* expiry will clear it */ }
    }
    setReview(null);
    setStage("compose");
  }

  return (
    <>
      <Steps stage={stage} />

      {isMainnet && stage !== "result" ? (
        <Notice tone="danger">
          <strong>Mainnet.</strong> This spends real bitcoin. A confirmed
          transaction cannot be reversed, recalled, or refunded by anyone.
        </Notice>
      ) : null}

      {stage === "compose" ? (
        <Card label="Send bitcoin">
          <Field
            label="Recipient address"
            value={recipient}
            onChange={(event) => setRecipient(event.target.value)}
            placeholder="bc1q…"
            spellCheck={false}
            autoComplete="off"
            hint="Paste the address. Typing it by hand risks an error the checksum may not catch."
          />

          <Field
            label="Amount in BTC"
            value={amountText}
            onChange={(event) => setAmountText(event.target.value)}
            placeholder="0.00000000"
            inputMode="decimal"
            spellCheck={false}
            autoComplete="off"
            error={fieldError}
            hint={`Spendable: ${formatBtc(spendable)} BTC`}
          />

          <span className="field-label">Network fee</span>
          <div className="btn-row" style={{ marginBottom: "var(--s2)" }}>
            {presets.map((preset) => (
              <Button
                key={preset.key}
                variant={feeRate === preset.rate ? "primary" : "default"}
                onClick={() => setFeeRate(preset.rate)}
                aria-pressed={feeRate === preset.rate}
              >
                {preset.label}
              </Button>
            ))}
          </div>
          <p className="field-hint">
            {presets.find((preset) => preset.rate === feeRate)?.note} · {feeRate} sat/vB
            {fees?.isLive ? (
              <> · live rates from {fees.source}</>
            ) : (
              <>
                {" "}· <strong>not live network rates.</strong> These are fixed
                defaults; during congestion they may be too low.
              </>
            )}
          </p>

          {error ? <><div className="spacer" /><Notice tone="danger">{error}</Notice></> : null}

          <div className="spacer" />
          <div className="btn-row">
            <Button variant="ghost" onClick={onBack}>Cancel</Button>
            <Button
              variant="primary"
              onClick={prepare}
              disabled={recipient.trim().length === 0 || amountText.trim().length === 0}
            >
              Review
            </Button>
          </div>
        </Card>
      ) : null}

      {stage === "review" && review ? (
        <>
          <Card label="Review before sending">
            <span className="card-label">To</span>
            <AddressDisplay address={review.recipient} />

            <div className="spacer" />
            <Row label="Amount" value={`${formatBtc(review.amount)} BTC`} />
            <Row label="Network fee" value={`${formatBtc(review.fee)} BTC`} />
            <Row label="Total" value={`${formatBtc(review.total)} BTC`} emphasis="total" />
            <Row label="Remaining balance" value={`${formatBtc(review.remainingBalance)} BTC`} tone="muted" />
          </Card>

          <Card label="What will be broadcast">
            <Row label="Transaction id" value={review.txid} />
            <Row label="Inputs" value={`${review.inputCount} coin${review.inputCount === 1 ? "" : "s"}`} />
            <Row
              label="Change"
              value={review.change === 0n ? "None — this spends the inputs exactly" : `${formatBtc(review.change)} BTC`}
              tone="muted"
            />
            <Row label="Size" value={`${review.vsize} vbytes at ${review.feeRate} sat/vB`} tone="muted" />
            <Row label="Fee in satoshis" value={formatSats(review.fee)} tone="muted" />
          </Card>

          <Notice tone="info">
            This transaction is already built and signed. Confirming broadcasts
            exactly these bytes — nothing above can change between now and then.
          </Notice>

          {error ? <Notice tone="danger">{error}</Notice> : null}

          <Button variant="commit" onClick={confirm}>
            Confirm and broadcast
          </Button>
          <div className="spacer" />
          <Button variant="ghost" onClick={cancel}>← Change something</Button>
        </>
      ) : null}

      {stage === "sending" ? (
        <Card label="Broadcasting">
          <p className="empty">Publishing the transaction to the network…</p>
        </Card>
      ) : null}

      {stage === "result" && txid ? (
        <>
          <Card label="Sent">
            <Notice tone="info">
              Broadcast accepted. It is not confirmed yet — that happens when a
              miner includes it in a block.
            </Notice>
            <Row label="Transaction id" value={txid} />
            {review ? (
              <>
                <Row label="Amount" value={`${formatBtc(review.amount)} BTC`} />
                <Row label="Fee" value={`${formatBtc(review.fee)} BTC`} />
              </>
            ) : null}
          </Card>
          <Button variant="primary" onClick={onDone}>Back to wallet</Button>
        </>
      ) : null}

      {stage === "failed" ? (
        <>
          <Card label="Not sent">
            <Notice tone="danger">{error}</Notice>
            <p className="field-hint">
              Nothing was spent. Your coins are untouched and you can try again.
            </p>
          </Card>
          <div className="btn-row">
            <Button variant="ghost" onClick={onBack}>Back to wallet</Button>
            <Button variant="primary" onClick={() => { setStage("compose"); setError(null); }}>
              Try again
            </Button>
          </div>
        </>
      ) : null}
    </>
  );
}

/**
 * The step indicator.
 *
 * Ordered markers are justified here because the send flow genuinely is a
 * sequence — each stage constrains the next, and the position tells the user
 * how far from the irreversible step they are.
 */
function Steps({ stage }: { stage: Stage }) {
  const order: Array<{ key: string; label: string; stages: Stage[] }> = [
    { key: "compose", label: "Compose", stages: ["compose"] },
    { key: "review", label: "Review", stages: ["review"] },
    { key: "broadcast", label: "Broadcast", stages: ["sending"] },
    { key: "result", label: "Result", stages: ["result", "failed"] },
  ];
  const currentIndex = order.findIndex((step) => step.stages.includes(stage));

  return (
    <nav className="steps" aria-label="Send progress">
      {order.map((step, index) => (
        <span key={step.key}>
          {index > 0 ? <span className="step-sep"> / </span> : null}
          <span
            className="step"
            data-state={index === currentIndex ? "current" : index < currentIndex ? "done" : "todo"}
            aria-current={index === currentIndex ? "step" : undefined}
          >
            {step.label}
          </span>
        </span>
      ))}
    </nav>
  );
}
