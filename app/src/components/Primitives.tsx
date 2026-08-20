/**
 * Interface primitives.
 *
 * Deliberately few. A wallet needs to display values, take three kinds of
 * input, and offer two kinds of action; anything beyond that is decoration
 * competing with the numbers for attention.
 */
import type { ReactNode, ButtonHTMLAttributes } from "react";

export function Card({ label, children }: { label?: string; children: ReactNode }) {
  return (
    <section className="card">
      {label ? <h2 className="card-label">{label}</h2> : null}
      {children}
    </section>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "commit" | "ghost";
};

export function Button({ variant = "default", children, ...rest }: ButtonProps) {
  return (
    <button className="btn" data-variant={variant} {...rest}>
      {children}
    </button>
  );
}

/**
 * A labelled value.
 *
 * `emphasis="total"` is reserved for the amount that actually leaves the
 * wallet. §16 forbids hiding fees, and the reliable way to honour that is to
 * give the total — amount plus fee — the visual weight, not the amount alone.
 */
export function Row({
  label, value, emphasis, tone,
}: {
  label: string;
  value: ReactNode;
  emphasis?: "total";
  tone?: "muted" | "danger";
}) {
  return (
    <div className="row" {...(emphasis ? { "data-emphasis": emphasis } : {})}>
      <span className="row-key">{label}</span>
      <span
        className="row-value"
        style={tone === "danger" ? { color: "var(--danger)" } : tone === "muted" ? { color: "var(--text-muted)" } : undefined}
      >
        {value}
      </span>
    </div>
  );
}

export function Field({
  label, hint, error, ...input
}: {
  label: string;
  hint?: string;
  error?: string | null;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input className="field-input" aria-invalid={error ? "true" : undefined} {...input} />
      {error ? <span className="field-error">{error}</span> : hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

export function Notice({
  tone = "info", children,
}: {
  tone?: "info" | "warning" | "danger";
  children: ReactNode;
}) {
  return (
    <div className="notice" data-tone={tone} role={tone === "danger" ? "alert" : undefined}>
      <span>{children}</span>
    </div>
  );
}

export function Status({ tone, children }: { tone: "healthy" | "warning" | "danger" | "idle"; children: ReactNode }) {
  return (
    <span className="status">
      <span className="status-dot" data-tone={tone} />
      {children}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}
