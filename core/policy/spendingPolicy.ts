/**
 * SPENDING POLICY
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  WHAT THIS DEFENDS AGAINST — AND WHAT IT DOES NOT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A policy engine sits above the cryptography and refuses transactions that
 * are individually valid but collectively suspicious. The premise is that the
 * crypto layer might have an undiscovered bug, and a second, simpler layer
 * limits the blast radius.
 *
 * That premise holds for exactly one class of attacker, and it is important to
 * be precise about which:
 *
 *   ✅ DEFENDS AGAINST
 *      · A bug in Veyra's own transaction-building or coin-selection logic
 *      · A compromised or confused API client with a valid token
 *      · An operator mistake — a fat-fingered amount, a script in a loop
 *      · An attacker who obtained the API token but not the host
 *
 *   ❌ DOES NOT DEFEND AGAINST
 *      · A local attacker who can read process memory. They have the seed;
 *        they will sign outside Veyra entirely and this code never runs.
 *      · Anyone who can modify the running process.
 *      · A compromised dependency in the signing path.
 *
 * So this is a meaningful control against *remote* and *accidental* misuse,
 * and no control at all against *host* compromise. A policy engine described
 * as protecting your funds generally would be security theatre — it protects
 * against a specific and narrower thing, which is still worth having because
 * a stolen API token is a far more likely event than a compromised host.
 *
 * ─── Time is a parameter, never read from the clock ────────────────────────
 * Every decision takes `now` explicitly. This is not stylistic:
 *
 *   · Tests become deterministic. No sleeps, no wall-clock flakiness, no
 *     "works except at midnight UTC" bugs.
 *   · A velocity window can be tested at its exact boundary rather than
 *     approximately.
 *   · The caller controls the clock, so a policy can be evaluated against a
 *     hypothetical future time — "what would this cost me tomorrow?"
 *
 * VEY-009 in docs/ATTACKS.md is the cautionary case: a test that read the
 * clock measured the machine rather than the code.
 *
 * ─── Scope decision: Veyra DECIDES, it does not HOLD ───────────────────────
 * When a transaction is delayed, this engine returns `delay` with a release
 * time. It does **not** queue the transaction, schedule it, or broadcast it
 * later.
 *
 * That is a deliberate boundary. Holding a signed transaction until a future
 * moment requires durable storage, a scheduler that survives restarts, and an
 * answer to "what happens if the inputs are spent while we wait" — all of
 * which are application concerns, not wallet-core concerns. A core that
 * silently acquired a background scheduler would be much harder to reason
 * about and much easier to get wrong.
 *
 * The calling application decides whether to hold, prompt, or abandon.
 */

import { VeyraError } from "../errors/index.js";

export class PolicyError extends VeyraError {
  constructor(reason: string) {
    super("INVALID_ENCODING", `Policy: ${reason}`);
    this.name = "PolicyError";
  }
}

/** A spend the policy is being asked about. */
export interface SpendRequest {
  /** Amount to the recipient, in satoshis. Excludes fee. */
  readonly amount: bigint;
  /** Fee, in satoshis. Counted toward limits — it leaves the wallet too. */
  readonly fee: bigint;
  /** Destination address. */
  readonly recipient: string;
}

/** A spend that already happened, for velocity accounting. */
export interface SpendRecord {
  readonly amount: bigint;
  readonly fee: bigint;
  readonly recipient: string;
  /** Unix milliseconds. */
  readonly at: number;
}

export interface PolicyLimits {
  /** Largest single spend, amount + fee. Omit for no cap. */
  readonly maxPerTransaction?: bigint;
  /** Largest total across a rolling window. Omit for no cap. */
  readonly maxPerWindow?: bigint;
  /** Rolling window length in milliseconds. Required if maxPerWindow is set. */
  readonly windowMs?: number;
  /**
   * Delay applied to a first-time destination, in milliseconds.
   *
   * The most valuable rule in practice: an attacker with a stolen token wants
   * to send somewhere new, and a delay turns an instant theft into one the
   * owner has a window to notice.
   */
  readonly newRecipientDelayMs?: number;
  /** Spends at or above this amount are delayed even to a known destination. */
  readonly largeAmountThreshold?: bigint;
  /** Delay applied to a large spend, in milliseconds. */
  readonly largeAmountDelayMs?: number;
  /**
   * Destinations exempt from the new-recipient delay.
   *
   * An allowlist the owner set deliberately, in advance — which is precisely
   * what an attacker with only a token cannot do.
   */
  readonly trustedRecipients?: readonly string[];
}

export type PolicyOutcome = "allow" | "deny" | "delay";

export interface PolicyDecision {
  readonly outcome: PolicyOutcome;
  /** Which rule decided. Stable identifier — branch on this, not the reason text. */
  readonly rule: string;
  /** Human-readable explanation, safe to show a user. */
  readonly reason: string;
  /** For `delay`: the earliest time this may proceed, in Unix milliseconds. */
  readonly releaseAt?: number;
  /** For velocity rules: how much of the window allowance remains. */
  readonly windowRemaining?: bigint;
}

/**
 * No limits at all.
 *
 * The default, and deliberately so: a wallet that silently imposed spending
 * caps nobody configured would be surprising in the worst way — a user
 * discovering it mid-payment. Policy is opt-in.
 */
export const NO_LIMITS: PolicyLimits = Object.freeze({});

/** A conservative starting point for someone who wants limits but not to design them. */
export const CAUTIOUS_LIMITS: PolicyLimits = Object.freeze({
  maxPerTransaction: 10_000_000n, // 0.1 BTC
  maxPerWindow: 50_000_000n, // 0.5 BTC
  windowMs: 24 * 60 * 60 * 1000,
  newRecipientDelayMs: 60 * 60 * 1000, // one hour to notice
  largeAmountThreshold: 5_000_000n, // 0.05 BTC
  largeAmountDelayMs: 30 * 60 * 1000,
});

export class SpendingPolicy {
  private readonly limits: PolicyLimits;
  private readonly trusted: ReadonlySet<string>;

  constructor(limits: PolicyLimits = NO_LIMITS) {
    // A window cap without a window is ambiguous, and guessing a default
    // would produce a limit the operator did not choose.
    if (limits.maxPerWindow !== undefined && limits.windowMs === undefined) {
      throw new PolicyError("maxPerWindow requires windowMs");
    }
    if (limits.windowMs !== undefined && (!Number.isFinite(limits.windowMs) || limits.windowMs <= 0)) {
      throw new PolicyError("windowMs must be a positive number of milliseconds");
    }
    if (limits.largeAmountThreshold !== undefined && limits.largeAmountDelayMs === undefined) {
      throw new PolicyError("largeAmountThreshold requires largeAmountDelayMs");
    }
    for (const [name, value] of [
      ["maxPerTransaction", limits.maxPerTransaction],
      ["maxPerWindow", limits.maxPerWindow],
      ["largeAmountThreshold", limits.largeAmountThreshold],
    ] as const) {
      if (value !== undefined && value < 0n) {
        throw new PolicyError(`${name} cannot be negative`);
      }
    }

    this.limits = limits;
    this.trusted = new Set(limits.trustedRecipients ?? []);
  }

  /**
   * Evaluate a spend.
   *
   * Rules are checked in order of severity, and the FIRST match decides. A
   * transaction that both exceeds the per-transaction cap and goes to a new
   * recipient is denied, not delayed — the more restrictive answer wins, and
   * ordering it explicitly means the outcome never depends on evaluation
   * accident.
   *
   * @param now Unix milliseconds. Always supplied by the caller.
   * @param history Prior spends, for velocity accounting.
   */
  evaluate(
    request: SpendRequest,
    now: number,
    history: readonly SpendRecord[] = [],
  ): PolicyDecision {
    if (!Number.isFinite(now)) throw new PolicyError("`now` must be a finite timestamp");
    if (request.amount < 0n || request.fee < 0n) {
      throw new PolicyError("amount and fee cannot be negative");
    }

    // Fee is included throughout. It leaves the wallet exactly as the payment
    // does, and a cap that ignored it could be evaded with an enormous fee.
    const total = request.amount + request.fee;

    // ── 1. Per-transaction cap. A hard denial. ─────────────────────────────
    if (this.limits.maxPerTransaction !== undefined && total > this.limits.maxPerTransaction) {
      return {
        outcome: "deny",
        rule: "max-per-transaction",
        reason:
          `This spend of ${total} sat exceeds the per-transaction limit of ` +
          `${this.limits.maxPerTransaction} sat.`,
      };
    }

    // ── 2. Rolling velocity cap. Also a denial. ────────────────────────────
    if (this.limits.maxPerWindow !== undefined && this.limits.windowMs !== undefined) {
      const windowStart = now - this.limits.windowMs;
      const spentInWindow = history
        .filter((record) => record.at > windowStart && record.at <= now)
        .reduce((sum, record) => sum + record.amount + record.fee, 0n);

      const remaining =
        this.limits.maxPerWindow > spentInWindow ? this.limits.maxPerWindow - spentInWindow : 0n;

      if (spentInWindow + total > this.limits.maxPerWindow) {
        return {
          outcome: "deny",
          rule: "max-per-window",
          reason:
            `This would bring spending to ${spentInWindow + total} sat within the ` +
            `last ${Math.round(this.limits.windowMs / 60000)} minutes, over the ` +
            `${this.limits.maxPerWindow} sat limit. ${remaining} sat remain.`,
          windowRemaining: remaining,
        };
      }
    }

    // ── 3. New destination. A delay, not a denial. ─────────────────────────
    // The highest-value rule against a stolen token: an attacker wants to
    // send somewhere new, and a delay converts instant theft into something
    // the owner has a window to notice and stop.
    if (this.limits.newRecipientDelayMs !== undefined && !this.isKnownRecipient(request.recipient, history)) {
      return {
        outcome: "delay",
        rule: "new-recipient",
        reason:
          `${request.recipient} has not been paid before. This spend is held for ` +
          `${Math.round(this.limits.newRecipientDelayMs / 60000)} minutes so it can be reviewed.`,
        releaseAt: now + this.limits.newRecipientDelayMs,
      };
    }

    // ── 4. Large amount, even to a known destination. ──────────────────────
    if (
      this.limits.largeAmountThreshold !== undefined &&
      this.limits.largeAmountDelayMs !== undefined &&
      total >= this.limits.largeAmountThreshold
    ) {
      return {
        outcome: "delay",
        rule: "large-amount",
        reason:
          `${total} sat is at or above the ${this.limits.largeAmountThreshold} sat ` +
          `review threshold. Held for ${Math.round(this.limits.largeAmountDelayMs / 60000)} minutes.`,
        releaseAt: now + this.limits.largeAmountDelayMs,
      };
    }

    return {
      outcome: "allow",
      rule: "no-limit-applies",
      reason: "Within all configured limits.",
      ...(this.limits.maxPerWindow !== undefined && this.limits.windowMs !== undefined
        ? { windowRemaining: this.remainingInWindow(now, history) }
        : {}),
    };
  }

  /**
   * Has this destination been paid before, or explicitly trusted?
   *
   * History is the wallet's own record of completed spends. Note the
   * consequence, which is intentional: an attacker cannot make a destination
   * "known" except by successfully paying it once — and that first payment is
   * exactly the one the delay catches.
   */
  private isKnownRecipient(recipient: string, history: readonly SpendRecord[]): boolean {
    if (this.trusted.has(recipient)) return true;
    return history.some((record) => record.recipient === recipient);
  }

  /** Remaining allowance in the current window. */
  remainingInWindow(now: number, history: readonly SpendRecord[]): bigint {
    if (this.limits.maxPerWindow === undefined || this.limits.windowMs === undefined) {
      throw new PolicyError("no window limit is configured");
    }
    const windowStart = now - this.limits.windowMs;
    const spent = history
      .filter((record) => record.at > windowStart && record.at <= now)
      .reduce((sum, record) => sum + record.amount + record.fee, 0n);
    return this.limits.maxPerWindow > spent ? this.limits.maxPerWindow - spent : 0n;
  }

  /** True when no rule could ever fire. */
  get isUnrestricted(): boolean {
    return (
      this.limits.maxPerTransaction === undefined &&
      this.limits.maxPerWindow === undefined &&
      this.limits.newRecipientDelayMs === undefined &&
      this.limits.largeAmountThreshold === undefined
    );
  }

  /** The configured limits, for display. Contains no secrets. */
  describe(): Record<string, unknown> {
    return {
      maxPerTransaction: this.limits.maxPerTransaction?.toString() ?? null,
      maxPerWindow: this.limits.maxPerWindow?.toString() ?? null,
      windowMs: this.limits.windowMs ?? null,
      newRecipientDelayMs: this.limits.newRecipientDelayMs ?? null,
      largeAmountThreshold: this.limits.largeAmountThreshold?.toString() ?? null,
      largeAmountDelayMs: this.limits.largeAmountDelayMs ?? null,
      trustedRecipientCount: this.trusted.size,
      unrestricted: this.isUnrestricted,
    };
  }
}
