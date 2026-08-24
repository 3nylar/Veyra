/**
 * SPENDING POLICY
 *
 * Every test supplies `now` explicitly. No sleeps, no wall-clock reads, no
 * "passes except at midnight" flakiness — and window boundaries can be tested
 * at the exact millisecond rather than approximately. See docs/ATTACKS.md
 * VEY-009 for why that matters.
 */
import { describe, it, expect } from "vitest";
import {
  SpendingPolicy, PolicyError, NO_LIMITS, CAUTIOUS_LIMITS,
  type SpendRecord,
} from "../../core/policy/spendingPolicy.js";

const T0 = 1_700_000_000_000; // a fixed instant
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const spend = (amount: bigint, recipient = "bc1qalice", fee = 500n) => ({ amount, fee, recipient });
const record = (amount: bigint, at: number, recipient = "bc1qalice", fee = 500n): SpendRecord =>
  ({ amount, fee, recipient, at });

describe("no limits by default", () => {
  it("allows anything when unconfigured", () => {
    // A wallet that silently imposed caps nobody configured would be
    // surprising in the worst way — a user discovering it mid-payment.
    const policy = new SpendingPolicy();
    expect(policy.evaluate(spend(21_000_000_00000000n), T0).outcome).toBe("allow");
    expect(policy.isUnrestricted).toBe(true);
  });

  it("NO_LIMITS is explicit and equivalent", () => {
    expect(new SpendingPolicy(NO_LIMITS).isUnrestricted).toBe(true);
  });
});

describe("per-transaction cap", () => {
  const policy = new SpendingPolicy({ maxPerTransaction: 100_000n });

  it("allows a spend under the cap", () => {
    expect(policy.evaluate(spend(50_000n), T0).outcome).toBe("allow");
  });

  it("allows a spend exactly at the cap", () => {
    // amount + fee = 100_000 exactly.
    expect(policy.evaluate({ amount: 99_500n, fee: 500n, recipient: "bc1qalice" }, T0).outcome)
      .toBe("allow");
  });

  it("DENIES one satoshi over", () => {
    const decision = policy.evaluate({ amount: 99_501n, fee: 500n, recipient: "bc1qalice" }, T0);
    expect(decision.outcome).toBe("deny");
    expect(decision.rule).toBe("max-per-transaction");
  });

  it("COUNTS THE FEE toward the cap", () => {
    // A cap ignoring the fee could be evaded with an enormous one.
    const decision = policy.evaluate({ amount: 99_999n, fee: 50_000n, recipient: "bc1qalice" }, T0);
    expect(decision.outcome).toBe("deny");
  });
});

describe("rolling velocity window", () => {
  const policy = new SpendingPolicy({
    maxPerWindow: 100_000n,
    windowMs: DAY,
    trustedRecipients: ["bc1qalice"],
  });

  it("allows a first spend within the allowance", () => {
    expect(policy.evaluate(spend(40_000n), T0).outcome).toBe("allow");
  });

  it("accumulates across spends", () => {
    const history = [record(40_000n, T0 - HOUR), record(40_000n, T0 - 2 * HOUR)];
    // 81_000 spent (with fees), plus 20_500 = 101_500 > 100_000.
    const decision = policy.evaluate(spend(20_000n), T0, history);
    expect(decision.outcome).toBe("deny");
    expect(decision.rule).toBe("max-per-window");
  });

  it("reports how much allowance remains", () => {
    const history = [record(40_000n, T0 - HOUR)];
    const decision = policy.evaluate(spend(10_000n), T0, history);
    expect(decision.outcome).toBe("allow");
    expect(decision.windowRemaining).toBe(100_000n - 40_500n);
  });

  it("EXPIRES spends that fall outside the window", () => {
    // Exactly at the boundary: a spend DAY ago is no longer counted.
    const justOutside = [record(90_000n, T0 - DAY)];
    expect(policy.evaluate(spend(50_000n), T0, justOutside).outcome).toBe("allow");

    const justInside = [record(90_000n, T0 - DAY + 1)];
    expect(policy.evaluate(spend(50_000n), T0, justInside).outcome).toBe("deny");
  });

  it("ignores records dated in the future", () => {
    // A clock-skewed or forged record must not inflate the window.
    const history = [record(90_000n, T0 + HOUR)];
    expect(policy.evaluate(spend(50_000n), T0, history).outcome).toBe("allow");
  });

  it("remainingInWindow never goes negative", () => {
    const history = [record(500_000n, T0 - HOUR)];
    expect(policy.remainingInWindow(T0, history)).toBe(0n);
  });

  it("requires windowMs alongside maxPerWindow", () => {
    // Guessing a default would impose a limit the operator did not choose.
    expect(() => new SpendingPolicy({ maxPerWindow: 1000n })).toThrow(/requires windowMs/);
  });
});

describe("new-recipient delay", () => {
  const policy = new SpendingPolicy({ newRecipientDelayMs: HOUR });

  it("DELAYS a first-time destination", () => {
    // The highest-value rule against a stolen token: an attacker wants to
    // send somewhere new, and this turns instant theft into something the
    // owner has a window to notice.
    const decision = policy.evaluate(spend(10_000n, "bc1qstranger"), T0);
    expect(decision.outcome).toBe("delay");
    expect(decision.rule).toBe("new-recipient");
    expect(decision.releaseAt).toBe(T0 + HOUR);
  });

  it("allows a destination that has been paid before", () => {
    const history = [record(5_000n, T0 - DAY, "bc1qbob")];
    expect(policy.evaluate(spend(10_000n, "bc1qbob"), T0, history).outcome).toBe("allow");
  });

  it("allows an explicitly trusted destination with no history", () => {
    // An allowlist the owner set in advance — precisely what an attacker with
    // only a token cannot do.
    const trusting = new SpendingPolicy({
      newRecipientDelayMs: HOUR,
      trustedRecipients: ["bc1qexchange"],
    });
    expect(trusting.evaluate(spend(10_000n, "bc1qexchange"), T0).outcome).toBe("allow");
  });

  it("history for a DIFFERENT recipient does not make this one known", () => {
    const history = [record(5_000n, T0 - DAY, "bc1qbob")];
    expect(policy.evaluate(spend(10_000n, "bc1qmallory"), T0, history).outcome).toBe("delay");
  });

  it("an attacker cannot make a destination known without first being delayed", () => {
    // The only route to "known" is a completed payment — which is the exact
    // payment this rule catches.
    const first = policy.evaluate(spend(10_000n, "bc1qattacker"), T0);
    expect(first.outcome).toBe("delay");

    // Only after it actually completes does the destination become known.
    const after = policy.evaluate(
      spend(10_000n, "bc1qattacker"),
      T0 + 2 * HOUR,
      [record(10_000n, T0 + HOUR, "bc1qattacker")],
    );
    expect(after.outcome).toBe("allow");
  });
});

describe("large-amount delay", () => {
  const policy = new SpendingPolicy({
    largeAmountThreshold: 1_000_000n,
    largeAmountDelayMs: 30 * MINUTE,
    trustedRecipients: ["bc1qalice"],
  });

  it("allows a small spend to a known destination", () => {
    expect(policy.evaluate(spend(10_000n), T0).outcome).toBe("allow");
  });

  it("DELAYS at the threshold, even to a known destination", () => {
    const decision = policy.evaluate({ amount: 999_500n, fee: 500n, recipient: "bc1qalice" }, T0);
    expect(decision.outcome).toBe("delay");
    expect(decision.rule).toBe("large-amount");
    expect(decision.releaseAt).toBe(T0 + 30 * MINUTE);
  });

  it("requires a delay alongside a threshold", () => {
    expect(() => new SpendingPolicy({ largeAmountThreshold: 1000n })).toThrow(/requires largeAmountDelayMs/);
  });
});

describe("rule precedence: the most restrictive answer wins", () => {
  const policy = new SpendingPolicy({
    maxPerTransaction: 100_000n,
    maxPerWindow: 500_000n,
    windowMs: DAY,
    newRecipientDelayMs: HOUR,
    largeAmountThreshold: 50_000n,
    largeAmountDelayMs: 30 * MINUTE,
  });

  it("a spend that both exceeds the cap AND is new is DENIED, not delayed", () => {
    // Ordering the rules explicitly means the outcome never depends on
    // evaluation accident.
    const decision = policy.evaluate(spend(200_000n, "bc1qstranger"), T0);
    expect(decision.outcome).toBe("deny");
    expect(decision.rule).toBe("max-per-transaction");
  });

  it("a window breach outranks a new-recipient delay", () => {
    const history = [record(490_000n, T0 - HOUR, "bc1qbob")];
    const decision = policy.evaluate(spend(50_000n, "bc1qstranger"), T0, history);
    expect(decision.outcome).toBe("deny");
    expect(decision.rule).toBe("max-per-window");
  });

  it("a new recipient outranks a large amount", () => {
    const decision = policy.evaluate(spend(60_000n, "bc1qstranger"), T0);
    expect(decision.outcome).toBe("delay");
    expect(decision.rule).toBe("new-recipient");
  });
});

describe("time is a parameter, never the clock", () => {
  const policy = new SpendingPolicy({ maxPerWindow: 100_000n, windowMs: HOUR, trustedRecipients: ["bc1qalice"] });

  it("the same inputs always give the same answer", () => {
    const history = [record(50_000n, T0 - 30 * MINUTE)];
    const first = policy.evaluate(spend(20_000n), T0, history);
    const second = policy.evaluate(spend(20_000n), T0, history);
    expect(first).toEqual(second);
  });

  it("advancing `now` expires history deterministically", () => {
    const history = [record(90_000n, T0)];
    expect(policy.evaluate(spend(50_000n), T0 + MINUTE, history).outcome).toBe("deny");
    // One millisecond past the window, the old spend no longer counts.
    expect(policy.evaluate(spend(50_000n), T0 + HOUR + 1, history).outcome).toBe("allow");
  });

  it("permits evaluating a hypothetical future", () => {
    // "What would this cost me tomorrow?" is answerable because the caller
    // owns the clock.
    const history = [record(90_000n, T0)];
    expect(policy.evaluate(spend(50_000n), T0 + DAY, history).outcome).toBe("allow");
  });

  it("rejects a non-finite timestamp", () => {
    expect(() => policy.evaluate(spend(1000n), Number.NaN)).toThrow(PolicyError);
    expect(() => policy.evaluate(spend(1000n), Number.POSITIVE_INFINITY)).toThrow(PolicyError);
  });
});

describe("validation", () => {
  it("rejects negative limits", () => {
    expect(() => new SpendingPolicy({ maxPerTransaction: -1n })).toThrow(/cannot be negative/);
    expect(() => new SpendingPolicy({ maxPerWindow: -1n, windowMs: 1000 })).toThrow(/cannot be negative/);
  });

  it("rejects a non-positive window", () => {
    expect(() => new SpendingPolicy({ maxPerWindow: 100n, windowMs: 0 })).toThrow(/positive/);
    expect(() => new SpendingPolicy({ maxPerWindow: 100n, windowMs: -5 })).toThrow(/positive/);
  });

  it("rejects negative amounts in a request", () => {
    const policy = new SpendingPolicy(CAUTIOUS_LIMITS);
    expect(() => policy.evaluate({ amount: -1n, fee: 0n, recipient: "bc1q" }, T0)).toThrow(PolicyError);
    expect(() => policy.evaluate({ amount: 1n, fee: -1n, recipient: "bc1q" }, T0)).toThrow(PolicyError);
  });
});

describe("CAUTIOUS_LIMITS preset", () => {
  const policy = new SpendingPolicy(CAUTIOUS_LIMITS);

  it("delays a first payment to anyone", () => {
    expect(policy.evaluate(spend(10_000n, "bc1qnew"), T0).outcome).toBe("delay");
  });

  it("denies a spend above 0.1 BTC", () => {
    expect(policy.evaluate(spend(20_000_000n, "bc1qnew"), T0).outcome).toBe("deny");
  });

  it("describe() exposes the configuration without secrets", () => {
    const described = policy.describe();
    expect(described.maxPerTransaction).toBe("10000000");
    expect(described.unrestricted).toBe(false);
    expect(JSON.stringify(described)).not.toMatch(/key|seed|mnemonic/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────
//  INTEGRATION: the policy actually gates the wallet
// ─────────────────────────────────────────────────────────────────────────
describe("wallet integration", () => {
  const MNEMONIC =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

  async function fundedWallet() {
    const { Wallet } = await import("../../core/wallet/wallet.js");
    const { MemoryChainSource } = await import("../../core/chain/memory.js");
    const { REGTEST } = await import("../../core/bitcoin/networks.js");

    const wallet = Wallet.restore(MNEMONIC, REGTEST);
    const chain = new MemoryChainSource("regtest", 500);
    // Several coins, not one: a broadcast consumes its inputs, and tests
    // that send twice need something left to spend the second time.
    const addresses = wallet.receiveAddresses(4);
    for (let i = 0; i < 4; i++) {
      chain.fund(addresses[i]!.address, (i + 17).toString(16).repeat(32).slice(0, 64), 0, 12_000_000n, 6);
    }
    await wallet.sync(chain);
    const recipient = Wallet.restore(MNEMONIC, REGTEST, "r").currentReceiveAddress().address;
    return { wallet, chain, recipient };
  }

  it("is unrestricted by default", async () => {
    const { wallet, recipient } = await fundedWallet();
    const prepared = wallet.send({ to: recipient, amount: 10_000_000n, feeRate: 5 });
    expect(prepared.policy?.outcome).toBe("allow");
  });

  it("DENIES a spend over the per-transaction cap", async () => {
    const { wallet, recipient } = await fundedWallet();
    wallet.setPolicy({ maxPerTransaction: 1_000_000n, trustedRecipients: [recipient] });
    expect(() => wallet.send({ to: recipient, amount: 5_000_000n, feeRate: 5 }))
      .toThrow(/Blocked by spending policy/);
  });

  it("the fee is counted, so a huge fee cannot evade the cap", async () => {
    const { wallet, recipient } = await fundedWallet();
    wallet.setPolicy({ maxPerTransaction: 100_000n, trustedRecipients: [recipient] });
    // Amount alone is under the cap; amount + fee is not.
    expect(() => wallet.send({ to: recipient, amount: 99_000n, feeRate: 500 }))
      .toThrow(/Blocked by spending policy/);
  });

  it("DELAYS a first payment but still builds the transaction", async () => {
    // Veyra decides; it does not hold. The caller gets a signed transaction
    // and a release time, and chooses what to do.
    const { wallet, recipient } = await fundedWallet();
    wallet.setPolicy({ newRecipientDelayMs: HOUR });

    const prepared = wallet.send({ to: recipient, amount: 1_000_000n, feeRate: 5, now: T0 });
    expect(prepared.policy?.outcome).toBe("delay");
    expect(prepared.policy?.releaseAt).toBe(T0 + HOUR);
    expect(prepared.hex.length).toBeGreaterThan(0); // signed and ready
  });

  it("a destination becomes known only after a SUCCESSFUL broadcast", async () => {
    const { wallet, chain, recipient } = await fundedWallet();
    wallet.setPolicy({ newRecipientDelayMs: HOUR });

    const first = wallet.send({ to: recipient, amount: 1_000_000n, feeRate: 5, now: T0 });
    expect(first.policy?.outcome).toBe("delay");

    await wallet.broadcast(chain, first);

    const second = wallet.send({ to: recipient, amount: 1_000_000n, feeRate: 5, now: T0 + DAY });
    expect(second.policy?.outcome).toBe("allow");
  });

  it("a DENIED spend never becomes history, so it cannot whitelist itself", async () => {
    const { wallet, recipient } = await fundedWallet();
    wallet.setPolicy({ maxPerTransaction: 100_000n, newRecipientDelayMs: HOUR });
    expect(() => wallet.send({ to: recipient, amount: 5_000_000n, feeRate: 5 })).toThrow();
    expect(wallet.spendHistory.length).toBe(0);
  });

  it("nothing is broadcast when the policy denies", async () => {
    const { wallet, chain, recipient } = await fundedWallet();
    wallet.setPolicy({ maxPerTransaction: 1000n });
    expect(() => wallet.send({ to: recipient, amount: 5_000_000n, feeRate: 5 })).toThrow();
    expect(chain.broadcastLog.length).toBe(0);
    // 4 coins x 12,000,000 sat. Balance is untouched by a denial.
    expect(wallet.balance().spendable).toBe(48_000_000n);
  });

  it("the velocity cap accumulates across real broadcasts", async () => {
    const { wallet, chain, recipient } = await fundedWallet();
    wallet.setPolicy({
      maxPerWindow: 3_000_000n,
      windowMs: DAY,
      trustedRecipients: [recipient],
    });

    const first = wallet.send({ to: recipient, amount: 2_000_000n, feeRate: 5 });
    await wallet.broadcast(chain, first);

    // 2_000_000 + fee already spent; another 2_000_000 breaches 3_000_000.
    expect(() => wallet.send({ to: recipient, amount: 2_000_000n, feeRate: 5 }))
      .toThrow(/Blocked by spending policy/);
  });
});
