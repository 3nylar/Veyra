/**
 * FIAT CONVERSION — the number must never say something untrue
 *
 * Two properties are worth testing here and one is worth testing hard.
 *
 * The easy one: a price server is untrusted, so a malformed or implausible
 * response must be rejected rather than rendered. A server answering `0` would
 * make every balance read "$0.00".
 *
 * The hard one: the arithmetic. VEY-011 was a doubled fee caused by
 * `parseFloat("4.35") * 1e8` evaluating to 434999999.99999994. `satsToUsdCents`
 * is the only place in the wallet where a float touches an amount, so it gets
 * exactly one float operation and the rest is BigInt. These tests pin that.
 */
import { describe, it, expect } from "vitest";
import {
  parseRate,
  satsToUsdCents,
  fmtCents,
  fmtUsd,
  isStale,
  isExpired,
  STALE_AFTER_MS,
  DISCARD_AFTER_MS,
  type FiatRate,
} from "../../app/src/price.js";

const NOW = 1_800_000_000_000;
const rate = (usdPerBtc: number, fetchedAt = NOW): FiatRate => ({
  usdPerBtc,
  source: "test",
  fetchedAt,
});

describe("parseRate: the price server is not trusted", () => {
  it("accepts a well-formed response", () => {
    const parsed = parseRate(JSON.stringify({ time: 1, USD: 106_000, EUR: 98_000 }), NOW);
    expect(parsed.usdPerBtc).toBe(106_000);
    expect(parsed.source).toBe("mempool.space");
    expect(parsed.fetchedAt).toBe(NOW);
  });

  it("REJECTS a zero rate rather than making every balance read $0.00", () => {
    expect(() => parseRate(JSON.stringify({ USD: 0 }), NOW)).toThrow(/plausible/);
  });

  it("REJECTS a negative rate", () => {
    expect(() => parseRate(JSON.stringify({ USD: -106_000 }), NOW)).toThrow(/plausible/);
  });

  it("REJECTS an absurd rate that would make dust look like a fortune", () => {
    expect(() => parseRate(JSON.stringify({ USD: 4e21 }), NOW)).toThrow(/plausible/);
  });

  it("REJECTS NaN and Infinity", () => {
    // JSON cannot carry these literally, but a server can send a string that
    // coerces, and `typeof NaN === "number"` is exactly the trap.
    expect(() => parseRate('{"USD": null}', NOW)).toThrow(/plausible/);
    expect(() => parseRate('{"USD": "106000"}', NOW)).toThrow(/plausible/);
  });

  it("REJECTS a response with no USD field at all", () => {
    expect(() => parseRate(JSON.stringify({ EUR: 98_000 }), NOW)).toThrow(/plausible/);
  });

  it("REJECTS malformed JSON and non-objects", () => {
    expect(() => parseRate("not json", NOW)).toThrow(/valid JSON/);
    expect(() => parseRate("[1,2,3]", NOW)).toThrow(/plausible/);
    expect(() => parseRate("null", NOW)).toThrow(/not an object/);
  });
});

describe("satsToUsdCents: exact, with one rounding step", () => {
  it("converts a whole bitcoin", () => {
    expect(satsToUsdCents(100_000_000n, rate(106_000))).toBe(10_600_000n);
  });

  it("converts the challenge-sized amount", () => {
    // ~$10 at $106,000/BTC is 9,434 sats.
    expect(satsToUsdCents(9_434n, rate(106_000))).toBe(1_000n);
  });

  it("does not accumulate float error across large amounts", () => {
    // The VEY-011 shape: a rate with cents that a float cannot hold exactly.
    // 21,000,000 BTC at $4.35 is exactly $91,350,000.00 and not a cent less.
    expect(satsToUsdCents(2_100_000_000_000_000n, rate(4.35))).toBe(9_135_000_000n);
  });

  it("rounds half up, deterministically", () => {
    // 1 sat at $1,000,000/BTC = exactly 1 cent.
    expect(satsToUsdCents(1n, rate(1_000_000))).toBe(1n);
    // 1 sat at $500,000/BTC = 0.5 cents → 1 cent (half up).
    expect(satsToUsdCents(1n, rate(500_000))).toBe(1n);
    // 1 sat at $499,000/BTC = 0.499 cents → 0 cents.
    expect(satsToUsdCents(1n, rate(499_000))).toBe(0n);
  });

  it("preserves sign for a spend", () => {
    expect(satsToUsdCents(-100_000_000n, rate(106_000))).toBe(-10_600_000n);
  });

  it("maps zero to zero", () => {
    expect(satsToUsdCents(0n, rate(106_000))).toBe(0n);
  });
});

describe("fmtCents", () => {
  it("groups thousands and always shows two decimals", () => {
    expect(fmtCents(10_600_000n)).toBe("$106,000.00");
    expect(fmtCents(1_000n)).toBe("$10.00");
    expect(fmtCents(5n)).toBe("$0.05");
    expect(fmtCents(0n)).toBe("$0.00");
    expect(fmtCents(-1_000n)).toBe("-$10.00");
  });
});

describe("fmtUsd: never fabricates, never misleads", () => {
  it("shows an em dash with no rate at all", () => {
    // The whole point: no cached value, no guess, no zero.
    expect(fmtUsd(9_434n, null, NOW)).toBe("—");
  });

  it("shows an em dash rather than an hour-old figure", () => {
    const old = rate(106_000, NOW - DISCARD_AFTER_MS);
    expect(fmtUsd(9_434n, old, NOW)).toBe("—");
  });

  it("marks a real amount worth under a cent, rather than showing $0.00", () => {
    // "$0.00" reads as "worthless". "< $0.01" reads as "very small".
    expect(fmtUsd(1n, rate(1_000), NOW)).toBe("< $0.01");
  });

  it("shows $0.00 only for a genuinely zero balance", () => {
    expect(fmtUsd(0n, rate(106_000), NOW)).toBe("≈ $0.00");
  });

  it("always carries the approximation mark", () => {
    // A price is a snapshot of a moving auction; it was stale on arrival.
    expect(fmtUsd(9_434n, rate(106_000), NOW)).toBe("≈ $10.00");
  });
});

describe("staleness", () => {
  it("is fresh when just fetched", () => {
    expect(isStale(rate(106_000), NOW)).toBe(false);
    expect(isExpired(rate(106_000), NOW)).toBe(false);
  });

  it("becomes stale but still usable after ten minutes", () => {
    const r = rate(106_000, NOW - STALE_AFTER_MS);
    expect(isStale(r, NOW)).toBe(true);
    expect(isExpired(r, NOW)).toBe(false);
    expect(fmtUsd(9_434n, r, NOW)).toBe("≈ $10.00");
  });

  it("is discarded entirely after an hour", () => {
    const r = rate(106_000, NOW - DISCARD_AFTER_MS);
    expect(isExpired(r, NOW)).toBe(true);
  });
});
