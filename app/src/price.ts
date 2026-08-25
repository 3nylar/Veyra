/**
 * USD VALUE — a number that is either LIVE or ABSENT
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  THE RULE THIS FILE EXISTS TO OBEY
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The same one `FeeEstimates` already follows: a figure that is not live is
 * never fabricated. There is no cached rate, no last-known value in
 * localStorage, no "roughly what it was this morning". If the fetch failed, the
 * interface shows an em dash and says the price is unavailable.
 *
 * That is a deliberate trade against a nicer-looking card. A wallet showing a
 * stale dollar figure is telling the user something false about how much money
 * they have, and the moment it matters is exactly the moment the network was
 * down.
 *
 * ─── Why mempool.space, and why this needs no CSP change ───────────────────
 * `https://mempool.space` is ALREADY in this page's pinned `connect-src` — it
 * serves the signet Esplora. So a price costs no new origin.
 *
 * That matters more than it sounds. The pinned allowlist is the single control
 * that makes a page holding keys AND reaching the network defensible: injected
 * script cannot POST a seed anywhere, because the browser refuses the request.
 * Widening it to `https:` for a dollar sign would trade the whole threat model
 * for a convenience, and `scripts/build-standalone.ts` would refuse the build.
 *
 * ─── Why this is not in core/ ──────────────────────────────────────────────
 * `core/` is guarded for runtime portability and is BigInt-only by discipline.
 * A fiat oracle is neither Bitcoin nor portable-relevant, `ChainSource` is
 * deliberately four methods wide, and an IEEE double exchange rate has no
 * business in the module that computes fees — someone would eventually use it
 * in arithmetic that matters.
 */

/** Prices, as served by mempool.space. Already in the page's connect-src. */
const PRICE_URL = "https://mempool.space/api/v1/prices";

/** A price server can hang. Six seconds is well past a healthy response. */
const TIMEOUT_MS = 6_000;

/**
 * A price response is a few dozen bytes. Anything larger is a broken or
 * hostile server, and reading it unbounded is a denial of service that needs
 * no exploit — the same reasoning as MAX_RESPONSE_BYTES in the Esplora client.
 */
const MAX_BYTES = 8 * 1024;

/**
 * Sanity bounds on the rate itself.
 *
 * A server that answers `0` would make every balance read `$0.00`, and one that
 * answers `4e21` would make a dust output look like a fortune. Neither should
 * reach the interface. The ceiling is absurdly high on purpose: it is a guard
 * against a broken response, not a prediction about the price of bitcoin.
 */
const MIN_USD_PER_BTC = 0.01;
const MAX_USD_PER_BTC = 10_000_000;

/** Older than this and the age is shown alongside the figure. */
export const STALE_AFTER_MS = 10 * 60 * 1000;

/** Older than this and the figure is not shown at all. */
export const DISCARD_AFTER_MS = 60 * 60 * 1000;

export interface FiatRate {
  /** USD per whole BTC. A float — for display only, never wallet arithmetic. */
  readonly usdPerBtc: number;
  /** Where it came from. Shown to the user, as FeeEstimates does. */
  readonly source: string;
  /** Epoch milliseconds. Rates go stale in minutes. */
  readonly fetchedAt: number;
}

/**
 * Fetch the current USD price of one bitcoin.
 *
 * Throws on any failure — a bad status, a slow server, a malformed body, an
 * implausible number. The caller stores `null` and the interface shows an em
 * dash. There is deliberately no fallback value to return.
 */
export async function fetchUsdRate(): Promise<FiatRate> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    // A bare `fetch(...)` call has no receiver, so it cannot reproduce VEY-020
    // — the bug where a stored `globalThis.fetch` was invoked as a method and
    // every sync failed with "Illegal invocation". Do not hoist this onto an
    // object and call it as a property.
    const response = await fetch(PRICE_URL, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      throw new Error(`price server returned ${response.status}`);
    }

    const text = await response.text();
    if (text.length > MAX_BYTES) {
      throw new Error("price response exceeded the maximum permitted size");
    }

    return parseRate(text, Date.now());
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Parse and validate a price response.
 *
 * Separated from the request so it can be tested without a network, and
 * written defensively because the price server is no more trusted than the
 * chain server — `core/chain/types.ts` validates every field it is handed for
 * exactly this reason.
 */
export function parseRate(body: string, now: number): FiatRate {
  let data: unknown;
  try {
    data = JSON.parse(body);
  } catch {
    throw new Error("price response was not valid JSON");
  }

  if (typeof data !== "object" || data === null) {
    throw new Error("price response was not an object");
  }

  const usd = (data as Record<string, unknown>).USD;

  if (
    typeof usd !== "number" ||
    !Number.isFinite(usd) ||
    usd < MIN_USD_PER_BTC ||
    usd > MAX_USD_PER_BTC
  ) {
    throw new Error("price response did not contain a plausible USD rate");
  }

  return { usdPerBtc: usd, source: "mempool.space", fetchedAt: now };
}

export const rateAge = (rate: FiatRate, now = Date.now()): number => now - rate.fetchedAt;

export const isStale = (rate: FiatRate, now = Date.now()): boolean =>
  rateAge(rate, now) >= STALE_AFTER_MS;

export const isExpired = (rate: FiatRate, now = Date.now()): boolean =>
  rateAge(rate, now) >= DISCARD_AFTER_MS;

/**
 * Satoshis → whole US cents, with exactly one rounding step.
 *
 * ─── Why the arithmetic looks like this ────────────────────────────────────
 * VEY-011 was a doubled fee caused by `parseFloat("4.35") * 1e8` evaluating to
 * 434999999.99999994. Money arithmetic in this codebase is BigInt-only for that
 * reason, and `fmtBtc`/`parseBtc` in the wallet remain untouched.
 *
 * A fiat rate is inherently a float, so exactly one float operation is
 * permitted: converting the rate to integer cents-per-BTC. It is bounded and
 * safe — a rate below 10,000,000 gives at most 1e9 cents, far inside a double's
 * exact integer range. Every subsequent step is BigInt, so no rounding error
 * can accumulate across the multiplication by a satoshi amount.
 */
export function satsToUsdCents(sats: bigint, rate: FiatRate): bigint {
  const centsPerBtc = BigInt(Math.round(rate.usdPerBtc * 100));

  const negative = sats < 0n;
  const abs = negative ? -sats : sats;

  // Round half up to the nearest whole cent, in exact integer arithmetic.
  // The +50_000_000n is half of 100_000_000n (satoshis per BTC).
  const cents = (abs * centsPerBtc + 50_000_000n) / 100_000_000n;

  return negative ? -cents : cents;
}

/** "$1,234.56", from whole cents. Mirrors fmtBtc's string surgery. */
export function fmtCents(cents: bigint): string {
  const negative = cents < 0n;
  const abs = negative ? -cents : cents;
  const whole = abs / 100n;
  const frac = (abs % 100n).toString().padStart(2, "0");
  return `${negative ? "-" : ""}$${whole.toLocaleString("en-US")}.${frac}`;
}

/**
 * The fiat figure for an amount, or an em dash when there is no live rate.
 *
 * Every branch here exists to stop the number saying something untrue:
 *
 *   - no rate, or one too old to trust  → "—", not a remembered figure
 *   - a real amount worth under a cent  → "< $0.01", not "$0.00", which reads
 *                                          as "this is worthless"
 *   - otherwise                          → "≈ $10.43"
 *
 * The "≈" is load-bearing. A price is a snapshot of a moving auction, and the
 * figure was already out of date when it arrived.
 */
export function fmtUsd(sats: bigint, rate: FiatRate | null, now = Date.now()): string {
  if (!rate || isExpired(rate, now)) return "—";

  const cents = satsToUsdCents(sats, rate);

  if (cents === 0n && sats !== 0n) {
    return sats > 0n ? "< $0.01" : "> -$0.01";
  }

  return `≈ ${fmtCents(cents)}`;
}

/** "just now", "4 minutes ago" — for the "where this number came from" line. */
export function fmtRateAge(rate: FiatRate, now = Date.now()): string {
  const seconds = Math.max(0, Math.floor(rateAge(rate, now) / 1000));
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  return `${hours} hour${hours === 1 ? "" : "s"} ago`;
}
