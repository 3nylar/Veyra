import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts", "api/tests/**/*.test.ts"],
    environment: "node",

    /**
     * Test timeout: 30 seconds.
     *
     * Vitest's 5-second default is an **implicit wall-clock assertion on every
     * test**, and it fails for the same reason VEY-009 did: it measures the
     * machine rather than the code. A property test doing 200 signing rounds
     * takes ~2 s here and over 5 s on a modest laptop — the property held
     * perfectly in both cases.
     *
     * 30 s is deliberately generous. These are correctness tests, not
     * benchmarks, and there is no number here that means "fast enough" —
     * only one that means "did not hang". A genuine hang still fails, just
     * later.
     *
     * If a test needs more than 30 s, that is a signal to look at the code
     * rather than to raise this further. The regtest suite sets its own
     * per-test timeouts because it mines real blocks.
     */
    testTimeout: 30_000,

    /**
     * Hooks get longer: the regtest `beforeAll` mines 101 blocks to mature a
     * coinbase output, which is genuinely slow the first time.
     */
    hookTimeout: 120_000,
  },
});
