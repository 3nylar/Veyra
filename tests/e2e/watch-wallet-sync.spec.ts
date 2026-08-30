/**
 * REAL-BROWSER SYNC SMOKE TEST
 *
 * Reproduces the exact user flow that broke in VEY-020: open watch.html,
 * paste an xpub, click "Load wallet" (which fires an immediate sync), and
 * confirm a balance actually renders.
 *
 * ─── Why route interception instead of a live Esplora server ───────────────
 * The point is testing OUR code's use of the browser's `fetch`, not
 * blockstream.info's uptime. `page.route()` intercepts requests at the
 * browser network layer — after the real browser `fetch` has already been
 * invoked with whatever receiver our code supplied. If core/chain/esplora.ts
 * ever regresses to `this.fetchImpl(...)` (a bare method call instead of the
 * unbound local it currently uses), Chromium and WebKit's WebIDL brand check
 * throws `Illegal invocation` before the mock ever sees the request — the
 * test fails for the same reason production did. Firefox's fetch does not
 * enforce a receiver check the same way, which is itself useful information:
 * a pass on Firefox alongside a failure on Chromium/WebKit means the fix has
 * regressed, not that all engines agree.
 *
 * This is deliberately NOT a duplicate of tests/unit/fetch-binding.test.ts,
 * which fakes the browser's brand check by hand inside Node. This test asks
 * a real browser instead of a simulation of one — see VEY-020's lesson: "a
 * suite that runs in one runtime cannot verify behaviour in another."
 */
import { test, expect } from "@playwright/test";

// A well-formed testnet account xpub (BIP-84, depth 3). Not a secret — xpubs
// derive addresses only, never spending keys.
const TEST_XPUB =
  "vpub5Y6cjg78GGuNM7uCryFHXW4H2eEZfPzXeCFcdmftMUqmwjgvsdTFqCbGqL5EihJDDdmpJZ8vHy2WgVMhFy7mnFjnwd97wnr9NTFriMSY7iw";

test.describe("watch-only wallet — sync (browser)", () => {
  test("loading a wallet renders a balance without a network error", async ({ page }) => {
    // Intercept the exact Esplora endpoints core/chain/esplora.ts calls.
    // A route that never fires would mean the request never left the page —
    // that failure mode is asserted for separately below.
    let sawUtxoRequest = false;

    await page.route("**/address/*/utxo", async (route) => {
      sawUtxoRequest = true;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { txid: "a".repeat(64), vout: 0, status: { confirmed: true, block_height: 800_000 }, value: 150_000 },
        ]),
      });
    });

    await page.route("**/address/*", async (route) => {
      if (route.request().url().includes("/utxo")) return route.fallback();
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          chain_stats: { funded_txo_sum: 150_000, spent_txo_sum: 0, tx_count: 1 },
          mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
        }),
      });
    });

    await page.route("**/address/*/txs", async (route) => {
      await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
    });

    await page.route("**/blocks/tip/height", async (route) => {
      await route.fulfill({ status: 200, contentType: "text/plain", body: "800100" });
    });

    await page.goto("/watch.html");

    // Reproduces the exact click sequence VEY-020's users performed.
    await page.getByLabel(/xpub/i).fill(TEST_XPUB);
    await page.locator("#network").selectOption("testnet");
    await page.locator("#connect").click();

    // The VEY-020 symptom: a status line reading exactly this string, and a
    // balance that never leaves its initial zero state. Assert the FIX's
    // outcome, not just the absence of a thrown error — a silently-empty
    // balance would also produce no thrown error.
    await expect(page.locator("#connectStatus")).not.toContainText("Illegal invocation");
    await expect(page.locator("#connectStatus")).not.toContainText("network error");
    await expect(page.locator("#connectStatus")).toContainText(/Scanned \d+ addresses/, {
      timeout: 15_000,
    });

    await expect(page.locator("#balance")).toContainText("0.00150000");
    expect(sawUtxoRequest).toBe(true);
  });

  test("Sync button re-fetches without a receiver error", async ({ page }) => {
    await page.route("**/address/*/utxo", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
    );
    await page.route("**/address/*", (route) => {
      if (route.request().url().includes("/utxo")) return route.fallback();
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          chain_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
          mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
        }),
      });
    });
    await page.route("**/address/*/txs", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
    );
    await page.route("**/blocks/tip/height", (route) =>
      route.fulfill({ status: 200, contentType: "text/plain", body: "800100" }),
    );

    await page.goto("/watch.html");
    await page.getByLabel(/xpub/i).fill(TEST_XPUB);
    await page.locator("#connect").click();
    await expect(page.locator("#connectStatus")).toContainText(/Scanned/, { timeout: 15_000 });

    // The second sync is the one VEY-020 actually broke in the wild — users
    // landed on the page fine, then pressed Sync and got the receiver error.
    await page.locator("#sync").click();
    await expect(page.locator("#connectStatus")).not.toContainText("Illegal invocation");
    await expect(page.locator("#connectStatus")).toContainText(/Scanned/, { timeout: 15_000 });
  });

  test("CSP connect-src does not block the allowlisted Esplora origin", async ({ page }) => {
    const cspViolations: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error" && /content security policy/i.test(msg.text())) {
        cspViolations.push(msg.text());
      }
    });

    await page.route("**/blocks/tip/height", (route) =>
      route.fulfill({ status: 200, contentType: "text/plain", body: "800100" }),
    );
    await page.goto("/watch.html");
    await page.waitForTimeout(500);

    expect(cspViolations).toEqual([]);
  });
});