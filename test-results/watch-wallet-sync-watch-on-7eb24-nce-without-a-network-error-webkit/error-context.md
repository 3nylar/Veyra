# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: watch-wallet-sync.spec.ts >> watch-only wallet — sync (browser) >> loading a wallet renders a balance without a network error
- Location: tests\e2e\watch-wallet-sync.spec.ts:34:3

# Error details

```
Error: expect(locator).toContainText(expected) failed

Locator: locator('#connectStatus')
Expected pattern: /Scanned \d+ addresses/
Received string:  "Base58: checksum mismatch — the string is mistyped or corrupted"
Timeout: 15000ms

Call log:
  - Expect "toContainText" with timeout 15000ms
  - waiting for locator('#connectStatus')
    32 × locator resolved to <p class="status" id="connectStatus">Base58: checksum mismatch — the string is mistype…</p>
       - unexpected value "Base58: checksum mismatch — the string is mistyped or corrupted"

```

```yaml
- paragraph: "Base58: checksum mismatch — the string is mistyped or corrupted"
```

# Test source

```ts
  1   | /**
  2   |  * REAL-BROWSER SYNC SMOKE TEST
  3   |  *
  4   |  * Reproduces the exact user flow that broke in VEY-020: open watch.html,
  5   |  * paste an xpub, click "Load wallet" (which fires an immediate sync), and
  6   |  * confirm a balance actually renders.
  7   |  *
  8   |  * ─── Why route interception instead of a live Esplora server ───────────────
  9   |  * The point is testing OUR code's use of the browser's `fetch`, not
  10  |  * blockstream.info's uptime. `page.route()` intercepts requests at the
  11  |  * browser network layer — after the real browser `fetch` has already been
  12  |  * invoked with whatever receiver our code supplied. If core/chain/esplora.ts
  13  |  * ever regresses to `this.fetchImpl(...)` (a bare method call instead of the
  14  |  * unbound local it currently uses), Chromium and WebKit's WebIDL brand check
  15  |  * throws `Illegal invocation` before the mock ever sees the request — the
  16  |  * test fails for the same reason production did. Firefox's fetch does not
  17  |  * enforce a receiver check the same way, which is itself useful information:
  18  |  * a pass on Firefox alongside a failure on Chromium/WebKit means the fix has
  19  |  * regressed, not that all engines agree.
  20  |  *
  21  |  * This is deliberately NOT a duplicate of tests/unit/fetch-binding.test.ts,
  22  |  * which fakes the browser's brand check by hand inside Node. This test asks
  23  |  * a real browser instead of a simulation of one — see VEY-020's lesson: "a
  24  |  * suite that runs in one runtime cannot verify behaviour in another."
  25  |  */
  26  | import { test, expect } from "@playwright/test";
  27  | 
  28  | // A well-formed testnet account xpub (BIP-84, depth 3). Not a secret — xpubs
  29  | // derive addresses only, never spending keys.
  30  | const TEST_XPUB =
  31  |   "vpub5Y6cjg78GGuNM7uCryFHXW4H2eEZfPzXeCFcdmftMUqmwjgvsdTFqCbGqL5EihJDDdmpJZ8vHy2WgVMhFy7mnFjnwd97wnr9NTFriMSY7iw";
  32  | 
  33  | test.describe("watch-only wallet — sync (browser)", () => {
  34  |   test("loading a wallet renders a balance without a network error", async ({ page }) => {
  35  |     // Intercept the exact Esplora endpoints core/chain/esplora.ts calls.
  36  |     // A route that never fires would mean the request never left the page —
  37  |     // that failure mode is asserted for separately below.
  38  |     let sawUtxoRequest = false;
  39  | 
  40  |     await page.route("**/address/*/utxo", async (route) => {
  41  |       sawUtxoRequest = true;
  42  |       await route.fulfill({
  43  |         status: 200,
  44  |         contentType: "application/json",
  45  |         body: JSON.stringify([
  46  |           { txid: "a".repeat(64), vout: 0, status: { confirmed: true, block_height: 800_000 }, value: 150_000 },
  47  |         ]),
  48  |       });
  49  |     });
  50  | 
  51  |     await page.route("**/address/*", async (route) => {
  52  |       if (route.request().url().includes("/utxo")) return route.fallback();
  53  |       await route.fulfill({
  54  |         status: 200,
  55  |         contentType: "application/json",
  56  |         body: JSON.stringify({
  57  |           chain_stats: { funded_txo_sum: 150_000, spent_txo_sum: 0, tx_count: 1 },
  58  |           mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
  59  |         }),
  60  |       });
  61  |     });
  62  | 
  63  |     await page.route("**/address/*/txs", async (route) => {
  64  |       await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
  65  |     });
  66  | 
  67  |     await page.route("**/blocks/tip/height", async (route) => {
  68  |       await route.fulfill({ status: 200, contentType: "text/plain", body: "800100" });
  69  |     });
  70  | 
  71  |     await page.goto("/watch.html");
  72  | 
  73  |     // Reproduces the exact click sequence VEY-020's users performed.
  74  |     await page.getByLabel(/xpub/i).fill(TEST_XPUB);
  75  |     await page.locator("#network").selectOption("testnet");
  76  |     await page.locator("#connect").click();
  77  | 
  78  |     // The VEY-020 symptom: a status line reading exactly this string, and a
  79  |     // balance that never leaves its initial zero state. Assert the FIX's
  80  |     // outcome, not just the absence of a thrown error — a silently-empty
  81  |     // balance would also produce no thrown error.
  82  |     await expect(page.locator("#connectStatus")).not.toContainText("Illegal invocation");
  83  |     await expect(page.locator("#connectStatus")).not.toContainText("network error");
> 84  |     await expect(page.locator("#connectStatus")).toContainText(/Scanned \d+ addresses/, {
      |                                                  ^ Error: expect(locator).toContainText(expected) failed
  85  |       timeout: 15_000,
  86  |     });
  87  | 
  88  |     await expect(page.locator("#balance")).toContainText("0.00150000");
  89  |     expect(sawUtxoRequest).toBe(true);
  90  |   });
  91  | 
  92  |   test("Sync button re-fetches without a receiver error", async ({ page }) => {
  93  |     await page.route("**/address/*/utxo", (route) =>
  94  |       route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
  95  |     );
  96  |     await page.route("**/address/*", (route) => {
  97  |       if (route.request().url().includes("/utxo")) return route.fallback();
  98  |       return route.fulfill({
  99  |         status: 200,
  100 |         contentType: "application/json",
  101 |         body: JSON.stringify({
  102 |           chain_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
  103 |           mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
  104 |         }),
  105 |       });
  106 |     });
  107 |     await page.route("**/address/*/txs", (route) =>
  108 |       route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
  109 |     );
  110 |     await page.route("**/blocks/tip/height", (route) =>
  111 |       route.fulfill({ status: 200, contentType: "text/plain", body: "800100" }),
  112 |     );
  113 | 
  114 |     await page.goto("/watch.html");
  115 |     await page.getByLabel(/xpub/i).fill(TEST_XPUB);
  116 |     await page.locator("#connect").click();
  117 |     await expect(page.locator("#connectStatus")).toContainText(/Scanned/, { timeout: 15_000 });
  118 | 
  119 |     // The second sync is the one VEY-020 actually broke in the wild — users
  120 |     // landed on the page fine, then pressed Sync and got the receiver error.
  121 |     await page.locator("#sync").click();
  122 |     await expect(page.locator("#connectStatus")).not.toContainText("Illegal invocation");
  123 |     await expect(page.locator("#connectStatus")).toContainText(/Scanned/, { timeout: 15_000 });
  124 |   });
  125 | 
  126 |   test("CSP connect-src does not block the allowlisted Esplora origin", async ({ page }) => {
  127 |     const cspViolations: string[] = [];
  128 |     page.on("console", (msg) => {
  129 |       if (msg.type() === "error" && /content security policy/i.test(msg.text())) {
  130 |         cspViolations.push(msg.text());
  131 |       }
  132 |     });
  133 | 
  134 |     await page.route("**/blocks/tip/height", (route) =>
  135 |       route.fulfill({ status: 200, contentType: "text/plain", body: "800100" }),
  136 |     );
  137 |     await page.goto("/watch.html");
  138 |     await page.waitForTimeout(500);
  139 | 
  140 |     expect(cspViolations).toEqual([]);
  141 |   });
  142 | });
```