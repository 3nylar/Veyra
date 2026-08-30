# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: watch-wallet-sync.spec.ts >> watch-only wallet — sync (browser) >> CSP connect-src does not block the allowlisted Esplora origin
- Location: tests\e2e\watch-wallet-sync.spec.ts:126:3

# Error details

```
Error: expect(received).toEqual(expected) // deep equality

- Expected  - 1
+ Received  + 4

- Array []
+ Array [
+   "Refused to connect to ws://127.0.0.1:5173/?token=WwBO_yoA_UY2 because it does not appear in the connect-src directive of the Content Security Policy.",
+   "Refused to connect to ws://127.0.0.1:5173/?token=WwBO_yoA_UY2 because it does not appear in the connect-src directive of the Content Security Policy.",
+ ]
```

# Page snapshot

```yaml
- generic [ref=e2]:
  - heading "Veyra Watch" [level=1] [ref=e3]
  - paragraph [ref=e4]: Client-side. Holds no keys. Talks to a chain source you choose.
  - generic [ref=e5]:
    - strong [ref=e6]: This page can reach the network, so it holds no keys.
    - text: A page allowed to contact Esplora is also able to contact an attacker's server — those two properties cannot coexist. Signing happens in
    - code [ref=e7]: veyra-sign.html
    - text: ", which is forbidden from making any network request at all."
  - generic [ref=e8]:
    - paragraph [ref=e9]: 1 · Connect
    - generic [ref=e11]:
      - generic [ref=e12]: Account xpub / tpub
      - textbox "Account xpub / tpub" [ref=e13]:
        - /placeholder: tpub… (depth 3, m/84'/coin'/account')
    - generic [ref=e14]:
      - generic [ref=e15]:
        - generic [ref=e16]: Network
        - combobox "Network" [ref=e17]:
          - option "testnet" [selected]
          - option "signet"
          - option "mainnet"
          - option "regtest"
      - generic [ref=e18]:
        - generic [ref=e19]: Esplora URL
        - textbox "Esplora URL" [ref=e20]: https://blockstream.info/testnet/api
    - generic [ref=e21]:
      - button "Load wallet" [ref=e22] [cursor=pointer]
      - button "Sync" [ref=e23] [cursor=pointer]
    - paragraph [ref=e24]: Not connected.
```

# Test source

```ts
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
  84  |     await expect(page.locator("#connectStatus")).toContainText(/Scanned \d+ addresses/, {
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
> 140 |     expect(cspViolations).toEqual([]);
      |                           ^ Error: expect(received).toEqual(expected) // deep equality
  141 |   });
  142 | });
```