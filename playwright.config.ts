import { defineConfig, devices } from "@playwright/test";

/**
 * REAL-BROWSER E2E TESTS
 *
 * ─── Why this exists ────────────────────────────────────────────────────────
 * VEY-020: every browser sync failed in production while 919 vitest tests
 * stayed green. The defect was a `fetch` receiver-binding rule that Node's
 * undici never enforces and jsdom cannot even test (it ships no `fetch` at
 * all). No amount of Node-side testing was ever going to catch it — only a
 * real browser evaluating real browser semantics can.
 *
 * That fix was retrofitted as a hand-written brand-checking fake
 * (tests/unit/fetch-binding.test.ts). This suite is the general answer the
 * specific one that gap: it runs the actual shipped pages inside actual
 * browser engines, so the NEXT browser-only behavioural difference — a
 * WebCrypto quirk, a CSP violation, a DOM API gap — has somewhere to surface
 * rather than passing silently in Node like VEY-020 did for 21 increments.
 *
 * ─── Why three engines, not three OSes ──────────────────────────────────────
 * The CI matrix in ci.yml varies OS to catch filesystem/path bugs (VEY-001).
 * This suite varies BROWSER ENGINE instead, because the bug class it targets
 * — `fetch` receiver checks, WebCrypto subtle-crypto behavior, CSP
 * enforcement — is a property of the engine (Chromium/Firefox/WebKit), not
 * the host OS. Running the same engine on three OSes would not have caught
 * VEY-020; running three engines on one OS would.
 */
export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",

  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },

  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],

  // Boots the real dev server the app is served from (app/vite.config.ts),
  // not a mock server — the point is testing what actually ships.
  webServer: {
    command: "npm run app",
    url: "http://127.0.0.1:5173/watch.html",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    // Visible by default: a silent timeout here gives no signal about
    // whether the server ever started, crashed, or is just slow. Piping
    // stdout/stderr means the real Vite output (ready message, errors)
    // shows up in the same terminal instead of vanishing.
    stdout: "pipe",
    stderr: "pipe",
  },
});
