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

  // Builds and serves the actual production bundle (app/vite.config.ts),
  // not a mock server and not the Vite dev server — the point is testing
  // what actually ships.
  //
  // This used to run `npm run app` (the dev server) directly. That server
  // injects a Vite HMR client into every page, which opens its own
  // WebSocket back to the dev server for live-reload. watch.html's CSP
  // intentionally omits `ws:` from connect-src (a page that talks to
  // Esplora should not also be trusted to open arbitrary sockets), so that
  // HMR socket tripped the same "content security policy" console-error
  // listener the CSP test uses to watch for real violations — a false
  // positive with nothing to do with the Esplora origin the test actually
  // cares about. A production preview build has no HMR client, so it
  // doesn't manufacture a violation the shipped page would never produce.
  webServer: {
    command: "npm run app:build && npm run app:preview",
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