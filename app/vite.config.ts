import { readdirSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vite";

/**
 * Every generated docs page is a build entry point.
 *
 * Enumerated from the directory rather than listed by hand: a list would drift
 * the moment a page is added, and the failure is silent — the page simply
 * vanishes from a production build while still working in dev.
 */
function docsEntries(): Record<string, string> {
  const dir = resolve(__dirname, "docs");
  const entries: Record<string, string> = {};
  for (const file of readdirSync(dir)) {
    if (file.endsWith(".html")) entries[`docs-${file.replace(/\.html$/, "")}`] = resolve(dir, file);
  }
  return entries;
}

/**
 * No React plugin.
 *
 * `@vitejs/plugin-react` exists for Fast Refresh, and it pins a Vite major
 * that conflicts with the one vitest brings in. Vite compiles JSX through
 * esbuild natively, so the plugin buys a development convenience at the cost
 * of a dependency conflict and one more package in a tree that holds wallet
 * code. §46 asks for a reason for every dependency; "hot reload" did not
 * survive the question.
 */
export default defineConfig({
  root: __dirname,
  esbuild: {
    jsx: "automatic",
  },
  server: {
    port: 5173,
    // Localhost only. This UI talks to an API holding private keys; exposing
    // the dev server on a LAN should never be something you get by accident.
    host: "127.0.0.1",
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // The wallet plus every documentation page.
    rollupOptions: {
      input: {
        index: resolve(__dirname, "index.html"),
        // The offline signer. Bundled as its own entry so it can be copied to
        // an air-gapped machine as a self-contained page.
        signer: resolve(__dirname, "signer.html"),
        ...docsEntries(),
      },
    },
  },
});
