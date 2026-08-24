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
  /**
   * A standalone build targets ONE page and inlines everything into it.
   *
   * Code splitting is correct for a served site and fatal for a single file:
   * the inlined script would import a chunk that does not exist beside it.
   * `inlineDynamicImports` forces a single bundle, and is only legal with a
   * single input — hence the separate build per page.
   */
  /**
   * A standalone build targets ONE page and inlines everything into it.
   *
   * Code splitting is correct for a served site and fatal for a single file:
   * the inlined script would `import` a chunk that does not exist beside it,
   * and the page loads blank. `inlineDynamicImports` forces a single bundle,
   * and is only legal with one input — hence one build per page.
   */
  build: process.env.VEYRA_STANDALONE_ENTRY
    ? {
        emptyOutDir: true,
        rollupOptions: {
          input: resolve(__dirname, process.env.VEYRA_STANDALONE_ENTRY),
          output: { inlineDynamicImports: true },
        },
      }
    : {
        outDir: "dist",
        emptyOutDir: true,
        rollupOptions: {
          input: {
            index: resolve(__dirname, "index.html"),
            // The main product: a single-page wallet anyone can open.
            wallet: resolve(__dirname, "wallet.html"),
            signer: resolve(__dirname, "signer.html"),
            watch: resolve(__dirname, "watch.html"),
            ...docsEntries(),
          },
        },
      },
});
