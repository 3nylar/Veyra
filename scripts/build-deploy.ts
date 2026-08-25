/**
 * BUILD THE COMPLETE PUBLIC SITE
 *
 * ─── Why one deployment and not two ────────────────────────────────────────
 * `vercel.json` always overrides dashboard settings, and a repository can only
 * have one. Two Vercel projects reading the same repository therefore read the
 * same config and build the same thing — whichever site that config describes.
 * Configuring the second project through its dashboard silently does nothing.
 *
 * We hit this in both directions: first both projects served the docs, then
 * both served the wallet. Neither was a misconfiguration to fix; it is what
 * happens when two projects share one config file.
 *
 * So: ONE project, one config, both sites.
 *
 *     /                    the wallet
 *     /veyra-sign.html     the offline signer
 *     /veyra-watch.html    the watch-only page
 *     /SHA256SUMS          hashes for verification
 *     /docs/               the documentation site
 *
 * This is better than the split anyway. The docs can link to the wallet and
 * the wallet to the docs without crossing domains, and there is one thing to
 * deploy rather than two that must agree.
 */

import { cpSync, mkdirSync, rmSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "public");

const run = (command: string) => execSync(command, { cwd: root, stdio: "inherit" });

console.log("\n=== 1/3  standalone wallet pages ===\n");
run("npx tsx scripts/build-standalone.ts");

console.log("\n=== 2/3  documentation ===\n");
run("npx tsx scripts/build-docs.ts");
run("npx tsx scripts/build-site.ts");

console.log("\n=== 3/3  assembling public/ ===\n");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// The wallet is the root of the site.
cpSync(join(root, "standalone", "veyra.html"), join(out, "index.html"));

for (const file of ["veyra-sign.html", "veyra-watch.html", "SHA256SUMS", "VERIFY.md"]) {
  cpSync(join(root, "standalone", file), join(out, file));
}

// Docs under /docs. build-site.ts already emits its own index.html there, so
// /docs and /docs/introduction.html both resolve.
cpSync(join(root, "app", "dist-site", "docs"), join(out, "docs"), { recursive: true });
cpSync(join(root, "app", "dist-site", "index.html"), join(out, "docs", "index.html"));
cpSync(join(root, "app", "dist-site", "404.html"), join(out, "404.html"));

/**
 * Verify the assembled site before it is deployed.
 *
 * Both previous deployment failures — the docs 404, and each project serving
 * the other's content — would have been caught by checking the OUTPUT rather
 * than trusting the configuration that produced it.
 */
const required = [
  "index.html",
  "veyra-sign.html",
  "veyra-watch.html",
  "SHA256SUMS",
  "404.html",
  "docs/index.html",
  "docs/introduction.html",
  "docs/api-reference.html",
  "docs/assets/docs.css",
];

const missing = required.filter((file) => !existsSync(join(out, file)));
if (missing.length > 0) {
  throw new Error(`public/ is incomplete — missing:\n  ${missing.join("\n  ")}`);
}

// The root must be the WALLET, not a docs redirect. Getting this wrong is
// exactly the failure that shipped twice, and it is one string comparison.
const index = readFileSync(join(out, "index.html"), "utf8");
if (!/Veyra — Bitcoin Wallet/.test(index)) {
  throw new Error("public/index.html is not the wallet — check the copy order above");
}
if (/http-equiv="refresh"/i.test(index)) {
  throw new Error("public/index.html is a redirect page, not the wallet");
}
if (!/sha256-/.test(index)) {
  throw new Error(
    "public/index.html has no script hash in its CSP — the browser would refuse " +
      "to run it and the page would load blank (see ATTACKS.md VEY-017)",
  );
}

const count = (dir: string): number =>
  readdirSync(dir, { withFileTypes: true }).reduce(
    (total, entry) =>
      total + (entry.isDirectory() ? count(join(dir, entry.name)) : 1),
    0,
  );

console.log(`public/ assembled — ${count(out)} files\n`);
console.log("  /                   the wallet");
console.log("  /veyra-sign.html    offline signer");
console.log("  /veyra-watch.html   watch-only page");
console.log("  /SHA256SUMS         verification hashes");
console.log("  /docs/              documentation\n");
