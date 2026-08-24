/**
 * STANDALONE BUILD — single self-contained HTML files
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  WHY A SINGLE FILE IS THE TAMPER-RESISTANT SHAPE
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The realistic attack on a browser wallet is not the cryptography. It is the
 * **delivery**: whoever serves the page can serve a different page. A hosting
 * account compromise, a hijacked domain, a malicious CDN, or a coerced
 * operator all produce the same result — you load a page that looks identical
 * and sends your seed somewhere.
 *
 * Nothing inside the page can defend against that, because the attacker
 * controls the page.
 *
 * The only real defence is to stop fetching it. A single file with no external
 * references can be:
 *
 *   1. downloaded once,
 *   2. **verified against a published hash**,
 *   3. stored locally, and
 *   4. opened from `file://` forever after, on a machine with no network.
 *
 * At that point the delivery attack requires modifying a file already on your
 * disk — a far higher bar than swapping a server response, and one you can
 * detect by re-checking the hash.
 *
 * ─── What "self-contained" has to mean ─────────────────────────────────────
 * Every byte inlined. No `<script src>`, no `<link href>`, no fonts, no CDN,
 * no analytics, no source maps fetched on open. One `<script>` failing to load
 * from a CDN turns a wallet into a blank page; one CDN compromised turns it
 * into a thief.
 *
 * This script asserts that afterwards rather than assuming it — see
 * `assertSelfContained`.
 */

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const distDirFor = (output: string) => join(root, "app", `dist-${output.replace(/\.html$/, "")}`);
const outDir = join(root, "standalone");

/** Pages that become self-contained files, and what each is for. */
const PAGES = [
  {
    source: "signer.html",
    output: "veyra-sign.html",
    role: "OFFLINE SIGNER — holds your seed, cannot reach the network",
  },
  {
    source: "watch.html",
    output: "veyra-watch.html",
    role: "ONLINE WATCH — holds no keys, talks to the chain",
  },
];

/**
 * Each page is built SEPARATELY.
 *
 * A multi-entry build code-splits shared code — secp256k1, hashing — into a
 * chunk the entries `import` from. That is correct for a served site and fatal
 * for a single file: the inlined script would contain
 * `import … from "./ecdsa-abc.js"`, a file that does not exist beside it, and
 * the page loads blank.
 *
 * `inlineDynamicImports` forces one bundle per entry, which is only legal with
 * a single input. Hence one build per page, and the duplicated crypto in each
 * file is the cost of both files standing alone.
 */
console.log("Building each page as a single bundle…\n");
for (const page of PAGES) {
  execSync(
    `npx vite build --config app/vite.config.ts --outDir dist-${page.output.replace(/\.html$/, "")}`,
    {
      cwd: root,
      stdio: "inherit",
      env: { ...process.env, VEYRA_STANDALONE_ENTRY: page.source },
    },
  );
}

if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

/** Inline every local asset a page references. */
function inline(html: string, distDir: string): string {
  let out = html;

  // <script type="module" crossorigin src="/assets/x.js"></script>
  out = out.replace(
    /<script[^>]*\ssrc="\/?(assets\/[^"]+)"[^>]*><\/script>/g,
    (_full, path: string) => {
      const code = readFileSync(join(distDir, path), "utf8");
      // `</script>` inside a string literal would terminate the tag early.
      // Escaping it is not optional; the file silently breaks otherwise.
      return `<script type="module">\n${code.replace(/<\/script>/gi, "<\\/script>")}\n</script>`;
    },
  );

  // <link rel="stylesheet" href="/assets/x.css">
  out = out.replace(
    /<link[^>]*rel="stylesheet"[^>]*href="\/?(assets\/[^"]+)"[^>]*>/g,
    (_full, path: string) => `<style>\n${readFileSync(join(distDir, path), "utf8")}\n</style>`,
  );

  // Preload hints point at files that will not exist beside a single file.
  out = out.replace(/<link[^>]*rel="modulepreload"[^>]*>/g, "");

  return out;
}

/**
 * Fail the build if anything still reaches outside the file.
 *
 * Asserted rather than trusted: a future dependency that pulls in a font or a
 * source map would otherwise silently reintroduce the delivery attack this
 * whole exercise exists to remove.
 */
function assertSelfContained(html: string, name: string): void {
  const violations: string[] = [];

  const srcRefs = [...html.matchAll(/<(script|link|img|iframe)[^>]*\s(?:src|href)="([^"]+)"/gi)];
  for (const [, tag, url] of srcRefs) {
    if (url!.startsWith("data:") || url!.startsWith("#")) continue;
    violations.push(`<${tag}> references ${url}`);
  }
  if (/@import\s+url\(/i.test(html)) violations.push("CSS @import present");
  if (/sourceMappingURL/.test(html)) violations.push("source map reference present");

  // The one the first version of this script missed. A code-split bundle
  // leaves `import … from "./chunk.js"` INSIDE the inlined JavaScript, where
  // no HTML-tag scan will find it — and the page loads blank. Caught here
  // because a silent blank wallet is worse than a failed build.
  const bareImports = [...html.matchAll(/\bimport\s*(?:\{[^}]*\}|[\w$]+|\*\s+as\s+[\w$]+)?\s*from\s*["'](\.[^"']+)["']/g)];
  for (const [, path] of bareImports) violations.push(`unresolved module import: ${path}`);

  const dynamicImports = [...html.matchAll(/\bimport\s*\(\s*["'](\.[^"']+)["']\s*\)/g)];
  for (const [, path] of dynamicImports) violations.push(`unresolved dynamic import: ${path}`);

  if (violations.length > 0) {
    throw new Error(`${name} is not self-contained:\n  ${violations.join("\n  ")}`);
  }
}

/** Confirm the signer's exfiltration guarantee survived bundling. */
function assertSignerIsOffline(html: string): void {
  if (!/connect-src\s+'none'/.test(html)) {
    throw new Error(
      "veyra-sign.html has lost `connect-src 'none'` — the guarantee that it " +
        "cannot exfiltrate a key is gone. Refusing to emit it.",
    );
  }
}

const results: Array<{ name: string; role: string; bytes: number; sha256: string }> = [];

for (const page of PAGES) {
  const distDir = distDirFor(page.output);
  const sourcePath = join(distDir, page.source);
  if (!existsSync(sourcePath)) throw new Error(`missing build output: ${page.source}`);

  const html = inline(readFileSync(sourcePath, "utf8"), distDir);
  assertSelfContained(html, page.output);
  if (page.output === "veyra-sign.html") assertSignerIsOffline(html);

  const target = join(outDir, page.output);
  writeFileSync(target, html, "utf8");

  results.push({
    name: page.output,
    role: page.role,
    bytes: Buffer.byteLength(html),
    sha256: createHash("sha256").update(html).digest("hex"),
  });
}

// A checksum file in the standard format, so `sha256sum -c` works directly.
const checksums = results.map((r) => `${r.sha256}  ${r.name}`).join("\n") + "\n";
writeFileSync(join(outDir, "SHA256SUMS"), checksums, "utf8");

writeFileSync(
  join(outDir, "VERIFY.md"),
  `# Verify before you open these

The realistic attack on a browser wallet is the **delivery** — whoever serves
the page can serve a different page. Checking the hash is what closes that.

## Hashes

\`\`\`
${checksums.trim()}
\`\`\`

## Check them

**Windows (PowerShell)**

\`\`\`powershell
Get-FileHash veyra-sign.html -Algorithm SHA256 | Format-List
Get-FileHash veyra-watch.html -Algorithm SHA256 | Format-List
\`\`\`

**macOS / Linux**

\`\`\`bash
sha256sum -c SHA256SUMS
\`\`\`

If a hash does not match, **do not open the file**. Re-download it, and if it
still differs, assume the copy is hostile.

## What each file is

| File | Holds keys | Network access |
| --- | --- | --- |
| \`veyra-sign.html\` | **Yes** — your seed | **None.** \`connect-src 'none'\` |
| \`veyra-watch.html\` | No | Yes — the Esplora you name |

Those two properties cannot coexist in one page. A page allowed to reach a
chain source is also able to reach an attacker's server, so splitting them is
the only arrangement in which either guarantee is real.

## Use them offline

Both files work from \`file://\`. Copy \`veyra-sign.html\` to a machine with no
network — an old laptop with the Wi-Fi card disabled is enough — and it is
never exposed to a delivery attack again.
`,
  "utf8",
);

console.log("\nStandalone files written to standalone/\n");
for (const result of results) {
  console.log(`  ${result.name}  ${(result.bytes / 1024).toFixed(0)} KB`);
  console.log(`    ${result.role}`);
  console.log(`    sha256 ${result.sha256}\n`);
}
console.log("Verify with SHA256SUMS before opening. See standalone/VERIFY.md.\n");

// The dist directories are intermediates. Leaving them invites someone to
// open the multi-file version, which carries none of these guarantees.
for (const page of PAGES) rmSync(distDirFor(page.output), { recursive: true, force: true });
void readdirSync;
