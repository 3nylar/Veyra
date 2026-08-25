/**
 * PRE-PUBLISH SAFETY CHECK
 *
 * Run before making the repository public. Publishing a secret is not
 * reversible: GitHub retains forks and caches, and scrapers watch new public
 * repos for exactly this. Deleting a commit afterwards does not help.
 */
import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const failures: string[] = [];
const warnings: string[] = [];

function tracked(): string[] {
  try {
    return execSync("git ls-files", { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);
  } catch {
    console.log("Not a git repository yet — run `git init` first.\n");
    process.exit(1);
  }
}

const files = tracked();
console.log(`Checking ${files.length} tracked files…\n`);

// 1. Secret-bearing files must not be tracked at all.
for (const file of files) {
  if (/^\.env$|^\.env\.(?!example)/.test(file)) failures.push(`.env file is tracked: ${file}`);
  if (/\.(seed|mnemonic)$|wallet-backup/i.test(file)) failures.push(`secret file is tracked: ${file}`);
  if (/^app\/dist\//.test(file)) warnings.push(`build output is tracked: ${file}`);
  if (/node_modules/.test(file)) failures.push(`node_modules is tracked: ${file}`);
}

// 2. A real mnemonic in source.
//
// Validated against the actual BIP-39 wordlist, not a loose word-shape regex.
// The first version of this check matched any run of short lowercase words and
// flagged six passages of ordinary English prose. A checker that cries wolf
// gets ignored, which is worse than not having one.
//
// A phrase only counts if EVERY word is in the wordlist AND the checksum
// verifies — which is precisely what makes it a usable wallet rather than a
// sentence.
const { ENGLISH_WORDLIST } = await import("../core/mnemonic/wordlist.js");
const { validateMnemonic } = await import("../core/mnemonic/index.js");
const WORDSET = new Set(ENGLISH_WORDLIST);

/** Published test vectors. Their presence in a test file is correct. */
const KNOWN_TEST_PHRASES = new Set(
  [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
  ].map((phrase) => phrase.trim()),
);

const WORDS = /\b([a-z]{3,8}[ \t]+){11,23}[a-z]{3,8}\b/g;

for (const file of files) {
  if (!/\.(ts|tsx|js|json|md|html)$/.test(file)) continue;
  const full = join(root, file);
  if (!existsSync(full)) continue;
  const content = readFileSync(full, "utf8");

  for (const match of content.match(WORDS) ?? []) {
    const phrase = match.trim().replace(/[ \t]+/g, " ");
    const words = phrase.split(" ");
    if (![12, 15, 18, 21, 24].includes(words.length)) continue;

    // Every word must be in the wordlist. Prose fails here immediately.
    if (!words.every((word) => WORDSET.has(word))) continue;

    // And the checksum must verify — otherwise it is not a usable wallet.
    if (!validateMnemonic(phrase)) continue;

    if (KNOWN_TEST_PHRASES.has(phrase)) continue;

    // Reaching here means a VALID, unpublished mnemonic is in a tracked file.
    // That is a failure, not a warning.
    failures.push(`VALID MNEMONIC in ${file}: "${words.slice(0, 3).join(" ")} …"`);
  }

  // 64-hex assigned to something key-shaped, outside test fixtures.
  if (!/^(tests|api\/tests)\//.test(file)) {
    const keyish = /(private_?key|secret|seed|xprv)\s*[:=]\s*["'][0-9a-f]{64}["']/i;
    if (keyish.test(content)) failures.push(`hard-coded key material in ${file}`);
  }

  // API tokens that look real.
  if (/VEYRA_API_TOKEN\s*=\s*["'][0-9a-f]{32,}["']/.test(content)) {
    failures.push(`hard-coded API token in ${file}`);
  }
}

// 3. .gitignore must cover the obvious.
const ignore = existsSync(join(root, ".gitignore"))
  ? readFileSync(join(root, ".gitignore"), "utf8")
  : "";
for (const required of [".env", "node_modules"]) {
  if (!ignore.includes(required)) failures.push(`.gitignore is missing "${required}"`);
}

// ── Report ────────────────────────────────────────────────────────────────
if (warnings.length > 0) {
  console.log("WARNINGS — review each one by hand:");
  for (const w of warnings) console.log(`  ⚠  ${w}`);
  console.log();
}

if (failures.length > 0) {
  console.log("FAILURES — do NOT publish until these are fixed:");
  for (const f of failures) console.log(`  ✗  ${f}`);
  console.log();
  process.exit(1);
}

// Deployment config: Vercel fails the BUILD on an unknown key, which costs a
// full deploy cycle to discover. Cheap to catch here.
if (existsSync(join(root, "vercel.json"))) {
  const ALLOWED_VERCEL_KEYS = new Set([
    "$schema", "buildCommand", "outputDirectory", "installCommand",
    "devCommand", "framework", "cleanUrls", "trailingSlash",
    "headers", "redirects", "rewrites", "regions", "public", "git",
  ]);
  try {
    const config = JSON.parse(readFileSync(join(root, "vercel.json"), "utf8")) as Record<string, unknown>;
    const unknown = Object.keys(config).filter((key) => !ALLOWED_VERCEL_KEYS.has(key));
    if (unknown.length > 0) {
      failures.push(`vercel.json has keys Vercel will reject: ${unknown.join(", ")}`);
    }
  } catch (error) {
    failures.push(`vercel.json is not valid JSON: ${(error as Error).message}`);
  }
}

console.log("✓ No secrets found in tracked files.");
console.log("✓ .gitignore covers .env and node_modules.\n");
console.log("Reminders that this script cannot check:");
console.log("  · Any mnemonic printed to your terminal is in scrollback, not in git.");
console.log("  · Check `git log -p` if you have committed before — history is published too.");
console.log("  · Never put a real mnemonic in a shell command; history persists.\n");
