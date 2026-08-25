/**
 * Validate vercel.json before pushing.
 *
 * Vercel validates this file against a strict schema and fails the BUILD on an
 * unknown key — including `"//"`, the usual JSON-comment convention. That
 * failure costs a full deploy cycle to discover, so it is worth catching in a
 * second locally.
 *
 * The allowlist below is not the complete Vercel schema; it is the set this
 * project uses. Adding a genuinely new key means adding it here deliberately.
 */
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Top-level keys Vercel accepts that this project uses. */
const ALLOWED = new Set([
  "$schema", "buildCommand", "outputDirectory", "installCommand",
  "devCommand", "framework", "cleanUrls", "trailingSlash",
  "headers", "redirects", "rewrites", "regions", "public", "git",
]);

const files = ["vercel.json"];
let failed = false;

for (const name of files) {
  const path = join(root, name);
  if (!existsSync(path)) continue;

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  } catch (error) {
    console.error(`✗ ${name} is not valid JSON: ${(error as Error).message}`);
    failed = true;
    continue;
  }

  const unknown = Object.keys(parsed).filter((key) => !ALLOWED.has(key));
  if (unknown.length > 0) {
    console.error(
      `✗ ${name} has keys Vercel will reject: ${unknown.join(", ")}\n` +
        `  Vercel fails the build on unknown properties — including "//".\n` +
        `  Put explanations in deploy/README.md instead.`,
    );
    failed = true;
    continue;
  }

  if (typeof parsed.buildCommand !== "string" || typeof parsed.outputDirectory !== "string") {
    console.error(`✗ ${name} is missing buildCommand or outputDirectory`);
    failed = true;
    continue;
  }

  console.log(`✓ ${name}`);
  console.log(`    build  ${String(parsed.buildCommand).slice(0, 70)}…`);
  console.log(`    output ${String(parsed.outputDirectory)}`);
}

if (failed) process.exit(1);
