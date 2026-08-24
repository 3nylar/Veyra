/**
 * SOURCE-TREE GUARD: core/ must run in a browser
 *
 * `docs/ARCHITECTURE.md` claims core/ can be dropped into a mobile or browser
 * UI unchanged. That claim was FALSE for months — four modules used `Buffer`
 * or `node:crypto`, and nothing caught it because every test ran in Node. See
 * docs/ATTACKS.md VEY-014.
 *
 * A claim about portability cannot be verified by tests that run in one
 * runtime, so this reads the source instead — the same technique as the
 * entropy and reference-isolation guards, and for the same reason: the failure
 * is invisible to behavioural testing.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const coreRoot = fileURLToPath(new URL("../../core", import.meta.url));

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...tsFiles(full));
    else if (entry.endsWith(".ts")) out.push(full);
  }
  return out;
}

const relativePosix = (from: string, to: string) => relative(from, to).split(sep).join("/");

/** Comments legitimately mention `Buffer` and `node:` while explaining why not to use them. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
}

/**
 * Files permitted to use Node APIs.
 *
 * The RPC chain source talks to a local bitcoind over HTTP with basic auth,
 * which is a server-side concern by definition — a browser cannot reach a
 * node on someone's LAN anyway. It is excluded deliberately, and narrowly.
 */
const NODE_ALLOWED = new Set(["chain/bitcoinRpc.ts"]);

const files = tsFiles(coreRoot);

describe("SECURITY GUARD: core/ is runtime-portable", () => {
  it("finds core source files to scan", () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it("the allowlist matches real files, so it cannot silently cover nothing", () => {
    // A backstop against a vacuous guard — the lesson of VEY-001.
    const paths = new Set(files.map((f) => relativePosix(coreRoot, f)));
    for (const allowed of NODE_ALLOWED) {
      expect(paths.has(allowed), `allowlisted file ${allowed} does not exist`).toBe(true);
    }
  });

  it("no module imports from 'node:'", () => {
    // A single node: import makes the whole dependency graph unusable in a
    // browser, which is how VEY-014 went unnoticed.
    const offenders = files
      .filter((f) => !NODE_ALLOWED.has(relativePosix(coreRoot, f)))
      .filter((f) => /from\s+["']node:|require\(["']node:/.test(stripComments(readFileSync(f, "utf8"))))
      .map((f) => relativePosix(coreRoot, f));
    expect(offenders).toEqual([]);
  });

  it("no module uses Buffer", () => {
    // Buffer is Node-only. `bytesToBase64`/`base64ToBytes` in
    // core/crypto/bytes.ts exist precisely so nothing needs it.
    const offenders = files
      .filter((f) => !NODE_ALLOWED.has(relativePosix(coreRoot, f)))
      .filter((f) => /\bBuffer\s*\./.test(stripComments(readFileSync(f, "utf8"))))
      .map((f) => relativePosix(coreRoot, f));
    expect(offenders).toEqual([]);
  });

  it("no module uses process, __dirname, or other Node globals", () => {
    const offenders: string[] = [];
    for (const file of files) {
      if (NODE_ALLOWED.has(relativePosix(coreRoot, file))) continue;
      const code = stripComments(readFileSync(file, "utf8"));
      if (/\bprocess\.(env|exit|cwd|argv)\b|\b__dirname\b|\b__filename\b/.test(code)) {
        offenders.push(relativePosix(coreRoot, file));
      }
    }
    expect(offenders).toEqual([]);
  });

  it("no module imports DOM-only globals either", () => {
    // Portable means BOTH directions: a `document` or `window` reference
    // would break the Node and React Native paths.
    const offenders = files
      .filter((f) => /\b(document|window|localStorage|sessionStorage)\s*\./.test(
        stripComments(readFileSync(f, "utf8")),
      ))
      .map((f) => relativePosix(coreRoot, f));
    expect(offenders).toEqual([]);
  });
});

describe("the portable primitives actually work", () => {
  it("base64 round-trips, including padding cases", async () => {
    const { bytesToBase64, base64ToBytes, bytesToHex } = await import("../../core/crypto/bytes.js");
    // Lengths 0-3 mod 3 exercise every padding branch.
    for (let length = 0; length < 40; length++) {
      const data = new Uint8Array(length);
      crypto.getRandomValues(data);
      expect(bytesToHex(base64ToBytes(bytesToBase64(data)))).toBe(bytesToHex(data));
    }
  });

  it("base64 matches the reference implementation", async () => {
    const { bytesToBase64, base64ToBytes } = await import("../../core/crypto/bytes.js");
    for (let i = 0; i < 200; i++) {
      const data = new Uint8Array(1 + Math.floor(Math.random() * 60));
      crypto.getRandomValues(data);
      // Buffer is the reference here, in a TEST — which may use Node freely.
      expect(bytesToBase64(data)).toBe(Buffer.from(data).toString("base64"));
      const text = Buffer.from(data).toString("base64");
      expect(Buffer.from(base64ToBytes(text)).toString("hex")).toBe(
        Buffer.from(data).toString("hex"),
      );
    }
  });

  it("base64 rejects malformed input rather than guessing", async () => {
    const { base64ToBytes } = await import("../../core/crypto/bytes.js");
    expect(() => base64ToBytes("not base64!")).toThrow();
    expect(() => base64ToBytes("abc")).toThrow(/multiple of 4/);
  });
});
