/**
 * THE STANDALONE FILES ACTUALLY RUN
 *
 * ─── Why this test exists ──────────────────────────────────────────────────
 * All three standalone files shipped blank. The CSP said `script-src 'self'`,
 * which permits scripts fetched from the origin and FORBIDS inline ones — and
 * the build inlines the bundle. The browser refused to run the only script on
 * the page.
 *
 * Every existing check passed, because they all READ the file. A CSP violation
 * is a runtime refusal; no amount of grepping reveals it. So this test does
 * the one thing the others could not: it executes the page and asserts
 * something appeared.
 *
 * See docs/ATTACKS.md VEY-017.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { execSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const standalone = join(root, "standalone");

const PAGES = ["veyra.html", "veyra-sign.html", "veyra-watch.html"] as const;

beforeAll(() => {
  // Building takes ~20s; only do it if the output is missing.
  if (!existsSync(join(standalone, "veyra.html"))) {
    execSync("npx tsx scripts/build-standalone.ts", { cwd: root, stdio: "pipe" });
  }
}, 180_000);

const read = (name: string) => readFileSync(join(standalone, name), "utf8");

function cspOf(html: string): string {
  const meta = /<meta[^>]+http-equiv="Content-Security-Policy"[^>]+content="([^"]+)"/i.exec(html);
  if (!meta) throw new Error("no CSP meta tag");
  return meta[1]!.replace(/\s+/g, " ");
}

function inlineScripts(html: string): string[] {
  return [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)]
    .map((m) => m[1]!)
    .filter((code) => code.trim().length > 0);
}

describe.each(PAGES)("%s", (page) => {
  it("has a CSP", () => {
    expect(cspOf(read(page))).toContain("default-src 'none'");
  });

  it("AUTHORISES its own inline script by hash", () => {
    // The bug: `script-src 'self'` forbids inline scripts, so the page loaded
    // blank. A hash permits exactly this script and nothing injected.
    const html = read(page);
    const csp = cspOf(html);
    const scripts = inlineScripts(html);
    expect(scripts.length).toBeGreaterThan(0);

    for (const code of scripts) {
      const hash = createHash("sha256").update(code, "utf8").digest("base64");
      expect(csp).toContain(`'sha256-${hash}'`);
    }
  });

  it("does NOT fall back to 'unsafe-inline'", () => {
    // That would fix the blank page and permit any injected script — the
    // opposite of the protection this policy exists to give.
    expect(cspOf(read(page))).not.toContain("'unsafe-inline'; script-src");
    const scriptSrc = /(?:^|;)\s*script-src\s+([^;]+)/i.exec(cspOf(read(page)))![1]!;
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it("RENDERS something when executed", async () => {
    // The assertion the other checks structurally could not make.
    const html = read(page);
    const dom = new JSDOM(`<!doctype html><html><body>${
      /<body[^>]*>([\s\S]*?)<\/body>/i.exec(html)?.[1]?.replace(/<script[\s\S]*?<\/script>/gi, "") ?? ""
    }</body></html>`, {
      url: "https://example.com/",
      runScripts: "dangerously",
      beforeParse(window) {
        Object.defineProperty(window, "crypto", { value: webcrypto, configurable: true });
      },
    });

    const script = dom.window.document.createElement("script");
    script.textContent = inlineScripts(html)[0]!;
    dom.window.document.body.appendChild(script);

    await new Promise((resolve) => setTimeout(resolve, 800));

    const text = dom.window.document.body.textContent?.trim() ?? "";
    expect(text.length, `${page} rendered nothing`).toBeGreaterThan(100);
  }, 60_000);
});

describe("veyra.html specifically", () => {
  it("shows the onboarding screen with no stored wallet", async () => {
    const html = read("veyra.html");
    const dom = new JSDOM(`<!doctype html><html><body><div id="root"></div></body></html>`, {
      url: "https://example.com/",
      runScripts: "dangerously",
      beforeParse(window) {
        Object.defineProperty(window, "crypto", { value: webcrypto, configurable: true });
      },
    });
    const script = dom.window.document.createElement("script");
    script.textContent = inlineScripts(html)[0]!;
    dom.window.document.body.appendChild(script);
    await new Promise((resolve) => setTimeout(resolve, 800));

    const text = dom.window.document.getElementById("root")!.textContent!;
    expect(text).toContain("Create a wallet");
    expect(text).toContain("Restore");
    // The warning a user must see before generating a key.
    expect(text.toLowerCase()).toContain("recover");
  }, 60_000);

  it("PINS connect-src rather than allowing a wildcard", () => {
    // This page holds keys; a wildcard would let injected script post them
    // anywhere. See ATTACKS.md VEY-016.
    const scriptSrc = /(?:^|;)\s*connect-src\s+([^;]+)/i.exec(cspOf(read("veyra.html")))![1]!;
    for (const wildcard of ["*", "https:", "http:", "data:"]) {
      expect(scriptSrc.split(/\s+/)).not.toContain(wildcard);
    }
  });
});

describe("veyra-sign.html specifically", () => {
  it("forbids ALL network access", () => {
    // The guarantee that makes it safe to hold a seed: there is no channel to
    // send one out through.
    expect(cspOf(read("veyra-sign.html"))).toContain("connect-src 'none'");
  });
});
