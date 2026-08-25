/**
 * THE STORED `fetch` MUST NOT BE INVOKED AS A METHOD
 *
 * ─── The defect ────────────────────────────────────────────────────────────
 * Both chain sources take an injectable `fetchImpl` and default it to the
 * global `fetch`. The default was stored bare on the instance:
 *
 *     this.fetchImpl = options.fetchImpl ?? globalThis.fetch;   // ← the bug
 *     ...
 *     await this.fetchImpl(url, init);                          // ← method call
 *
 * `this.fetchImpl(...)` is a METHOD call, so `this` inside native fetch is the
 * chain source rather than the Window. Browsers brand-check the receiver and
 * throw `TypeError: Failed to execute 'fetch' on 'Window': Illegal invocation`,
 * which `request()` then wrapped into the message every user of the deployed
 * wallet saw when they pressed Sync — on wallet.html AND watch.html:
 *
 *     Chain: network error: Failed to execute 'fetch' on 'Window': Illegal invocation
 *
 * ─── Why 55 existing tests missed it ───────────────────────────────────────
 * Two independent reasons, and BOTH have to be defeated for a test here to be
 * worth anything:
 *
 *   1. Every existing Esplora and RPC test injects a `fetchImpl`, so the
 *      defaulting branch — the only broken one — was never executed.
 *   2. `vitest.config.ts` runs in `environment: "node"`, and Node's undici
 *      `fetch` performs no receiver brand check. Even executing the default
 *      branch under Node passes with the bug present.
 *
 * jsdom would not have helped either: jsdom 25 ships no `fetch` at all. So the
 * approach here is to SUPPLY the check the runtime is missing, rather than
 * hope some runtime provides it. That is the whole trick.
 *
 * See docs/ATTACKS.md VEY-020.
 */
import { describe, it, expect, afterEach } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { EsploraChainSource } from "../../core/chain/esplora.js";
import { BitcoinRpcChainSource } from "../../core/chain/bitcoinRpc.js";

/**
 * A `fetch` that brand-checks its receiver, exactly as a browser's does.
 *
 * NOT an arrow function — an arrow has no `this` of its own, which would make
 * the guard vacuous. That is precisely why every injected fake in the suite
 * was blind to this defect.
 */
function brandCheckedFetch(body: string): typeof fetch {
  return function (this: unknown) {
    if (this !== undefined && this !== globalThis) {
      throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
    }
    return Promise.resolve({ ok: true, status: 200, text: async () => body } as Response);
  } as unknown as typeof fetch;
}

/** Records the receiver each call was made with, so it can be asserted on. */
function receiverSpy(body: string) {
  const seen: unknown[] = [];
  const impl = function (this: unknown) {
    seen.push(this);
    return Promise.resolve({ ok: true, status: 200, text: async () => body } as Response);
  } as unknown as typeof fetch;
  return { impl, seen };
}

const original = globalThis.fetch;
const setGlobalFetch = (value: unknown) =>
  Object.defineProperty(globalThis, "fetch", { value, configurable: true, writable: true });

afterEach(() => setGlobalFetch(original));

const HEIGHT = "2500000";
const RPC_HEIGHT = JSON.stringify({ result: 2_500_000, error: null, id: "veyra" });

// `maxRetries: 0` throughout: with the default of 2 a receiver failure is
// retried three times before surfacing, tripling the runtime for no gain.
const esplora = (extra: Record<string, unknown> = {}) =>
  new EsploraChainSource({
    baseUrl: "https://example.test/api",
    network: "testnet",
    maxRetries: 0,
    ...extra,
  });

const rpc = (extra: Record<string, unknown> = {}) =>
  new BitcoinRpcChainSource({
    url: "http://127.0.0.1:18443",
    network: "regtest",
    username: "veyra",
    password: "veyra",
    ...extra,
  });

describe("EsploraChainSource", () => {
  it("survives a receiver brand check on the DEFAULT global fetch", async () => {
    // No `fetchImpl`. This is the branch the deployed wallet takes, and the
    // one no other test in the suite covers.
    setGlobalFetch(brandCheckedFetch(HEIGHT));

    await expect(esplora().getBlockHeight()).resolves.toBe(2_500_000);
  });

  it("survives a receiver brand check on an INJECTED fetch", async () => {
    // Someone passing `window.fetch` straight through must not reintroduce it.
    await expect(
      esplora({ fetchImpl: brandCheckedFetch(HEIGHT) }).getBlockHeight(),
    ).resolves.toBe(2_500_000);
  });

  it("names the failure recognisably if it ever regresses", async () => {
    // The fingerprint of this bug is one string. Pinning it means the next
    // person to see the failure can search for it and land on VEY-020.
    setGlobalFetch(brandCheckedFetch(HEIGHT));
    const source = esplora();

    let message = "";
    try {
      await source.getBlockHeight();
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toContain("Illegal invocation");
  });

  it("never invokes the stored implementation with the chain source as receiver", async () => {
    const { impl, seen } = receiverSpy(HEIGHT);
    await esplora({ fetchImpl: impl }).getBlockHeight();

    expect(seen).not.toHaveLength(0);
    for (const receiver of seen) {
      expect(receiver).not.toBeInstanceOf(EsploraChainSource);
      expect(receiver === undefined || receiver === globalThis).toBe(true);
    }
  });

  it("still reports a runtime with no fetch as a ChainError", () => {
    // The binding must not turn a missing implementation into a raw TypeError
    // from `.bind` — the explanatory ChainError is the useful outcome.
    setGlobalFetch(undefined);

    expect(() => esplora()).toThrow(/no fetch implementation/);
  });
});

describe("BitcoinRpcChainSource — the same defect, fixed the same way", () => {
  it("survives a receiver brand check on the DEFAULT global fetch", async () => {
    setGlobalFetch(brandCheckedFetch(RPC_HEIGHT));

    await expect(rpc().getBlockHeight()).resolves.toBe(2_500_000);
  });

  it("never invokes the stored implementation with the chain source as receiver", async () => {
    const { impl, seen } = receiverSpy(RPC_HEIGHT);
    await rpc({ fetchImpl: impl }).getBlockHeight();

    expect(seen).not.toHaveLength(0);
    for (const receiver of seen) {
      expect(receiver).not.toBeInstanceOf(BitcoinRpcChainSource);
      expect(receiver === undefined || receiver === globalThis).toBe(true);
    }
  });

  it("still reports a runtime with no fetch as a ChainError", () => {
    setGlobalFetch(undefined);

    expect(() => rpc()).toThrow(/no fetch implementation/);
  });
});

/**
 * A source-tree guard, in the style of tests/cryptography/portability.test.ts.
 *
 * The behavioural tests above cover the two chain sources that exist today.
 * This one catches the third copy somebody adds next year, in a file nobody
 * thought to write a receiver test for.
 *
 * It is deliberately shipped ALONGSIDE the behavioural tests and never instead
 * of them: a source scan proves a shape, not a behaviour, and VEY-016 in this
 * repo is the story of a guard that passed by reading its own comment.
 */
describe("GUARD: core/ never calls a stored fetch as a method", () => {
  const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "core");

  function sourceFiles(dir: string): string[] {
    const found: string[] = [];
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) found.push(...sourceFiles(full));
      else if (entry.endsWith(".ts")) found.push(full);
    }
    return found;
  }

  /** Strip comments so a mention in prose is not mistaken for a call. */
  const stripComments = (source: string) =>
    source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

  it("finds no `this.fetchImpl(` call anywhere in core/", () => {
    const offenders: string[] = [];

    for (const file of sourceFiles(coreDir)) {
      const code = stripComments(readFileSync(file, "utf8"));
      if (/this\.fetchImpl\s*\(/.test(code)) {
        offenders.push(file.slice(coreDir.length + 1).replace(/\\/g, "/"));
      }
    }

    // The fix is to read it into a local first:
    //     const doFetch = this.fetchImpl;
    //     await doFetch(url, init);
    expect(offenders).toEqual([]);
  });

  it("scans a plausible number of files, so an empty pass means something", () => {
    // A guard that silently scanned zero files would pass forever. VEY-016.
    expect(sourceFiles(coreDir).length).toBeGreaterThan(30);
  });
});
