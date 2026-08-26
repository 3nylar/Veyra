/**
 * @vitest-environment jsdom
 *
 * LAYOUT AND HIERARCHY
 *
 * The interface was described as "empty and cluttered" — which is one problem,
 * not two. Everything was a `.card`: same border, same padding, same uppercase
 * micro-label. When every group carries equal visual weight nothing is a
 * hierarchy, so the eye reads noise (cluttered) while the generous uniform
 * padding leaves large dead areas (empty).
 *
 * These assertions pin the structural half of the fix, which is the half that
 * can regress silently. How it *looks* is a judgement call; how many competing
 * boxes are on screen is a fact.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { webcrypto } from "node:crypto";
import { encryptMnemonic } from "../../core/wallet/keystore.js";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSPHRASE = "a good passphrase";

const settle = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const root = () => document.getElementById("root")!;

async function click(selector: string) {
  document.querySelector<HTMLElement>(selector)?.dispatchEvent(
    new window.MouseEvent("click", { bubbles: true }),
  );
  await settle();
}

/** Top-level bordered containers competing for attention on this screen. */
const boxes = () => root().querySelectorAll(".card, .panel, .hero, .danger-zone").length;

beforeAll(async () => {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (input: unknown) => {
      const url = String(input);
      const body = url.includes("/blocks/tip/height")
        ? "160000"
        : url.includes("/address/")
          ? JSON.stringify({ chain_stats: { tx_count: 0 }, mempool_stats: { tx_count: 0 } })
          : "{}";
      return { ok: true, status: 200, text: async () => body } as Response;
    },
  });
  if (typeof globalThis.requestAnimationFrame !== "function") {
    Object.defineProperty(globalThis, "requestAnimationFrame", {
      value: (cb: FrameRequestCallback) => setTimeout(() => cb(0), 0) as unknown as number,
      configurable: true,
    });
  }

  document.body.innerHTML = `<div id="root"></div>`;
  localStorage.clear();
  localStorage.setItem(
    "veyra.keystore.v1",
    JSON.stringify(await encryptMnemonic(MNEMONIC, PASSPHRASE, { network: "signet" })),
  );
  localStorage.setItem(
    "veyra.prefs.v1",
    JSON.stringify({ network: "signet", esplora: "https://mempool.space/signet/api" }),
  );

  await import("../../app/src/wallet-app.js");
  await settle(100);

  (document.getElementById("unlockPass") as HTMLInputElement).value = PASSPHRASE;
  await click('[data-act="unlock"]');
  for (let i = 0; i < 40 && !document.getElementById("balanceCard"); i++) await settle(250);
  await settle(200);
}, 120_000);

describe("hierarchy", () => {
  it("gives the balance ONE hero and does not dress it as a card", async () => {
    await click('[data-nav="home"]');

    const hero = document.getElementById("balanceCard")!;
    expect(hero.classList.contains("hero")).toBe(true);
    // It used to carry `.card`, which gave it exactly the same border,
    // background and padding as the activity list beneath it.
    expect(hero.classList.contains("card")).toBe(false);
    expect(root().querySelectorAll(".hero")).toHaveLength(1);
  });

  it("keeps the home screen to a small number of competing boxes", async () => {
    await click('[data-nav="home"]');
    expect(boxes()).toBeLessThanOrEqual(3);
  });

  it("no longer stacks six identical boxes on settings", async () => {
    // The worst offender: six `.card`s in a column read as a wall rather than
    // as a set of choices.
    await click('[data-nav="settings"]');
    expect(boxes()).toBeLessThanOrEqual(5);
    await click('[data-nav="home"]');
  });
});

describe("wide-screen layout", () => {
  it("puts the home screen in a two-column grid container", async () => {
    // Below 900px the CSS collapses this to one column, so the same markup
    // serves both. The container has to exist for that to be possible.
    await click('[data-nav="home"]');

    const grid = root().querySelector(".home-grid");
    expect(grid, "home should render into .home-grid").not.toBeNull();
    expect(grid!.querySelectorAll(":scope > .col")).toHaveLength(2);
  });
});

describe("chrome", () => {
  it("moves Sync into the header instead of the bottom of the activity list", async () => {
    await click('[data-nav="home"]');

    const sync = root().querySelector('.topbar-actions [data-act="sync"]');
    expect(sync, "sync is a global action and belongs in the chrome").not.toBeNull();
    expect(sync!.getAttribute("aria-label")).toMatch(/sync/i);
  });

  it("labels every nav tab with text, not an icon alone", async () => {
    // Icons carry the visual weight; the words carry the meaning. An icon-only
    // tab bar is a guessing game, and every icon here is decorative by design
    // (`aria-hidden`), so the text is the only accessible name.
    const tabs = [...root().querySelectorAll<HTMLElement>(".nav button")];
    expect(tabs.length).toBe(4);
    for (const tab of tabs) {
      expect(tab.querySelector("svg")).not.toBeNull();
      expect(tab.textContent!.trim().length).toBeGreaterThan(2);
    }
  });

  it("marks every icon aria-hidden, since each sits beside a real label", async () => {
    const icons = [...root().querySelectorAll("svg.ic")];
    expect(icons.length).toBeGreaterThan(4);
    for (const svg of icons) {
      expect(svg.getAttribute("aria-hidden")).toBe("true");
    }
  });
});
