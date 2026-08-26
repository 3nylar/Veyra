/**
 * @vitest-environment jsdom
 *
 * THE WALLET INTERFACE, DRIVEN
 *
 * `standalone-render.test.ts` proves the built file loads and does not throw.
 * This one proves the parts a user touches actually behave: unlock, the flip
 * card, and — the assertion that matters most — that hiding the balance also
 * hides every amount elsewhere on screen.
 *
 * ─── Why this imports the source instead of the bundle ─────────────────────
 * The obvious approach is to inject the built inline script into a JSDOM built
 * by hand. It works, and it is ~75x slower: code inside a nested VM context
 * gets no JIT treatment, and scrypt at N=2¹⁷ — a deliberately memory-hard
 * function — went from 0.7 seconds to **50 seconds per unlock**. A test file
 * that costs ten minutes does not get run.
 *
 * Importing the module under vitest's own jsdom environment runs it in the
 * normal V8 context at full speed, and loses nothing here: whether the BUNDLE
 * executes is already `standalone-render.test.ts`'s job, and this file is
 * asking a different question — whether the interface behaves.
 *
 * ─── Why there is one import and one unlock ────────────────────────────────
 * `wallet-app.ts` registers document-level listeners at module load. Re-
 * importing it after `vi.resetModules()` would leave the previous listeners
 * attached to the same document, holding stale module state, and every click
 * would be handled twice. So the module is imported once and driven through a
 * sequence, which also means paying for scrypt exactly once.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { webcrypto } from "node:crypto";
import { encryptMnemonic } from "../../core/wallet/keystore.js";

/** A fixed BIP-39 vector. Nothing here ever touches a real key. */
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSPHRASE = "a good passphrase";

const settle = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const root = () => document.getElementById("root")!;
const text = () => root().textContent ?? "";
const card = () => document.getElementById("balanceCard");
const prefs = () => JSON.parse(localStorage.getItem("veyra.prefs.v1") ?? "{}");

async function click(selector: string) {
  document.querySelector<HTMLElement>(selector)?.dispatchEvent(
    new window.MouseEvent("click", { bubbles: true }),
  );
  await settle();
}

/** Answers a gap-limit scan truthfully for a wallet that has never been used. */
const stubFetch = async (input: unknown) => {
  const url = String(input);
  const body = url.includes("/blocks/tip/height")
    ? "160000"
    : url.includes("/address/")
      ? JSON.stringify({ chain_stats: { tx_count: 0 }, mempool_stats: { tx_count: 0 } })
      : "{}";
  return { ok: true, status: 200, text: async () => body } as Response;
};

beforeAll(async () => {
  // jsdom's `crypto` has no `subtle`, which the keystore needs for AES-GCM.
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  Object.defineProperty(globalThis, "fetch", { value: stubFetch, configurable: true });
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

  // Importing the module renders the first screen and wires the listeners.
  await import("../../app/src/wallet-app.js");
  await settle(100);
}, 120_000);

describe("unlock", () => {
  it("asks for a passphrase when a keystore is stored", () => {
    expect(text()).toContain("Unlock");
    expect(document.getElementById("unlockPass")).not.toBeNull();
  });

  it("opens the wallet with the right passphrase", async () => {
    (document.getElementById("unlockPass") as HTMLInputElement).value = PASSPHRASE;
    await click('[data-act="unlock"]');

    // scrypt, then a sync against the stub.
    for (let i = 0; i < 40 && !card(); i++) await settle(250);
    await settle(200);

    expect(card(), "the balance card should be on screen after unlocking").not.toBeNull();
  }, 60_000);
});

describe("the flip card", () => {
  it("is a real button, so it is keyboard operable with no extra code", () => {
    expect(card()!.tagName).toBe("BUTTON");
    expect(card()!.getAttribute("aria-label")).toMatch(/hide|show/i);
  });

  it("FAILS CLOSED — hidden when no preference was ever saved", () => {
    // A wallet that reveals a balance on first open in a café has failed at
    // the only thing this card is for. Absent and corrupt both mean hidden.
    expect(card()!.getAttribute("data-shown")).toBe("false");
    expect(card()!.getAttribute("aria-pressed")).toBe("false");
  });

  it("carries both faces, and the cover shows no figure", () => {
    const faces = [...document.querySelectorAll(".flip-face")].map((f) =>
      f.getAttribute("data-face"),
    );
    expect(faces).toContain("cover");
    expect(faces).toContain("balance");

    const cover = document.querySelector('.flip-face[data-face="cover"]')!.textContent ?? "";
    expect(cover).toContain("signet");
    expect(cover).toContain("••••••••");
    expect(cover, "the cover face must never carry a real amount").not.toMatch(/\d+\.\d{8}/);
  });
});

describe("hiding the balance hides the amounts", () => {
  it("masks the spendable figure on the send screen", async () => {
    // The leak that would make the flip card decorative. The send screen
    // states the spendable balance as a hint; if that stays readable while the
    // card is hidden, nothing has been hidden — and the user believes it has.
    await click('[data-nav="send"]');

    expect(text()).toContain("••••••");
    expect(text()).not.toMatch(/Spendable: \d+\.\d{8}/);
  });
});

describe("honest states", () => {
  it("says there are no transactions, rather than that something failed", async () => {
    await click('[data-nav="home"]');

    expect(text()).toContain("Nothing here yet");
    expect(text(), "an empty history is not a failed one").not.toContain("could not be loaded");
  });

  it("offers a way forward from the empty state instead of just reporting it", async () => {
    // A bordered box containing four words was the biggest patch of dead space
    // in a new wallet, and it left the person who most needs direction —
    // someone who has just created a wallet — with nothing to do.
    const cta = document.querySelector<HTMLElement>('.empty [data-nav="receive"]');
    expect(cta, "the empty activity state should offer the receive screen").not.toBeNull();
    expect(cta!.textContent).toContain("Show my address");
  });

  it("shows no USD anywhere on signet", () => {
    // Signet coins have no market value, so quoting one would be a lie — and
    // no price request is made there either.
    expect(text()).not.toContain("$");
  });
});

describe("revealing", () => {
  it("flips the card and PERSISTS the choice", async () => {
    expect(card()!.getAttribute("data-shown")).toBe("false");

    await click("#balanceCard");
    await settle(80);

    expect(card()!.getAttribute("data-shown")).toBe("true");
    expect(card()!.getAttribute("aria-pressed")).toBe("true");

    // Written to storage, not merely to the DOM. This is what survives a
    // reload, and what makes "come back on the face you left it on" true.
    expect(prefs().balanceHidden).toBe(false);
  });

  it("un-masks the amounts everywhere once revealed", async () => {
    await click('[data-nav="send"]');
    expect(text()).toMatch(/Spendable: \d+\.\d{8}/);
    await click('[data-nav="home"]');
  });

  it("hides again on a second press, and persists that too", async () => {
    await click("#balanceCard");
    await settle(80);

    expect(card()!.getAttribute("data-shown")).toBe("false");
    expect(prefs().balanceHidden).toBe(true);
  });
});
