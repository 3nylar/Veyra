import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";
import { encryptMnemonic } from "../core/wallet/keystore.js";

const M = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const P = "a good passphrase";
const dom = new JSDOM(`<!doctype html><html><body><div id="root"></div></body></html>`, { url: "https://v.test/" });
const g: any = globalThis;
g.window = dom.window; g.document = dom.window.document;
g.localStorage = dom.window.localStorage; g.navigator = dom.window.navigator;
g.MouseEvent = dom.window.MouseEvent; g.confirm = () => true;
g.requestAnimationFrame = (cb: any) => setTimeout(() => cb(0), 0);
Object.defineProperty(g, "crypto", { value: webcrypto, configurable: true });
g.fetch = async (i: unknown) => {
  const u = String(i);
  const b = u.includes("tip/height") ? "160000"
    : u.includes("/address/") ? JSON.stringify({chain_stats:{tx_count:0},mempool_stats:{tx_count:0}}) : "{}";
  return { ok: true, status: 200, text: async () => b } as Response;
};
localStorage.setItem("veyra.keystore.v1", JSON.stringify(await encryptMnemonic(M, P, { network: "signet" })));
localStorage.setItem("veyra.prefs.v1", JSON.stringify({network:"signet",esplora:"https://mempool.space/signet/api"}));

await import("../app/src/wallet-app.js");
await new Promise(r => setTimeout(r, 200));
(document.getElementById("unlockPass") as HTMLInputElement).value = P;
document.querySelector<HTMLElement>('[data-act="unlock"]')!.dispatchEvent(new MouseEvent("click",{bubbles:true}));
for (let i=0;i<40 && !document.getElementById("balanceCard");i++) await new Promise(r=>setTimeout(r,250));
await new Promise(r=>setTimeout(r,300));

const click = async (s: string) => { document.querySelector<HTMLElement>(s)?.dispatchEvent(new MouseEvent("click",{bubbles:true})); await new Promise(r=>setTimeout(r,80)); };

function outline(label: string) {
  const root = document.getElementById("root")!;
  const cards = root.querySelectorAll(".card, .flip");
  const notices = root.querySelectorAll(".notice");
  const buttons = root.querySelectorAll("button");
  const chars = (root.textContent ?? "").replace(/\s+/g," ").trim().length;
  console.log(`\n${"=".repeat(60)}\n  ${label.toUpperCase()}`);
  console.log(`  cards=${cards.length}  notices=${notices.length}  buttons=${buttons.length}  text=${chars} chars`);
  cards.forEach((c, i) => {
    const lbl = c.querySelector(".label")?.textContent?.trim() ?? "(no label)";
    const t = (c.textContent ?? "").replace(/\s+/g," ").trim();
    console.log(`    card ${i+1}: "${lbl}" — ${t.length} chars`);
  });
}
outline("home"); await click('[data-nav="receive"]'); outline("receive");
await click('[data-nav="send"]'); outline("send");
await click('[data-nav="settings"]'); outline("settings");
process.exit(0);
