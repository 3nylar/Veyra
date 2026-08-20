/**
 * Build the PUBLIC site — documentation only.
 *
 * ─── What is deliberately NOT deployed ─────────────────────────────────────
 * The wallet interface. Two reasons, and the second is decisive:
 *
 *   1. It is useless hosted. It talks to an API on 127.0.0.1, which only
 *      exists on the visitor's own machine.
 *
 *   2. A page served over HTTPS cannot call http://127.0.0.1 — browsers block
 *      it as mixed content. So a hosted wallet UI would show a connection
 *      error to every visitor, and the obvious "fix" is to point it at a
 *      hosted API, which would mean hosting private keys for strangers.
 *
 * Self-custodial software is distributed as source that people run themselves.
 * The site's job is to explain it and link to the repository.
 */
import { cpSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "app", "dist-site");
const docs = join(root, "app", "docs");

if (!existsSync(join(docs, "introduction.html"))) {
  throw new Error("app/docs is empty — run `npm run docs:build` first");
}

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, "docs"), { recursive: true });
cpSync(docs, join(out, "docs"), { recursive: true });

console.log("Built public site into app/dist-site/");
console.log("  Contains: documentation only.");
console.log("  Excluded: the wallet interface — it must run locally.");
