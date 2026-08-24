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
import { cpSync, mkdirSync, rmSync, existsSync, writeFileSync } from "node:fs";
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

/**
 * A real index.html at the root, rather than a host-side redirect.
 *
 * The site previously relied on a `redirects` rule in vercel.json to send `/`
 * to the introduction. That rule stops applying the moment a dashboard setting
 * overrides the file — and the result is a bare 404 at the domain root, which
 * is what happened. See docs/ATTACKS.md VEY-018.
 *
 * A physical file works on Vercel, Netlify, GitHub Pages, S3, nginx, and from
 * a local filesystem, because it depends on nothing but the file existing.
 * The meta refresh covers browsers; the link covers anything that ignores it.
 */
writeFileSync(
  join(out, "index.html"),
  `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="refresh" content="0; url=./docs/introduction.html" />
    <link rel="canonical" href="./docs/introduction.html" />
    <title>Veyra — Documentation</title>
  </head>
  <body>
    <p><a href="./docs/introduction.html">Veyra documentation</a></p>
    <script>location.replace("./docs/introduction.html");</script>
  </body>
</html>
`,
  "utf8",
);

// Vercel and Netlify both serve 404.html for unmatched paths.
writeFileSync(
  join(out, "404.html"),
  `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Not found — Veyra</title>
    <style>
      body{background:#0a0c0e;color:#e9eef1;font:15px/1.6 ui-sans-serif,system-ui,sans-serif;
        display:grid;place-items:center;min-height:100vh;margin:0;text-align:center}
      a{color:#14b8a6}
      h1{font-size:20px;letter-spacing:.14em;text-transform:uppercase}
    </style>
  </head>
  <body>
    <div>
      <h1>Veyra</h1>
      <p>That page does not exist.</p>
      <p><a href="/docs/introduction.html">Go to the documentation</a></p>
    </div>
  </body>
</html>
`,
  "utf8",
);

// Fail loudly rather than deploying a site whose root 404s.
for (const required of ["index.html", "docs/introduction.html"]) {
  if (!existsSync(join(out, required))) {
    throw new Error(`build produced no ${required} — the deployed root would 404`);
  }
}

console.log("Built public site into app/dist-site/");
console.log("  Contains: documentation only.");
console.log("  Excluded: the wallet interface — it must run locally.");
