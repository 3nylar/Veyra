/**
 * Build the documentation site.
 *
 * Emits static HTML into app/docs/, which the Vite dev server already serves.
 * Run: npm run docs:build
 */
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderPage, GROUPS } from "./docs/layout.js";
import { PAGES } from "./docs/content.js";

// fileURLToPath, not .pathname — see docs/ATTACKS.md VEY-001.
const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "app", "docs");

if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

// Fail loudly on a duplicate slug: two pages writing the same file would mean
// one silently disappears from the site.
const slugs = new Set<string>();
for (const page of PAGES) {
  if (slugs.has(page.slug)) throw new Error(`duplicate slug: ${page.slug}`);
  slugs.add(page.slug);
  if (!GROUPS.includes(page.group as (typeof GROUPS)[number])) {
    throw new Error(`page '${page.slug}' has unknown group '${page.group}'`);
  }
}

// Every internal link must point at a page that exists. A docs site with a
// dead link is a docs site nobody finishes reading.
const broken: string[] = [];
for (const page of PAGES) {
  for (const match of page.body.matchAll(/href="([a-z0-9-]+)\.html"/g)) {
    if (!slugs.has(match[1]!)) broken.push(`${page.slug} → ${match[1]}.html`);
  }
}
if (broken.length > 0) throw new Error(`broken internal links:\n  ${broken.join("\n  ")}`);

for (const page of PAGES) {
  writeFileSync(join(outDir, `${page.slug}.html`), renderPage(page, PAGES), "utf8");
}

// index.html redirects to the introduction, so /docs/ works as a URL.
writeFileSync(
  join(outDir, "index.html"),
  `<!doctype html><html lang="en"><head><meta charset="utf-8" />
<meta http-equiv="refresh" content="0; url=introduction.html" />
<title>Veyra API Docs</title></head>
<body><p><a href="introduction.html">Veyra API documentation</a></p></body></html>\n`,
  "utf8",
);

console.log(`Built ${PAGES.length} pages into app/docs/`);
for (const group of GROUPS) {
  const pages = PAGES.filter((p) => p.group === group);
  console.log(`  ${group}: ${pages.map((p) => p.slug).join(", ")}`);
}
