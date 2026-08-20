/**
 * DOCS SITE — layout and navigation
 *
 * The shell is written once here and applied to every page. Hand-writing the
 * sidebar into fourteen files would guarantee they drift out of sync, and a
 * navigation that disagrees with itself is worse than no navigation.
 *
 * Output is plain static HTML with no client framework. A documentation site
 * that needs 200 KB of JavaScript to render a paragraph is a bad advertisement
 * for a project whose whole argument is that you should read the source.
 */

export interface Page {
  /** URL slug, without extension. */
  readonly slug: string;
  readonly title: string;
  /** Sidebar group. */
  readonly group: string;
  /** One-line summary under the H1, and the meta description. */
  readonly lede: string;
  /** Body HTML. `<h2 id="...">` headings become the on-this-page TOC. */
  readonly body: string;
}

export const GROUPS = [
  "Get started",
  "Core concepts",
  "Guides",
  "Reference",
] as const;

/** Pull `<h2 id="x">Label</h2>` out of the body for the right-hand TOC. */
function extractHeadings(body: string): Array<{ id: string; label: string }> {
  const out: Array<{ id: string; label: string }> = [];
  const pattern = /<h2 id="([^"]+)">([\s\S]*?)<\/h2>/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(body)) !== null) {
    out.push({
      id: match[1]!,
      // Strip any inline markup so the TOC stays plain text.
      label: match[2]!.replace(/<[^>]+>/g, "").trim(),
    });
  }
  return out;
}

/** Anchor links on every H2, so a section can be linked to directly. */
function addAnchors(body: string): string {
  return body.replace(
    /<h2 id="([^"]+)">([\s\S]*?)<\/h2>/g,
    (_full, id: string, label: string) =>
      `<h2 id="${id}"><a class="anchor" href="#${id}" aria-label="Link to this section">#</a>${label}</h2>`,
  );
}

export function renderPage(page: Page, all: readonly Page[]): string {
  const index = all.findIndex((p) => p.slug === page.slug);
  const previous = index > 0 ? all[index - 1] : null;
  const next = index < all.length - 1 ? all[index + 1] : null;
  const headings = extractHeadings(page.body);

  const sidebar = GROUPS.map((group) => {
    const pages = all.filter((p) => p.group === group);
    if (pages.length === 0) return "";
    return `
      <div class="nav-group">
        <h4>${group}</h4>
        ${pages
          .map(
            (p) =>
              `<a href="${p.slug}.html"${p.slug === page.slug ? ' class="current" aria-current="page"' : ""}>${p.title}</a>`,
          )
          .join("")}
      </div>`;
  }).join("");

  const toc =
    headings.length > 0
      ? `<aside class="toc">
           <h5>On this page</h5>
           ${headings.map((h) => `<a href="#${h.id}">${h.label}</a>`).join("")}
         </aside>`
      : `<aside class="toc"></aside>`;

  const pager = `
    <nav class="pager">
      ${previous ? `<a class="pager-link" href="${previous.slug}.html"><span>Previous</span><strong>${previous.title}</strong></a>` : "<span></span>"}
      ${next ? `<a class="pager-link next" href="${next.slug}.html"><span>Next</span><strong>${next.title}</strong></a>` : "<span></span>"}
    </nav>`;

  return `<!doctype html>
<html lang="en" data-theme="dark">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="${escapeAttr(page.lede)}" />
    <title>${page.title} — Veyra API</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="assets/docs.css" />
  </head>
  <body>
    <header class="topbar">
      <button class="menu-toggle" aria-label="Menu" aria-expanded="false">☰</button>
      <a class="brand" href="introduction.html">
        <span class="brand-mark">Veyra</span><span class="brand-kind">Docs</span>
      </a>
      <nav class="topnav">
        <a href="api-reference.html">API reference</a>
        <a href="changelog.html">Changelog</a>
        <a href="https://github.com" rel="noopener">GitHub</a>
        <button class="theme-toggle" aria-label="Toggle theme">◐</button>
      </nav>
    </header>

    <div class="layout">
      <nav class="sidebar" aria-label="Documentation">${sidebar}</nav>

      <main class="content">
        <p class="eyebrow">${page.group}</p>
        <h1>${page.title}</h1>
        <p class="lede">${page.lede}</p>
        ${addAnchors(page.body)}
        ${pager}
      </main>

      ${toc}
    </div>

    <script src="assets/docs.js" type="module"></script>
  </body>
</html>
`;
}

function escapeAttr(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}
