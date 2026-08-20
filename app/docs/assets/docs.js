/**
 * Docs site behaviour. No framework — a documentation site that needs a
 * bundle to render a paragraph is a poor advertisement for a project whose
 * argument is that you should read the source.
 */

// ── Theme ────────────────────────────────────────────────────────────────
// Persisted, because re-choosing a theme on every page load would be worse
// than the small cost of a localStorage entry. No credential is stored here.
const root = document.documentElement;
const savedTheme = localStorage.getItem("veyra-docs-theme");
if (savedTheme) root.setAttribute("data-theme", savedTheme);
else if (window.matchMedia?.("(prefers-color-scheme: light)").matches) {
  root.setAttribute("data-theme", "light");
}

document.querySelector(".theme-toggle")?.addEventListener("click", () => {
  const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
  root.setAttribute("data-theme", next);
  localStorage.setItem("veyra-docs-theme", next);
});

// ── Mobile menu ──────────────────────────────────────────────────────────
const menuToggle = document.querySelector(".menu-toggle");
menuToggle?.addEventListener("click", () => {
  const sidebar = document.querySelector(".sidebar");
  const open = sidebar?.classList.toggle("open");
  menuToggle.setAttribute("aria-expanded", String(open));
});

// ── Copy buttons on code blocks ──────────────────────────────────────────
for (const block of document.querySelectorAll(".code-block")) {
  const button = document.createElement("button");
  button.className = "copy-btn";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    const code = block.querySelector("pre")?.innerText ?? "";
    try {
      await navigator.clipboard.writeText(code);
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = "Copy"), 1500);
    } catch {
      button.textContent = "Press Ctrl+C";
    }
  });
  block.appendChild(button);
}

// ── On-this-page highlighting ────────────────────────────────────────────
const tocLinks = [...document.querySelectorAll(".toc a")];
if (tocLinks.length > 0) {
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        for (const link of tocLinks) {
          link.classList.toggle("active", link.getAttribute("href") === `#${entry.target.id}`);
        }
      }
    },
    { rootMargin: "-76px 0px -70% 0px" },
  );
  for (const heading of document.querySelectorAll("h2[id]")) observer.observe(heading);
}

// ── Expandable endpoint cards ────────────────────────────────────────────
for (const endpoint of document.querySelectorAll(".endpoint")) {
  const head = endpoint.querySelector(".endpoint-head");
  head?.addEventListener("click", () => {
    const open = endpoint.classList.toggle("open");
    head.setAttribute("aria-expanded", String(open));
  });
}

// ── Live request console ─────────────────────────────────────────────────
// Credentials live in sessionStorage, not localStorage: they should not
// outlive the browser session, and a docs page is not a place to leave a
// wallet token lying around indefinitely.
const baseInput = document.getElementById("baseUrl");
const tokenInput = document.getElementById("token");

if (baseInput && tokenInput) {
  baseInput.value = sessionStorage.getItem("veyra-docs-base") || baseInput.value;
  tokenInput.value = sessionStorage.getItem("veyra-docs-token") || "";
  baseInput.addEventListener("input", () => sessionStorage.setItem("veyra-docs-base", baseInput.value));
  tokenInput.addEventListener("input", () => sessionStorage.setItem("veyra-docs-token", tokenInput.value));
}

function credentials() {
  return {
    base: (document.getElementById("baseUrl")?.value ?? "").replace(/\/$/, ""),
    token: (document.getElementById("token")?.value ?? "").trim(),
  };
}

const escapeHtml = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;");

for (const runner of document.querySelectorAll("[data-run]")) {
  runner.addEventListener("click", async () => {
    const card = runner.closest(".endpoint") ?? runner.closest(".console");
    const out = card?.querySelector(".result");
    if (!out) return;

    const { base, token } = credentials();
    if (!base) { out.textContent = "Set the API base URL first."; return; }

    let path = runner.dataset.path ?? "";
    const method = runner.dataset.method ?? "GET";

    const param = card.querySelector(".param");
    if (path.includes("{id}")) {
      const id = param?.value.trim();
      if (!id) { out.textContent = "Enter a prepared transaction id first."; return; }
      path = path.replace("{id}", encodeURIComponent(id));
    }

    const init = { method, headers: {} };
    if (runner.dataset.auth !== "false" && token) init.headers.Authorization = `Bearer ${token}`;

    const bodyField = card.querySelector(".reqbody");
    if (bodyField) {
      init.headers["Content-Type"] = "application/json";
      init.body = bodyField.value;
    }

    out.textContent = "Sending…";
    try {
      const started = performance.now();
      const response = await fetch(`${base}${path}`, init);
      const elapsed = Math.round(performance.now() - started);
      const text = await response.text();
      let pretty = text;
      try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch { /* not JSON */ }
      out.innerHTML =
        `<span class="status-code" data-ok="${response.ok}">${response.status}</span>${elapsed} ms` +
        `<pre>${escapeHtml(pretty)}</pre>`;
    } catch {
      out.innerHTML =
        `<span class="status-code" data-ok="false">—</span>` +
        `Could not reach the API. Check it is running, and that this page's origin is in VEYRA_ALLOWED_ORIGINS.`;
    }
  });
}

// A file:// page has origin "null", which the API's CORS allowlist excludes
// deliberately. Explain the block rather than letting requests fail opaquely.
if (location.protocol === "file:") {
  const warn = document.getElementById("fileWarn");
  if (warn) warn.style.display = "block";
}
