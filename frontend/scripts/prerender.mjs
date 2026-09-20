/**
 * Build-time prerender for kaeorn.com  (runs after `vite build` + the SSR build)
 *
 * WHY THIS EXISTS
 * The storefront is a client-side React app. Before this step every URL returned the same empty
 * <div id="root"> with the same hard-coded canonical (the homepage), so Google saw ~40 URLs that
 * all said "I am a duplicate of /" and indexed almost nothing.
 *
 * WHAT IT DOES
 *  1. Renders every public route to real HTML (react-dom/server) — real <h1>, text and <a href>
 *     links, plus that page's own <title>, description, canonical, Open Graph and JSON-LD in <head>.
 *  2. Pulls published blog posts from the API and renders them too (so they don't depend on the
 *     API being awake when Googlebot arrives).
 *  3. Writes dist/<route>.html (Vercel `cleanUrls` serves it at /<route>) — dist/index.html for "/".
 *  4. Writes dist/app-shell.html (empty SPA shell — used for private pages and brand-new blog posts)
 *     and dist/404.html (real 404 status for unknown URLs).
 *  5. Regenerates dist/sitemap.xml from the routes above + the blog posts.
 *  6. Verifies every page (one canonical = its own URL, one title, one <h1>, real links) and FAILS THE
 *     BUILD if a static page is wrong, so this can never silently regress.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadEnv } from "vite";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(ROOT, "dist");
const SSR = path.join(ROOT, "dist-ssr", "entry-server.js");
const SITE = "https://kaeorn.com";

const env = { ...loadEnv("production", ROOT, "VITE_"), ...process.env };
const API = (env.VITE_API_BASE || "").replace(/\/$/, "");

/* Every public, indexable, statically-known page.  Keep in sync with <Routes> in src/App.jsx */
const STATIC_ROUTES = [
  { path: "/", priority: "1.0", changefreq: "weekly" },
  { path: "/perfume/noir-party-perfume", priority: "0.9", changefreq: "weekly" },
  { path: "/perfume/soie-femme-floral-perfume", priority: "0.9", changefreq: "weekly" },
  { path: "/perfume/veil-fresh-perfume", priority: "0.9", changefreq: "weekly" },
  { path: "/perfume/discovery-set", priority: "0.9", changefreq: "weekly" },
  { path: "/perfume/nox", priority: "0.6", changefreq: "monthly" },
  { path: "/perfume/velion", priority: "0.6", changefreq: "monthly" },
  { path: "/blogs", priority: "0.8", changefreq: "weekly" },
  { path: "/program/ambassador", priority: "0.6", changefreq: "monthly" },
  { path: "/about", priority: "0.7", changefreq: "monthly" },
  { path: "/contact", priority: "0.5", changefreq: "yearly" },
  { path: "/privacy", priority: "0.3", changefreq: "yearly" },
  { path: "/terms", priority: "0.3", changefreq: "yearly" },
  { path: "/refund", priority: "0.3", changefreq: "yearly" },
  { path: "/shipping", priority: "0.3", changefreq: "yearly" },
];

const log = (...a) => console.log("[prerender]", ...a);
const warn = (...a) => console.warn("[prerender] ⚠", ...a);

/* ───────────────────────── helpers ───────────────────────── */

const escapeXml = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** React 19 hoists <title>/<meta>/<link> to the *front* of renderToString output. Peel them off. */
function splitHoisted(html) {
  const head = [];
  let rest = html;
  const re = /^(?:<title[^>]*>[\s\S]*?<\/title>|<meta\b[^>]*\/?>|<link\b[^>]*\/?>|<base\b[^>]*\/?>)/;
  for (;;) {
    const m = rest.match(re);
    if (!m) break;
    head.push(m[0]);
    rest = rest.slice(m[0].length);
  }
  return { head, body: rest };
}

/** Pull JSON-LD out of the body so it lives in <head> (still valid either way). */
function extractJsonLd(body) {
  const scripts = [];
  const cleaned = body.replace(
    /<script type="application\/ld\+json">[\s\S]*?<\/script>/g,
    (m) => {
      scripts.push(m);
      return "";
    },
  );
  return { scripts, body: cleaned };
}

const markPrerender = (tag) => tag.replace(/^<(\w+)/, '<$1 data-prerender="1"');

function withoutOld(templateHtml) {
  // Belt & braces: drop any title/description/canonical that may exist in the template.
  return templateHtml
    .replace(/<title>[\s\S]*?<\/title>\s*/i, "")
    .replace(/<meta\s+name="description"[\s\S]*?\/?>\s*/i, "")
    .replace(/<link\s+rel="canonical"[^>]*\/?>\s*/i, "");
}

function buildPage(template, { head, body }) {
  const headHtml = head.map(markPrerender).join("\n    ");
  return template
    .replace("</head>", `    ${headHtml}\n  </head>`)
    .replace('<div id="root"></div>', `<div id="root">${body}</div>`)
    .replace(/<div id="root">\s*<\/div>/, `<div id="root">${body}</div>`);
}

async function write(file, contents) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, contents, "utf8");
}

const fileFor = (route) => (route === "/" ? path.join(DIST, "index.html") : path.join(DIST, `${route.slice(1)}.html`));

/* ───────────────────────── blog data ───────────────────────── */

async function fetchBlogs() {
  if (!API) {
    warn("VITE_API_BASE is not set — skipping blog prerender (posts will be served by the SPA shell).");
    return null;
  }
  // Render's free tier sleeps when idle and can take 30-60 s to wake, so: generous timeout + retries.
  const ATTEMPTS = 3;
  for (let i = 1; i <= ATTEMPTS; i++) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 90_000);
      const res = await fetch(`${API}/api/blogs`, { signal: ctrl.signal, headers: { accept: "application/json" } });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error("unexpected response shape");
      log(`fetched ${data.length} published blog post(s) from ${API} (attempt ${i})`);
      return data.filter((b) => b && b.slug && b.title);
    } catch (e) {
      warn(`blog fetch attempt ${i}/${ATTEMPTS} failed (${e.name === "AbortError" ? "timed out" : e.message})`);
      if (i < ATTEMPTS) await new Promise((r) => setTimeout(r, 5_000 * i));
    }
  }
  warn("could not fetch blogs — blog pages fall back to the SPA shell this build (re-deploy once the API is up).");
  return null;
}

/* ───────────────────────── main ───────────────────────── */

const templatePath = path.join(DIST, "index.html");
// Idempotent: keep a pristine copy of Vite's index.html so re-running this script (which overwrites
// dist/index.html with the prerendered homepage) never uses an already-rendered page as the template.
const pristinePath = path.join(ROOT, "dist-ssr", "index.template.html");
let rawTemplate = await fs.readFile(templatePath, "utf8");
if (rawTemplate.includes("data-prerender")) rawTemplate = await fs.readFile(pristinePath, "utf8");
else await fs.writeFile(pristinePath, rawTemplate, "utf8");
const template = withoutOld(rawTemplate);

const fetched = await fetchBlogs(); // null = API unreachable / not configured (unknown), [] = reachable but no published posts
const blogs = fetched ?? [];
if (fetched && fetched.length === 0) {
  warn("the API is reachable but returned 0 PUBLISHED blog posts — /blogs will render the empty state. (Posts need published: true.)");
}
// Only hand data to the renderer when we actually have it; otherwise pages render their normal loading state.
globalThis.__PRERENDER_DATA__ = fetched
  ? { blogs: fetched, blogBySlug: Object.fromEntries(fetched.map((b) => [b.slug, b])) }
  : {};

/* Customer reviews per product (so crawlers get the real review text + rating in the HTML) */
const REVIEW_PRODUCT_IDS = ["the-noir-men", "perfume-veil-unisex", "perfume-soie-femme", "nox", "velion", "discovery-set"];
if (API) {
  const reviews = {};
  for (const id of REVIEW_PRODUCT_IDS) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 30_000);
      const res = await fetch(`${API}/api/reviews/${id}`, { signal: ctrl.signal });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();
      if (d && d.summary && Array.isArray(d.reviews)) reviews[id] = d;
    } catch (e) {
      warn(`reviews for ${id} not prerendered (${e.message}) — the browser will load them instead.`);
    }
  }
  globalThis.__PRERENDER_DATA__.reviews = reviews;
  log(`fetched reviews for ${Object.keys(reviews).length}/${REVIEW_PRODUCT_IDS.length} products`);
}

// If the API was unreachable, keep the previously-known post URLs in the sitemap so they aren't dropped.
const FALLBACK_BLOG_SLUGS = fetched
  ? []
  : [
      "why-kaeorn-perfumes-are-unique",
      "how-to-choose-perfume-kaeorn-guide",
      "kaeorn-perfumes-luxury-fragrance-india",
    ];

const { render } = await import(pathToFileURL(SSR).href);

const routes = [
  ...STATIC_ROUTES,
  ...blogs.map((b) => ({
    path: `/blogs/${b.slug}`,
    priority: "0.7",
    changefreq: "monthly",
    lastmod: (b.updatedAt || b.createdAt || "").slice(0, 10),
    isBlog: true,
  })),
];

const problems = [];
const rendered = [];

for (const r of routes) {
  let out;
  try {
    out = render(r.path);
  } catch (e) {
    problems.push(`${r.path}: render crashed — ${e.message}`);
    continue;
  }
  const { head, body: b1 } = splitHoisted(out.html);
  const { scripts, body } = extractJsonLd(b1);
  const page = buildPage(template, { head: [...head, ...scripts], body });

  /* ---- verification ---- */
  const url = r.path === "/" ? `${SITE}/` : `${SITE}${r.path}`;
  const canon = [...page.matchAll(/<link[^>]*rel="canonical"[^>]*>/g)].map((m) => m[0]);
  const titles = [...page.matchAll(/<title[^>]*>([\s\S]*?)<\/title>/g)];
  const descs = [...page.matchAll(/<meta[^>]*name="description"[^>]*>/g)];
  const h1s = [...body.matchAll(/<h1[\s>]/g)];
  const links = [...body.matchAll(/<a [^>]*href="\/[^"#]/g)];
  const errs = [];
  if (canon.length !== 1) errs.push(`expected exactly 1 canonical, found ${canon.length}`);
  else if (!canon[0].includes(`href="${url}"`)) errs.push(`canonical is not self-referencing (${canon[0]})`);
  if (titles.length !== 1) errs.push(`expected exactly 1 <title>, found ${titles.length}`);
  else if (!titles[0][1].trim()) errs.push("<title> is empty");
  if (descs.length !== 1) errs.push(`expected exactly 1 meta description, found ${descs.length}`);
  else if (!/content="[^"]{20,}"/.test(descs[0][0])) errs.push("meta description is empty/too short");
  if (h1s.length < 1) errs.push("no <h1> in server-rendered HTML");
  if (r.path !== "/" && links.length < 1) errs.push("no internal <a href> links found");
  if (/noindex/i.test(page)) errs.push("page contains a noindex directive");
  if (errs.length) {
    // Blog pages come from the CMS — warn, don't fail the whole deploy over one post.
    (r.isBlog ? warn : (m) => problems.push(m))(`${r.path}: ${errs.join("; ")}`);
    if (r.isBlog) continue;
  }

  await write(fileFor(r.path), page);
  rendered.push({ ...r, title: titles[0]?.[1], h1: h1s.length, links: links.length, bytes: Buffer.byteLength(page) });
}

if (problems.length) {
  console.error("\n[prerender] ✖ build failed:\n - " + problems.join("\n - "));
  process.exit(1);
}

/* ---- app shell (private pages, brand-new blog posts) & 404 ---- */
const shell = template.replace("</head>", `    <title>KAEORN</title>\n  </head>`);
await write(path.join(DIST, "app-shell.html"), shell);
await write(
  path.join(DIST, "404.html"),
  template.replace(
    "</head>",
    `    <title>Page not found | KAEORN</title>\n    <meta name="robots" content="noindex" />\n  </head>`,
  ),
);

/* ---- sitemap ---- */
const urls = [
  ...routes.filter((r) => rendered.some((x) => x.path === r.path)),
  ...FALLBACK_BLOG_SLUGS.map((slug) => ({ path: `/blogs/${slug}`, priority: "0.7", changefreq: "monthly" })),
]
  .map((r) => {
    const loc = r.path === "/" ? `${SITE}/` : `${SITE}${r.path}`;
    return [
      "  <url>",
      `    <loc>${escapeXml(loc)}</loc>`,
      r.lastmod ? `    <lastmod>${r.lastmod}</lastmod>` : null,
      `    <changefreq>${r.changefreq}</changefreq>`,
      `    <priority>${r.priority}</priority>`,
      "  </url>",
    ]
      .filter(Boolean)
      .join("\n");
  })
  .join("\n");
await write(
  path.join(DIST, "sitemap.xml"),
  `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`,
);

/* ---- report ---- */
log(`prerendered ${rendered.length} pages:`);
for (const r of rendered) {
  console.log(`   ${r.path.padEnd(40)} ${String(Math.round(r.bytes / 1024)).padStart(4)} kB  h1:${r.h1}  links:${String(r.links).padStart(2)}  ${r.title ?? ""}`);
}
log("wrote app-shell.html, 404.html and sitemap.xml");
