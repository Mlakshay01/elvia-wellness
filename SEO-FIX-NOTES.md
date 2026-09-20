# kaeorn.com indexing fix — what changed

Root causes: (1) index.html had a hard-coded canonical -> "/" served for EVERY route, (2) product/blog/footer links were
onClick handlers (not crawlable), (3) removed/unknown URLs returned 200 blank pages.

## Frontend
- `scripts/prerender.mjs` + `src/entry-server.jsx`: build now renders 15+ public pages (and every published blog) to real HTML
  with per-page title/description/canonical/JSON-LD. Build FAILS if a page has a wrong/duplicate canonical, empty title/description, or no <h1>.
- `package.json` build: `vite build && vite build --ssr src/entry-server.jsx --outDir dist-ssr && node scripts/prerender.mjs`.
  Removed unused `react-snap` / `vite-ssg`.
- `index.html`: static canonical + description removed.
- `src/App.jsx` (new, from main.jsx): lazy-loaded private/admin routes, noindex on private paths, 404 route. `main.jsx` is now just the client entry.
- `src/components/CrawlLink.jsx`: real <a href> for cards; Footer/Navbar logo/Blog cards now use real links.
- `src/seo/schema.js`: Product, Breadcrumb, Article, Organization, WebSite JSON-LD.
- Ambassador page got its own head; NOX/VELION meta prices fixed (₹499); blog <title> bug fixed.
- `vercel.json`: cleanUrls, 301s for old slugs (CONFIRM targets), rewrites of blog fallback + private routes to /app-shell.html, noindex header on private routes.
- `robots.txt`, `public/sitemap.xml` updated (build regenerates sitemap incl. blog posts).

## Backend
- `routes/blogRoutes.js`: optional `VERCEL_DEPLOY_HOOK_URL` env -> triggers a (debounced) frontend rebuild when a blog is created/edited/deleted.

## Set on Vercel
- `VITE_API_BASE` must be available at BUILD time (blog prerender reads it).
- Optional deploy hook URL -> backend env `VERCEL_DEPLOY_HOOK_URL`.

## Then, in Google Search Console
Test live URL on / and a product page, resubmit sitemap, Request indexing, Validate fix on each report.

## Customer reviews (replaces the hardcoded ones)
- Removed the hardcoded REVIEWS from THÉ NOIR, VEIL, SOIE FEMME, NOX, VELION.
- Backend: `models/Review.js`, `routes/reviewRoutes.js` (mounted at `/api/reviews`, `trust proxy` enabled for the per-IP rate limit).
  - `GET  /api/reviews/:productId`            public — published reviews + rating summary
  - `GET  /api/reviews/:productId/mine`       logged-in — my review + whether I bought it
  - `POST /api/reviews/:productId`            logged-in — create/update my review {rating 1-5, title?, comment 10-1000 chars}
  - `DELETE /api/reviews/:productId/mine`     logged-in — delete my review
  - Admin (adminAuth): `GET /api/reviews/admin/all`, `PATCH /api/reviews/admin/:id {status:"hidden"|"published"}`, `DELETE /api/reviews/admin/:id`
  - One review per user per product; markup is stripped; display name = "First L." (never the email); "Verified buyer" badge when the user has a paid order containing the product (30 ml variants count).
- Frontend: `components/ProductReviews.jsx` + `hooks/useProductReviews.js` on all 6 product pages (incl. Discovery Set). Reviews are visible on the page (not in a closed accordion).
- Product JSON-LD gets `aggregateRating`/`review` ONLY when real reviews exist; the prerender bakes the latest reviews into the HTML at build time.
- New reviews appear immediately in the browser; the prerendered HTML/schema refreshes on the next deploy.
