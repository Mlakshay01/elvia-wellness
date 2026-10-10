# Halloween Edition — owner runbook

## One place to change things
`frontend/src/config/halloween.js`: on/off switch, end date, countdown date, product names, taglines, prices, notes, photo URLs, audio file paths. Routes, cart, schema and the prerender/sitemap all read from it.

## Before launch: owner TODO
1. **Price.** ₹1399 is a **placeholder**. Set it in **both** `HALLOWEEN_PRICE_100ML` (config) **and** `PRICE_100ML` in `backend/seedHalloweenPerfumes.js`.
2. **Run the seed** (the server charges the DB price, so the products can't be bought until you do): `cd backend && node seedHalloweenPerfumes.js`. Safe to re-run.
3. **Scent notes.** The three notes per product (`notes` in the config) are **mood words, not ingredient claims** (NOCTURNE: Dark berry / Deep red / After dark; AZUR: Cool blue / Oud / Midnight). Replace with the real notes.
4. **Photos:** see `PHOTO_SHOTLIST.md`. **Audio:** listen to the files and see `AUDIO_CREDITS.md`.
5. Confirm names/taglines and the slugs `/perfume/nocturne`, `/perfume/azur`. If you change a slug or id, change it in config **and** the seed (and `public/sitemap.xml`).

## Ending Halloween
- After `endDate` (default **2 Nov 2026, 00:00 IST**) the theme, intro, audio, banner/nav link, countdown and mute toggle switch off by themselves for anyone running the site in a browser (even a tab left open).
- **Important:** pages are pre-rendered at build time, so crawlers and no-JS visitors keep seeing the Halloween home page until the next deploy. **Trigger a redeploy on or just after 2 Nov** (for example a scheduled Vercel deploy hook), or just set `enabled: false` and deploy.
- The two perfumes stay live as normal products (same pages, no particles/mist/sound/seasonal wording) and join the home collection grid ("Five moods").
- To switch off immediately: `enabled: false`, deploy.

## Things worth knowing
- **Pre-existing, not changed:** `backend/seedDiscoverySet.js` charges **₹1200** while the storefront shows **₹1500** for the Discovery Set. Worth checking which is right.
- **Pre-existing, not changed:** the desktop navbar already overlaps ("Coming Soon" touching "Instagram") below ~1280 px wide. The Halloween link would have made 1440 px laptops overlap too, so spacing is tightened (and the label shortened to "Halloween" under 1360 px) while the theme is on.
- 30 ml: the existing 30 ml option is switched off in `getSizeOptions`, so only 100 ml was added.
- The pinned notes section needs `overflow-x: clip` (Chrome 90+, Safari 16+); on older browsers the notes simply scroll normally.
- Reduced motion: intro is skipped (no flash), and float, mist, particles, parallax and the pinned scroll are all switched off.
