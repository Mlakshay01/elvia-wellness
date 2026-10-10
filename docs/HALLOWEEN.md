# Halloween Edition — owner runbook

## One place to change things
`frontend/src/config/halloween.js`: on/off switch, end date, countdown date, product names, taglines, prices, notes, photo URLs, audio file paths. Routes, cart, schema and the prerender/sitemap all read from it.

## Before launch: owner TODO
1. **Price / launch offer.** MRP **₹1100** (struck through) and sale price **₹799**, labelled "Limited launch offer · Halloween special" (after the theme ends the label becomes just "Limited launch offer"). Set in `HALLOWEEN_MRP` / `HALLOWEEN_PRICE` in the config, **and** `PRICE` in `backend/seedHalloweenPerfumes.js` (the seed must match `HALLOWEEN_PRICE`: it is what the customer is actually charged; MRP is display-only).
2. **Run the seed** (the server charges the DB price, so the products can't be bought, or will be charged a stale price, until you do): `cd backend && node seedHalloweenPerfumes.js`. Safe to re-run; re-run it whenever the price changes.
3. **Scent notes.** Notes are in `notes` in the config. Please double-check them before launch.
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

## Limited launch offer: how to end it
The offer does **not** expire by itself, because the price actually charged lives in the database, and the page must never show a price different from what is charged. To end it: set `HALLOWEEN_PRICE = HALLOWEEN_MRP` (1100) in the config **and** `PRICE = 1100` in the seed, run the seed, redeploy. When price equals MRP, the strike-through, "% off" and offer label disappear on their own.

## Loading screen (what it does now)
- **No flash.** `index.html` paints a plain black cover (with a thin red line) *before any JavaScript runs*, so visitors never see the unfinished page flash before the loader. The loader removes it the moment it takes over.
- **It waits for the page to be really ready**: fonts, the hero video's first frame, and the hero bottle photos. Anything marked `data-boot-wait` is waited for (add that attribute to any other image/video that must be loaded before the reveal). If it's still waiting after its minimum time, the KAEORN wordmark breathes and a thin line sweeps.
- **It can never hang**: after 7 s it leaves anyway (slow network, iOS Low-Power Mode, a missing file). Failsafe: if the app fails to start at all, the cover removes itself after 20 s. On "data saver" / 2G connections the decorative video is not waited for.
- **Minimum times:** first visit in a session: the full ~2.5 s Halloween intro (fog, lightning, bats). Later loads in the same session, and reduced-motion: a quick wordmark-only screen (~0.5 s minimum). After Halloween, the original KAEORN splash (2.2 s minimum) with the same waiting.
- **Tap / Esc / Enter** skips the *animation* but still waits for the page, so a stray tap can't expose a half-loaded page.
- **Not shown** to crawlers/Lighthouse (they see the real page instantly), nor on `/admin`, `/cart`, `/checkout` and other private routes.
- Debugging: after load, `<html data-boot="ready|timeout" data-boot-ms="…">` records how it ended.
- **Video size matters for the wait.** Phones in portrait load `hero-mobile.mp4` (~0.96 MB), PCs/landscape load `hero-desktop.mp4` (~0.72 MB). The loader waits for the first frame of whichever applies, so keep them small (re-encode if you can get them well under 1 MB); they are the main thing that decides how long the loading screen stays up.
