/* =========================================================================
   BOOT GATE — keeps the loading screen up until the page is REALLY ready
   -------------------------------------------------------------------------
   The splash used to run on a fixed timer, so on a slow connection it left
   before the hero video / bottle photos had arrived and the page "popped"
   in underneath it. Now a loader asks this module when it may leave:

     ready  =  minimum display time has passed
           AND web fonts are loaded
           AND every element marked  data-boot-wait  is ready:
                 <video>  first frame decoded (readyState >= 2) — or it errored
                 <img>    finished loading (or failed)
     …or the hard maximum (maxMs) is reached, so it can NEVER hang
     (iOS Low-Power Mode, a missing file, a stalled network…).

   Elements marked data-boot-wait are found by polling the DOM, so any page can
   opt in just by adding the attribute — no wiring needed.

   Also here: the shared "should we show a loader on this page load at all?"
   rules (bots, private/app routes) used by BOTH loaders, and the helper that
   removes the static cover painted by index.html.
========================================================================= */

const isBrowser = typeof window !== "undefined";

// Keep in sync with the inline script in index.html (the pre-JS cover uses the same rules).
const BOT = /bot|crawl|spider|slurp|lighthouse|pagespeed|headless/i;
const PRIVATE = /^\/(admin|cart|checkout|account|addresses|my-orders|previous-orders|order|order-success|success|support|verify)(\/|$)/;

/** false for crawlers, audits, internal navigations and private/app routes. */
export function bootAllowed() {
  if (!isBrowser) return false;
  if (BOT.test(navigator.userAgent)) return false;
  if (PRIVATE.test(window.location.pathname)) return false;
  try {
    if (sessionStorage.getItem("internalNav")) return false;
  } catch {
    /* storage blocked: carry on */
  }
  return true;
}

/** Removes the static cover that index.html paints before any JavaScript runs. */
export function removeBootCover() {
  if (isBrowser) document.documentElement.classList.remove("boot");
}

/* Connections where a decorative video should NOT hold the page hostage. */
function saveDataMode() {
  const c = navigator.connection;
  return !!c && (c.saveData || /^(slow-2g|2g)$/.test(c.effectiveType || ""));
}

function mediaReady() {
  const lite = saveDataMode();
  for (const el of document.querySelectorAll("[data-boot-wait]")) {
    if (getComputedStyle(el).display === "none") continue; // e.g. hidden by reduced-motion CSS
    if (el.tagName === "VIDEO") {
      if (lite || el.error || el.networkState === 3 /* NETWORK_NO_SOURCE */) continue;
      if (el.readyState < 2) return false; // first frame not available yet
    } else if (el.tagName === "IMG") {
      if (!el.complete) return false; // `complete` is also true when the image failed
    }
  }
  return true;
}

/**
 * Resolves when the page is ready (or maxMs is hit). Returns
 * { promise, expedite(), cancel() }:
 *   expedite() — drop the minimum time (used by tap-to-skip) but STILL wait for readiness
 *   cancel()   — stop polling (component unmounted)
 * The outcome is also written to <html data-boot="ready|timeout"> and data-boot-ms for debugging.
 */
export function waitForPageReady({ minMs = 0, maxMs = 7000 } = {}) {
  const start = performance.now();
  let fontsDone = false;
  let expedited = false;
  let cancelled = false;
  let timer = 0;
  let resolveFn;

  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(() => (fontsDone = true), () => (fontsDone = true));
  } else {
    fontsDone = true;
  }

  const finish = (reason) => {
    document.documentElement.dataset.boot = reason;
    document.documentElement.dataset.bootMs = String(Math.round(performance.now() - start));
    resolveFn(reason);
  };

  const tick = () => {
    if (cancelled) return;
    const t = performance.now() - start;
    if (t >= maxMs) return finish("timeout");
    if ((expedited || t >= minMs) && fontsDone && mediaReady()) return finish("ready");
    timer = setTimeout(tick, 60);
  };

  const promise = new Promise((res) => {
    resolveFn = res;
    tick();
  });

  return {
    promise,
    expedite() {
      expedited = true;
    },
    cancel() {
      cancelled = true;
      clearTimeout(timer);
    },
  };
}
