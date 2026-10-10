/* =========================================================================
   HALLOWEEN EDITION — single source of truth
   -------------------------------------------------------------------------
   Everything the owner may want to change lives in this file:
   on/off switch, end date, product names, taglines, prices, notes, photos
   and sound files.

   IMPORTANT: this file is plain ES (no imports, no import.meta, no JSX) so
   that scripts/prerender.mjs can import it directly in Node and the routes,
   sitemap and storefront can never drift apart.
========================================================================= */

export const HALLOWEEN = {
  /** Master switch. false = the whole site is normal, regardless of date. */
  enabled: true,

  /**
   * The theme, intro, audio and banner switch themselves OFF at this moment.
   * Default: 2 Nov 2026, 00:00 India time. (ISO string with an explicit offset.)
   */
  endDate: "2026-11-02T00:00:00+05:30",

  /** Countdown on the home page counts down to the end of 31 Oct (India time). */
  countdownTo: "2026-10-31T23:59:59+05:30",

  /** Approximate intro length in ms (tap anywhere to skip). */
  introMs: 2500,

  /** Ambient bed volume (0–1). Brief asks for about 20 %. */
  ambientVolume: 0.2,
};

/** true while the Halloween theme should be shown (flag on AND before end date). */
export function isHalloweenActive(now = Date.now()) {
  if (!HALLOWEEN.enabled) return false;
  const end = Date.parse(HALLOWEEN.endDate);
  return Number.isNaN(end) ? true : now < end;
}

/* ── Site-wide Halloween copy ─────────────────────────────────────────── */
export const HALLOWEEN_COPY = {
  navLabel: "Halloween Edition",
  marqueeLabel: "THE HALLOWEEN EDITION",
  heroEyebrow: "KAEORN · LIMITED SEASON",
  heroTitle: "The Halloween Edition",
  heroSub:
    "Two fragrances for the longest night of the year. One born after dark, one blue beyond midnight.",
  heroCta: "Shop the Collection",
  collectionEyebrow: "THE HALLOWEEN EDITION",
  collectionTitle: "Two scents.",
  collectionTitleEm: "One long night.",
  collectionIntro:
    "A limited seasonal pair. Quiet, dark and made to linger well past midnight.",
};

/* ── Audio files (put the real files in /public/audio — see docs/AUDIO_CREDITS.md) ── */
export const HALLOWEEN_AUDIO = {
  ambient: "/audio/halloween-ambient.mp3", // home page bed (loops)
  thunder: "/audio/halloween-thunder.mp3", // first interaction during intro
  bell: "/audio/halloween-bell.mp3", // add to cart
  pages: {
    nocturne: "/audio/ambient-nocturne.mp3", // per-product beds (loop)
    azur: "/audio/ambient-azur.mp3",
  },
};

/* ── The two perfumes ─────────────────────────────────────────────────────
   Names and taglines: edit here, they update everywhere.
   Routes follow the existing "/perfume/<descriptive-slug>" pattern.

   Product ids MUST match backend/seedHalloweenPerfumes.js (the server
   charges the price stored in MongoDB, not this one).

   PHOTOS: replace the `images` URLs with transparent-PNG Cloudinary URLs
   when the real shoot is done (see docs/PHOTO_SHOTLIST.md). Until then they
   point at generated SVG placeholders in /public/halloween.
========================================================================== */

/** TODO(owner): confirm. Placeholder = same as the existing 100 ml perfumes. */
export const HALLOWEEN_PRICE_100ML = 799;

export const HALLOWEEN_PRODUCTS = {
  nocturne: {
    key: "nocturne",
    id: "perfume-nocturne", // MongoDB productId
    route: "/perfume/nocturne",
    name: "NOCTURNE",
    tagline: "Born after dark",
    category: "EAU DE PARFUM",
    size: "30 ml",
    price: 799, // TODO(owner): confirm price
    mood: "Dark berry · Deep red",
    other: "azur",
    seoDescription:
      "NOCTURNE by KAEORN — a dark berry, deep red Eau de Parfum from the Halloween Edition. Born after dark. 100 ml, made in India.",
    story:
      "Born after dark. NOCTURNE is the deep red of the last candle in the room — dark berry, close to the skin, unhurried.",
    feel: "Slow, warm and a little dangerous. The scent of the hour when the house goes quiet.",
    // TODO(owner): confirm the real notes. These are mood words, not ingredient claims.
    notes: {
      top: { name: "Wild Berries, Bergamot, Plum", desc: "First impression" },
      heart: { name: "Rose Petals, Amber, Cinnamon", desc: "The warm centre" },
      base: { name: "Musk, Vanilla", desc: "What stays on skin" },
    },
    theme: {
      bgFrom: "#2b0510",
      bgMid: "#14040a",
      bgTo: "#050204",
      glow: "rgba(190, 18, 48, 0.55)",
      accent: "#c8213f",
      accentSoft: "rgba(200, 33, 63, 0.18)",
      text: "#f1e6df",
      particle: "ember", // ember | frost
      light: "spot", // spot = soft red spotlight under the bottle | moon = cold moon glow behind it
      floor: false, // true = subtle reflective floor
    },
    images: {
      front: "/halloween/nocturne-front.png", // transparent PNG: hero + pinned section
      threeQuarter: "/halloween/nocturne-three-quarter.png",
      detail: "/halloween/nocturne-detail.png",
      lifestyle: "/halloween/nocturne-lifestyle.png",
      flatlay: "/halloween/nocturne-flatlay.png",
    },
  },

  azur: {
    key: "azur",
    id: "perfume-azur", // MongoDB productId
    route: "/perfume/azur",
    name: "AZUR",
    tagline: "Blue beyond midnight",
    category: "EAU DE PARFUM",
    size: "30 ml",
    price: 799, // TODO(owner): confirm price
    mood: "Oud · Cool blue",
    other: "nocturne",
    seoDescription:
      "AZUR by KAEORN — a cool blue oud Eau de Parfum from the Halloween Edition. Blue beyond midnight. 100 ml, made in India.",
    story:
      "Blue beyond midnight. AZUR is oud seen through frost — cool, clear and strangely calm after the dark has settled.",
    feel: "Still, cold and luminous. Moonlight on glass.",
    // TODO(owner): confirm the real notes. These are mood words, not ingredient claims.
    notes: {
      top: { name: "Agarwood (oud), Black Pepper, Apple, Bergamot", desc: "First impression" },
      heart: { name: "Exotic Fruits, Saffron, Musk, Jasmine, Sage", desc: "The quiet centre" },
      base: { name: "Ambergris, Sandalwood, Guaiac Wood", desc: "What stays on skin" },
    },
    theme: {
      bgFrom: "#0b1a3a",
      bgMid: "#0a1530",
      bgTo: "#06080f",
      glow: "rgba(150, 205, 255, 0.5)",
      accent: "#9fd3ff",
      accentSoft: "rgba(159, 211, 255, 0.16)",
      text: "#e8f1fb",
      particle: "frost",
      light: "moon",
      floor: true,
    },
    images: {
      front: "/halloween/azur-front.png",
      threeQuarter: "/halloween/azur-three-quarter.png",
      detail: "/halloween/azur-detail.png",
      lifestyle: "/halloween/azur-lifestyle.png",
      flatlay: "/halloween/azur-flatlay.png",
    },
  },
};

export const HALLOWEEN_PRODUCT_LIST = Object.values(HALLOWEEN_PRODUCTS);
