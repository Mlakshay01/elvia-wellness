/* =========================================================================
   DUSSEHRA SIGNATURE OFFER — single source of truth (storefront side)
   -------------------------------------------------------------------------
   One-day, 3-tier offer on the SIGNATURE perfumes only.
   NOT valid on: Halloween Edition (NOCTURNE / AZUR), Discovery Set, balms,
   30 ml variants. Those keep their own pricing untouched.

   KEEP IN SYNC with backend/config/dussehraOffer.js — the server recalculates
   the discount from this same rule and is the only amount Razorpay charges.

   Plain ES (no imports) so it can also be used by the prerender script.

   TO CHANGE THE DAY: edit `start` and `end` here AND in the backend file.
   Dussehra 2026 is Tue 20 Oct. Default sale day: Sun 18 Oct (IST).
========================================================================= */

export const DUSSEHRA_OFFER = {
  /** Master switch. false = offer is off everywhere, regardless of date. */
  enabled: true,

  name: "Dussehra Signature Offer",

  /** 24 hours, India time. `end` is exclusive (midnight at the end of the day). */
  start: "2026-10-19T00:00:00+05:30",
  end: "2026-10-20T00:00:00+05:30",

  /** Canonical product ids (100 ml signature scents only). */
  eligibleProductIds: ["the-noir-men", "perfume-veil-unisex", "perfume-soie-femme"],

  /** Units of eligible perfumes in the cart -> % off those units. 3+ gets the top tier. */
  tiers: [
    { units: 1, percent: 10, tag: "DISCOVER", title: "Buy 1 perfume" },
    { units: 2, percent: 15, tag: "EXPLORE", title: "Buy 2 perfumes" },
    { units: 3, percent: 25, tag: "BEST VALUE", title: "Buy 3 perfumes" },
  ],
};

export function isDussehraOfferActive(now = Date.now()) {
  if (!DUSSEHRA_OFFER.enabled) return false;
  const s = Date.parse(DUSSEHRA_OFFER.start);
  const e = Date.parse(DUSSEHRA_OFFER.end);
  if (Number.isNaN(s) || Number.isNaN(e)) return false;
  return now >= s && now < e;
}

export function isOfferEligible(productId) {
  return DUSSEHRA_OFFER.eligibleProductIds.includes(productId);
}

/** % for a given number of eligible units (0 when none). */
export function tierPercentFor(units) {
  let pct = 0;
  for (const t of DUSSEHRA_OFFER.tiers) if (units >= t.units) pct = t.percent;
  return pct;
}

/**
 * items: [{ id | productId, price, quantity }]
 * Returns { active, units, percent, discount, eligibleSubtotal, nextTier }
 * nextTier = { addUnits, percent } or null when already on the top tier.
 */
export function computeDussehraOffer(items = [], now = Date.now()) {
  const none = { active: false, units: 0, percent: 0, discount: 0, eligibleSubtotal: 0, nextTier: null };
  if (!isDussehraOfferActive(now)) return none;

  let units = 0;
  let eligibleSubtotal = 0;
  for (const it of items) {
    const id = it.productId || it.id;
    if (!isOfferEligible(id)) continue;
    const q = Number(it.quantity) || 0;
    units += q;
    eligibleSubtotal += (Number(it.price) || 0) * q;
  }

  const percent = tierPercentFor(units);
  const discount = Math.round((eligibleSubtotal * percent) / 100);
  const next = DUSSEHRA_OFFER.tiers.find((t) => t.units > units);
  return {
    active: true,
    units,
    percent,
    discount,
    eligibleSubtotal,
    nextTier: next ? { addUnits: next.units - units, percent: next.percent } : null,
  };
}

/**
 * Combine the festive offer with a (partner) coupon discount.
 * They do NOT stack: the customer gets whichever saves more.
 * Returns { discount, source: "offer" | "coupon" | null }
 */
export function bestDiscount(offerDiscount, couponDiscount) {
  const o = Math.max(0, Number(offerDiscount) || 0);
  const c = Math.max(0, Number(couponDiscount) || 0);
  if (o > 0 && o >= c) return { discount: o, source: "offer" };
  if (c > 0) return { discount: c, source: "coupon" };
  return { discount: 0, source: null };
}
