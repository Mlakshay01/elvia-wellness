/* =========================================================================
   DUSSEHRA SIGNATURE OFFER — server side (source of truth for the charge)
   KEEP IN SYNC with frontend/src/config/dussehraOffer.js.

   Signature 100 ml perfumes only. Halloween Edition, Discovery Set, balms and
   30 ml variants are NOT eligible and are never discounted here.
   Default sale day: Sun 18 Oct 2026, 00:00–24:00 IST.
========================================================================= */

const DUSSEHRA_OFFER = {
  enabled: true,
  name: "Dussehra Signature Offer",
  start: "2026-10-19T00:00:00+05:30",
  end: "2026-10-20T00:00:00+05:30",
  eligibleProductIds: ["the-noir-men", "perfume-veil-unisex", "perfume-soie-femme"],
  tiers: [
    { units: 1, percent: 10 },
    { units: 2, percent: 15 },
    { units: 3, percent: 25 },
  ],
};

function isDussehraOfferActive(now = Date.now()) {
  if (!DUSSEHRA_OFFER.enabled) return false;
  const s = Date.parse(DUSSEHRA_OFFER.start);
  const e = Date.parse(DUSSEHRA_OFFER.end);
  if (Number.isNaN(s) || Number.isNaN(e)) return false;
  return now >= s && now < e;
}

function tierPercentFor(units) {
  let pct = 0;
  for (const t of DUSSEHRA_OFFER.tiers) if (units >= t.units) pct = t.percent;
  return pct;
}

/** items: validated items [{ productId, price (from DB), quantity }] */
function computeDussehraOffer(items = [], now = Date.now()) {
  if (!isDussehraOfferActive(now)) return { active: false, units: 0, percent: 0, discount: 0 };

  let units = 0;
  let eligibleSubtotal = 0;
  for (const it of items) {
    if (!DUSSEHRA_OFFER.eligibleProductIds.includes(it.productId)) continue;
    const q = Number(it.quantity) || 0;
    units += q;
    eligibleSubtotal += (Number(it.price) || 0) * q;
  }
  const percent = tierPercentFor(units);
  const discount = Math.round((eligibleSubtotal * percent) / 100);
  return { active: true, units, percent, discount };
}

module.exports = { DUSSEHRA_OFFER, isDussehraOfferActive, computeDussehraOffer };
