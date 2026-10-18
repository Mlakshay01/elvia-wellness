/* =========================================================================
   FESTIVE OFFER — "A Festival of New Beginnings" (Dussehra, 24 hours)
   -------------------------------------------------------------------------
   SERVER SOURCE OF TRUTH for the tiered signature-fragrance discount.
   The checkout (routes/paymentRoutes.js → /create-order) calls this with the
   products it loaded FROM MONGODB, so the charged amount can never be set by
   the browser. The storefront shows the same offer using
   frontend/src/config/festive.js — KEEP THE TWO FILES IN SYNC
   (tests/festive-offer.test.js fails if they drift).

   WHAT IT DOES
   • Applies only to the signature perfumes listed in eligibleProductIds
     (THÉ NOIR, SOIE FEMME, VEIL). The Halloween Edition (NOCTURNE / AZUR),
     NOX, VELION and the Discovery Set are NOT eligible and keep their own
     prices/discounts.
   • The tier is chosen by how many eligible perfumes are in the cart
     (any mix): 1 → 10 %, 2 → 15 %, 3 or more → 25 %.
   • The percentage applies to the eligible items' subtotal, rounded to a
     whole rupee (so ₹1,399 → ₹1,259 exactly as advertised).
   • Only while the server clock is inside [startsAt, endsAt).

   COUPON CODES (ambassador/partner codes)
   • couponPolicy "best-of" (default): the customer gets whichever is larger —
     the festive offer OR their coupon — never both. If the coupon wins it is
     attributed to the partner as usual; if the festive offer wins the coupon
     is NOT applied or attributed (no commission is paid on that order).
     A tie goes to the coupon.
   • couponPolicy "stack": the coupon is applied on top, on the amount left
     after the festive discount.
========================================================================= */

const FESTIVE = {
  enabled: true,
  id: "dussehra-2026",
  name: "Dussehra Festival Offer",
  // Dussehra (Vijayadashami) 2026 = Tuesday 20 October. 24 hours, India time.
  startsAt: "2026-10-19T00:00:00+05:30",
  endsAt: "2026-10-20T00:00:00+05:30",
  eligibleProductIds: ["the-noir-men", "perfume-veil-unisex", "perfume-soie-femme"],
  couponPolicy: "best-of", // "best-of" | "stack"
  tiers: [
    { min: 1, percent: 10, name: "DISCOVER" },
    { min: 2, percent: 15, name: "EXPLORE" },
    { min: 3, percent: 25, name: "BEST VALUE" },
  ],
};

const roundMoney = (n) => Math.round(Number(n) * 100) / 100;

/** "off" | "upcoming" | "live" | "ended" */
function festivePhase(now = Date.now()) {
  if (!FESTIVE.enabled) return "off";
  const start = Date.parse(FESTIVE.startsAt);
  const end = Date.parse(FESTIVE.endsAt);
  if (Number.isNaN(start) || Number.isNaN(end)) return "off";
  if (now < start) return "upcoming";
  if (now >= end) return "ended";
  return "live";
}

/** The best tier reached with `qty` eligible perfumes (null when qty is 0). */
function tierFor(qty) {
  let hit = null;
  for (const t of FESTIVE.tiers) if (qty >= t.min) hit = t;
  return hit;
}

/**
 * items: [{ productId | id, price, quantity }] — price MUST be the database price.
 * Returns { active, percent, tier, eligibleQuantity, eligibleSubtotal, discountAmount }.
 */
function computeFestiveDiscount(items, now = Date.now()) {
  const none = { active: false, percent: 0, tier: null, eligibleQuantity: 0, eligibleSubtotal: 0, discountAmount: 0 };
  if (festivePhase(now) !== "live") return none;

  let qty = 0;
  let subtotal = 0;
  for (const it of items || []) {
    const id = it.productId || it.id;
    if (!FESTIVE.eligibleProductIds.includes(id)) continue; // Halloween etc. never qualify
    const q = Number(it.quantity);
    const p = Number(it.price);
    if (!Number.isInteger(q) || q < 1 || !Number.isFinite(p) || p <= 0) continue;
    qty += q;
    subtotal += p * q;
  }
  const tier = tierFor(qty);
  if (!tier) return { ...none, eligibleQuantity: qty, eligibleSubtotal: roundMoney(subtotal) };

  return {
    active: true,
    percent: tier.percent,
    tier: tier.name,
    eligibleQuantity: qty,
    eligibleSubtotal: roundMoney(subtotal),
    discountAmount: Math.round((subtotal * tier.percent) / 100), // whole rupees
  };
}

/**
 * Combine the festive discount with an (already validated) coupon.
 *   festive: result of computeFestiveDiscount
 *   coupon:  { code, percent, amount } — amount = what the coupon alone would take off the full cart
 * Returns { discountAmount, festiveAmount, couponAmount, couponApplied }.
 */
function resolveDiscounts({ originalAmount, festive, coupon }) {
  const F = festive && festive.active ? festive.discountAmount : 0;
  const hasCoupon = !!(coupon && coupon.code);
  const C = hasCoupon ? Math.max(0, Number(coupon.amount) || 0) : 0;
  let festiveAmount = 0;
  let couponAmount = 0;
  let couponApplied = false;

  if (F <= 0) {
    couponAmount = C;
    couponApplied = hasCoupon;
  } else if (!hasCoupon) {
    festiveAmount = F;
  } else if (FESTIVE.couponPolicy === "stack") {
    festiveAmount = F;
    couponAmount = roundMoney(Math.max(0, originalAmount - F) * (Number(coupon.percent || 0) / 100));
    couponApplied = true;
  } else if (Math.round(C) >= F) {
    // Compared in whole rupees (the festive discount is whole-rupee, a coupon may have paise), so an
    // equal-percentage code (₹139.90 vs ₹140) is a TIE, which goes to the coupon — the partner keeps
    // their attribution at no extra cost to the customer.
    couponAmount = C;
    couponApplied = true;
  } else {
    festiveAmount = F; // festive is larger: coupon not applied, not attributed
  }

  const discountAmount = roundMoney(Math.min(festiveAmount + couponAmount, originalAmount));
  return { discountAmount, festiveAmount, couponAmount, couponApplied };
}

module.exports = { FESTIVE, festivePhase, tierFor, computeFestiveDiscount, resolveDiscounts };
