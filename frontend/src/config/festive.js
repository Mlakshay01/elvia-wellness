/* =========================================================================
   FESTIVE OFFER — "A Festival of New Beginnings" (Dussehra, 24 hours)
   -------------------------------------------------------------------------
   Storefront copy of backend/config/festiveOffer.js (the SERVER decides what
   is actually charged — this file only drives what the site SHOWS). Keep the
   two in sync: backend/tests/festive-offer.test.js fails if they drift.

   Plain ES (no imports / import.meta / JSX) so it can be imported by Node tests.

   Applies ONLY to the signature perfumes below. The Halloween Edition
   (NOCTURNE / AZUR) keeps its own separate launch offer in config/halloween.js.
========================================================================= */

export const FESTIVE = {
  enabled: true,
  id: "dussehra-2026",
  name: "Dussehra Festival Offer",
  // Dussehra (Vijayadashami) 2026 = Tuesday 20 October. 24 hours, India time.
  startsAt: "2026-10-19T00:00:00+05:30",
  endsAt: "2026-10-21T00:00:00+05:30",
  eligibleProductIds: ["the-noir-men", "perfume-veil-unisex", "perfume-soie-femme"],
  couponPolicy: "best-of", // "best-of" | "stack"
  tiers: [
    { min: 1, percent: 10, name: "DISCOVER" },
    { min: 2, percent: 15, name: "EXPLORE" },
    { min: 3, percent: 25, name: "BEST VALUE" },
  ],
};

/* Display-only copy (not mirrored on the server). */
export const FESTIVE_COPY = {
  eyebrow: "A Festival of New Beginnings",
  title: "This Dussehra, discover your signature.",
  intro: "For 24 hours only, experience KAEORN’s signature fragrances with an exclusive festive offer.",
  tiers: [
    { tag: "TIER 1 · DISCOVER", buy: "Buy 1 perfume" },
    { tag: "TIER 2 · EXPLORE", buy: "Buy 2 perfumes" },
    { tag: "TIER 3 · BEST VALUE", buy: "Buy 3 perfumes", note: "Maximum savings." },
  ],
  cta: "Choose your signature",
  terms:
    "Valid on THÉ NOIR, SOIE FEMME and VEIL only, any mix. Not valid on the Halloween Edition, which has its own offer. Cannot be combined with coupon codes: the larger saving applies. Discount is applied automatically at checkout.",
};

const roundMoney = (n) => Math.round(Number(n) * 100) / 100;

/** "off" | "upcoming" | "live" | "ended" */
export function festivePhase(now = Date.now()) {
  if (!FESTIVE.enabled) return "off";
  const start = Date.parse(FESTIVE.startsAt);
  const end = Date.parse(FESTIVE.endsAt);
  if (Number.isNaN(start) || Number.isNaN(end)) return "off";
  if (now < start) return "upcoming";
  if (now >= end) return "ended";
  return "live";
}

/** The best tier reached with `qty` eligible perfumes (null when qty is 0). */
export function tierFor(qty) {
  let hit = null;
  for (const t of FESTIVE.tiers) if (qty >= t.min) hit = t;
  return hit;
}

/** The next tier above `qty` (to nudge "add 1 more…"), or null at the top. */
export function nextTierFor(qty) {
  return FESTIVE.tiers.find((t) => t.min > qty) || null;
}

/* items: [{ productId | id, price, quantity }]  (identical rules to the server) */
export function computeFestiveDiscount(items, now = Date.now()) {
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

/* Combine with an already-validated coupon: { code, percent, amount } (identical to the server). */
export function resolveDiscounts({ originalAmount, festive, coupon }) {
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
    couponAmount = C; // tie (whole-rupee comparison) → coupon keeps the partner attribution
    couponApplied = true;
  } else {
    festiveAmount = F; // festive is larger: coupon not applied
  }

  const discountAmount = roundMoney(Math.min(festiveAmount + couponAmount, originalAmount));
  return { discountAmount, festiveAmount, couponAmount, couponApplied };
}

/* ── storefront helpers (display only) ─────────────────────────────────── */

/** What each tier costs for `unitPrice` (e.g. 1399): total, saving, and the rounded figures shown on the cards. */
export function tierPreview(unitPrice) {
  return FESTIVE.tiers.map((t) => {
    const original = unitPrice * t.min;
    const save = Math.round((original * t.percent) / 100);
    return { ...t, original, total: original - save, save };
  });
}

/** ₹ amount in Indian grouping: 2378 → "₹2,378". */
export const inr = (n) => `₹${Number(n).toLocaleString("en-IN")}`;

/**
 * Full cart breakdown the cart/payment pages display.
 *   items: cart items; coupon: { discountType, discountValue, code } | null
 * (The server recomputes all of this from database prices — this is display only.)
 */
export function computeBreakdown(items, coupon, now = Date.now()) {
  const originalAmount = (items || []).reduce((s, i) => s + Number(i.price || 0) * Number(i.quantity || 0), 0);
  const festive = computeFestiveDiscount(items, now);

  let couponAmount = 0;
  let couponPercent = 0;
  if (coupon) {
    if (coupon.discountType === "fixed") {
      couponAmount = Math.min(Number(coupon.discountValue || 0), originalAmount);
    } else {
      couponPercent = Math.max(0, Math.min(100, Number(coupon.discountValue || 0)));
      couponAmount = Math.round((originalAmount * couponPercent) / 100);
    }
  }
  const resolved = resolveDiscounts({
    originalAmount,
    festive,
    coupon: coupon ? { code: coupon.code || "COUPON", percent: couponPercent, amount: couponAmount } : null,
  });

  return {
    originalAmount,
    festive, // { active, percent, tier, eligibleQuantity, … }
    festiveAmount: resolved.festiveAmount,
    couponAmount: resolved.couponAmount,
    couponApplied: resolved.couponApplied, // false = a coupon was entered but the festive offer is larger
    discount: resolved.discountAmount,
    finalTotal: Math.max(originalAmount - resolved.discountAmount, 0),
  };
}
