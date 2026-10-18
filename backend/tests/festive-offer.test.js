/* Pure-rule tests for config/festiveOffer.js + a drift check against the storefront copy.
   Run:  npm test        (from /backend) */
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const { pathToFileURL } = require("node:url");
const S = require("../config/festiveOffer");

const LIVE = Date.parse("2026-10-20T12:00:00+05:30");
const item = (productId, quantity, price = 1399) => ({ productId, price, quantity });
const NOIR = "the-noir-men";
const VEIL = "perfume-veil-unisex";
const SOIE = "perfume-soie-femme";

test("phases: upcoming → live → ended (24 hours, India time)", () => {
  assert.equal(S.festivePhase(Date.parse("2026-10-19T23:59:59+05:30")), "upcoming");
  assert.equal(S.festivePhase(Date.parse("2026-10-20T00:00:00+05:30")), "live");
  assert.equal(S.festivePhase(Date.parse("2026-10-20T23:59:59+05:30")), "live");
  assert.equal(S.festivePhase(Date.parse("2026-10-21T00:00:00+05:30")), "ended");
});

test("advertised figures: ₹1,259/140, ₹2,378/420, ₹3,148/1,049", () => {
  for (const [qty, total, save, pct] of [[1, 1259, 140, 10], [2, 2378, 420, 15], [3, 3148, 1049, 25]]) {
    const r = S.computeFestiveDiscount([item(NOIR, qty)], LIVE);
    assert.equal(r.percent, pct);
    assert.equal(r.discountAmount, save);
    assert.equal(1399 * qty - r.discountAmount, total);
  }
});

test("tier counts any mix of signature perfumes; 4+ stays at the top tier", () => {
  assert.equal(S.computeFestiveDiscount([item(NOIR, 1), item(VEIL, 1)], LIVE).percent, 15);
  assert.equal(S.computeFestiveDiscount([item(NOIR, 1), item(VEIL, 1), item(SOIE, 1)], LIVE).percent, 25);
  assert.equal(S.computeFestiveDiscount([item(NOIR, 4)], LIVE).percent, 25);
});

test("Halloween Edition, NOX, VELION, Discovery Set and 30 ml variants are NOT eligible", () => {
  for (const id of ["perfume-nocturne", "perfume-azur", "nox", "velion", "discovery-set", "the-noir-men-30ml"]) {
    assert.equal(S.computeFestiveDiscount([item(id, 3, 799)], LIVE).discountAmount, 0, id);
  }
});

test("mixed cart: only the signature perfumes are discounted and counted", () => {
  const r = S.computeFestiveDiscount([item(NOIR, 2), item("perfume-nocturne", 5, 799)], LIVE);
  assert.equal(r.eligibleQuantity, 2); // Halloween perfumes do NOT push the tier up
  assert.equal(r.percent, 15);
  assert.equal(r.discountAmount, 420);
});

test("no discount before the start or after the end", () => {
  assert.equal(S.computeFestiveDiscount([item(NOIR, 3)], Date.parse("2026-10-19T12:00:00+05:30")).discountAmount, 0);
  assert.equal(S.computeFestiveDiscount([item(NOIR, 3)], Date.parse("2026-10-21T00:00:00+05:30")).discountAmount, 0);
});

test("bad input is ignored, never throws or discounts", () => {
  const r = S.computeFestiveDiscount([item(NOIR, 0), item(NOIR, 1.5), { productId: NOIR, price: -5, quantity: 1 }, null && 1].filter(Boolean), LIVE);
  assert.equal(r.discountAmount, 0);
});

test("coupon policy best-of: larger wins, tie → coupon, loser is not applied", () => {
  const original = 4197;
  const festive = S.computeFestiveDiscount([item(NOIR, 3)], LIVE); // 1049
  // 10% partner code (419.70) < festive 1049 → festive wins, coupon dropped
  let r = S.resolveDiscounts({ originalAmount: original, festive, coupon: { code: "AMB10", percent: 10, amount: 419.7 } });
  assert.deepEqual([r.discountAmount, r.couponApplied], [1049, false]);
  // 30% partner code (1259.10) > festive → coupon wins, attributed
  r = S.resolveDiscounts({ originalAmount: original, festive, coupon: { code: "BIG30", percent: 30, amount: 1259.1 } });
  assert.deepEqual([r.discountAmount, r.couponApplied], [1259.1, true]);
  // one perfume: 10% code = ₹139.90 vs festive ₹140 → TIE (whole rupees) → coupon keeps attribution
  const f1 = S.computeFestiveDiscount([item(NOIR, 1)], LIVE);
  r = S.resolveDiscounts({ originalAmount: 1399, festive: f1, coupon: { code: "AMB10", percent: 10, amount: 139.9 } });
  assert.deepEqual([r.discountAmount, r.couponApplied], [139.9, true]);
});

test("coupon policy stack: coupon applies on the amount left after the festive discount", () => {
  const prev = S.FESTIVE.couponPolicy;
  S.FESTIVE.couponPolicy = "stack";
  try {
    const festive = S.computeFestiveDiscount([item(NOIR, 3)], LIVE); // 1049
    const r = S.resolveDiscounts({ originalAmount: 4197, festive, coupon: { code: "AMB10", percent: 10, amount: 419.7 } });
    assert.equal(r.festiveAmount, 1049);
    assert.equal(r.couponAmount, 314.8); // 10% of (4197 − 1049)
    assert.equal(r.couponApplied, true);
  } finally {
    S.FESTIVE.couponPolicy = prev;
  }
});

test("without the festive offer a coupon behaves exactly as before", () => {
  const r = S.resolveDiscounts({ originalAmount: 1399, festive: S.computeFestiveDiscount([item(NOIR, 1)], Date.parse("2026-11-01T00:00:00+05:30")), coupon: { code: "AMB10", percent: 10, amount: 139.9 } });
  assert.deepEqual([r.discountAmount, r.couponApplied, r.festiveAmount], [139.9, true, 0]);
});

test("DRIFT CHECK: server rules === storefront rules (frontend/src/config/festive.js)", async (t) => {
  const file = path.resolve(__dirname, "../../frontend/src/config/festive.js");
  if (!fs.existsSync(file)) return t.skip("storefront not present next to the backend");
  const F = await import(pathToFileURL(file).href);
  assert.deepEqual(F.FESTIVE, S.FESTIVE, "FESTIVE config differs between frontend and backend");
  const ids = [NOIR, VEIL, SOIE, "perfume-nocturne", "nox"];
  const times = [Date.parse("2026-10-19T12:00:00+05:30"), LIVE, Date.parse("2026-10-21T01:00:00+05:30")];
  let n = 0;
  for (const now of times) {
    assert.equal(F.festivePhase(now), S.festivePhase(now));
    for (let a = 0; a < 4; a++) for (let b = 0; b < 4; b++) for (let c = 0; c < 3; c++) {
      const cart = [item(ids[0], a), item(ids[1], b), item("perfume-nocturne", c, 799), item(ids[2], c)].filter((i) => i.quantity > 0);
      assert.deepEqual(F.computeFestiveDiscount(cart, now), S.computeFestiveDiscount(cart, now));
      const festive = S.computeFestiveDiscount(cart, now);
      const orig = cart.reduce((s, i) => s + i.price * i.quantity, 0);
      for (const coupon of [null, { code: "X", percent: 10, amount: orig * 0.1 }, { code: "Y", percent: 30, amount: orig * 0.3 }]) {
        assert.deepEqual(F.resolveDiscounts({ originalAmount: orig, festive, coupon }), S.resolveDiscounts({ originalAmount: orig, festive, coupon }));
        n++;
      }
    }
  }
  assert.ok(n > 100);
});
