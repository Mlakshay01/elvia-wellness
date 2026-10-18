/* Drives the REAL routes/paymentRoutes.js  POST /create-order  with MongoDB, Razorpay and auth stubbed,
   to prove what is actually charged. Run: npm test   (from /backend) */
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const http = require("node:http");
const express = require("express");

process.env.RAZORPAY_KEY_ID = "rzp_test_x";
process.env.RAZORPAY_KEY_SECRET = "secret";
process.env.RAZORPAY_WEBHOOK_SECRET = "whsec";

/* ── stubs ─────────────────────────────────────────────────────────────── */
const stub = (rel, exports) => {
  const file = require.resolve(path.resolve(__dirname, rel));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
};
const DB = {
  "the-noir-men": { productId: "the-noir-men", name: "THÉ NOIR", price: 1399, images: [] },
  "perfume-veil-unisex": { productId: "perfume-veil-unisex", name: "VEIL", price: 1399, images: [] },
  "perfume-soie-femme": { productId: "perfume-soie-femme", name: "SOIE FEMME", price: 1399, images: [] },
  "perfume-nocturne": { productId: "perfume-nocturne", name: "NOCTURNE", price: 799, images: [] },
  "perfume-azur": { productId: "perfume-azur", name: "AZUR", price: 799, images: [] },
  nox: { productId: "nox", name: "NOX", price: 499, images: [] },
};
const PARTNERS = {
  AMB10: { name: "Amb", couponCode: "AMB10", discountPercent: 10, commissionPercent: 10 },
  BIG30: { name: "Big", couponCode: "BIG30", discountPercent: 30, commissionPercent: 10 },
};
let created = []; // orders written
let rzpCalls = []; // what Razorpay was asked to charge

stub("../models/Product", { findOne: async ({ productId }) => DB[productId] || null });
stub("../models/PartnerUser", {
  findOne: ({ couponCode }) => ({ select: async () => PARTNERS[couponCode] || null }),
});
stub("../models/Order", {
  create: async (doc) => {
    const o = { _id: "ord_" + (created.length + 1), ...doc, payment: { ...doc.payment }, save: async () => {} };
    created.push(o);
    return o;
  },
});
stub("../middleware/userAuth", (req, _res, next) => {
  req.user = { _id: "user1", email: "t@test.com" };
  req.userEmail = "t@test.com";
  next();
});
const rzpFile = require.resolve("razorpay");
require.cache[rzpFile] = {
  id: rzpFile, filename: rzpFile, loaded: true,
  exports: class { constructor() { this.orders = { create: async (a) => { rzpCalls.push(a); return { id: "order_rzp1", amount: a.amount, currency: a.currency }; } }; } },
};

const router = require("../routes/paymentRoutes");
const app = express();
app.use(express.json());
app.use("/api/payment", router);

let server, base;
test.before(async () => {
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => server.close());

const REAL_NOW = Date.now;
const at = (iso) => { Date.now = () => Date.parse(iso); };
test.afterEach(() => { Date.now = REAL_NOW; created = []; rzpCalls = []; });

const ADDR = { fullName: "T", phone: "9999999999", street: "1 St", city: "Karnal", state: "HR", postalCode: "132001" };
async function checkout(cartItems, couponCode) {
  const res = await fetch(`${base}/api/payment/create-order`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ cartItems, address: ADDR, couponCode }),
  });
  return { status: res.status, body: await res.json() };
}
const L = "2026-10-20T12:00:00+05:30"; // live
const cart = (...pairs) => pairs.map(([id, quantity]) => ({ id, quantity, price: 1 /* client price must be ignored */ }));

test("LIVE: 1 / 2 / 3 signature perfumes are charged exactly ₹1,259 / ₹2,378 / ₹3,148", async () => {
  at(L);
  for (const [items, total, save] of [
    [cart(["the-noir-men", 1]), 1259, 140],
    [cart(["the-noir-men", 1], ["perfume-veil-unisex", 1]), 2378, 420],
    [cart(["the-noir-men", 1], ["perfume-veil-unisex", 1], ["perfume-soie-femme", 1]), 3148, 1049],
  ]) {
    const { status, body } = await checkout(items);
    assert.equal(status, 200, JSON.stringify(body));
    assert.equal(body.order.totalAmount, total);
    assert.equal(body.order.discountAmount, save);
    assert.equal(rzpCalls.at(-1).amount, total * 100, "Razorpay is asked for exactly the discounted paise");
    assert.equal(body.razorpay.amount, total * 100);
    assert.equal(body.order.festiveOffer.offerId, "dussehra-2026");
  }
});

test("LIVE: Halloween perfumes keep their own price and are never discounted by the tiers", async () => {
  at(L);
  const { body } = await checkout(cart(["perfume-nocturne", 2], ["perfume-azur", 1]));
  assert.equal(body.order.originalAmount, 2397);
  assert.equal(body.order.discountAmount, 0);
  assert.equal(body.order.totalAmount, 2397);
  assert.equal(body.order.festiveOffer, null);
});

test("LIVE: mixed cart — tier counts and discounts the signature perfumes only", async () => {
  at(L);
  const { body } = await checkout(cart(["the-noir-men", 2], ["perfume-nocturne", 1]));
  assert.equal(body.order.originalAmount, 2798 + 799);
  assert.equal(body.order.discountAmount, 420); // 15% of 2798 only
  assert.equal(body.order.totalAmount, 3177);
  assert.equal(body.order.festiveOffer.eligibleQuantity, 2);
});

test("BEFORE the start and AFTER the end the full price is charged", async () => {
  for (const when of ["2026-10-19T23:59:00+05:30", "2026-10-21T00:00:00+05:30", "2026-11-01T10:00:00+05:30"]) {
    at(when);
    const { body } = await checkout(cart(["the-noir-men", 3]));
    assert.equal(body.order.totalAmount, 4197, when);
    assert.equal(body.order.discountAmount, 0, when);
  }
});

test("a tampered client cannot change the price: client price / total fields are ignored", async () => {
  at(L);
  const res = await fetch(`${base}/api/payment/create-order`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ cartItems: [{ id: "the-noir-men", quantity: 1, price: 1 }], address: ADDR, totalAmount: 1, discountAmount: 9999, festivePercent: 100 }),
  });
  const body = await res.json();
  assert.equal(body.order.totalAmount, 1259);
});

test("COUPON best-of: a 10% partner code loses to a 25% tier and is NOT attributed", async () => {
  at(L);
  const { body } = await checkout(cart(["the-noir-men", 3]), "AMB10");
  assert.equal(body.order.totalAmount, 3148);
  assert.equal(body.order.couponCode, null);
  assert.ok(body.order.festiveOffer);
});

test("COUPON best-of: a bigger 30% partner code beats the 25% tier and IS attributed", async () => {
  at(L);
  const { body } = await checkout(cart(["the-noir-men", 3]), "BIG30");
  assert.equal(body.order.couponCode, "BIG30");
  assert.equal(body.order.discountAmount, 1259.1);
  assert.equal(body.order.totalAmount, 2937.9);
  assert.equal(body.order.festiveOffer, null);
});

test("COUPON tie: 10% code on ONE perfume (₹139.90 vs ₹140) keeps the partner attribution", async () => {
  at(L);
  const { body } = await checkout(cart(["the-noir-men", 1]), "AMB10");
  assert.equal(body.order.couponCode, "AMB10");
  assert.equal(body.order.festiveOffer, null);
});

test("outside the offer a coupon behaves exactly as it always did", async () => {
  at("2026-11-01T10:00:00+05:30");
  const { body } = await checkout(cart(["the-noir-men", 2]), "AMB10");
  assert.equal(body.order.couponCode, "AMB10");
  assert.equal(body.order.discountAmount, 279.8);
  assert.equal(body.order.totalAmount, 2518.2);
});

test("invalid coupon is still rejected, offer or not", async () => {
  at(L);
  const { status } = await checkout(cart(["the-noir-men", 1]), "NOPE");
  assert.equal(status, 400);
});

test("unknown / inactive products are still rejected", async () => {
  at(L);
  const { status } = await checkout(cart(["not-a-product", 1]));
  assert.equal(status, 400);
});
