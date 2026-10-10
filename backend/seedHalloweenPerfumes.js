/* =========================================================
   SEED HALLOWEEN EDITION — NOCTURNE & AZUR (100 ml)

   Adds (or updates) the two Halloween perfumes in MongoDB.
   The server always charges the price stored here, so the
   storefront cannot sell them until this has been run.

   Usage (from /backend, with MONGO_URI in .env):

     node seedHalloweenPerfumes.js

   Safe to re-run: it upserts by productId, so re-running after
   changing PRICE_100ML simply updates the price.

   KEEP IN SYNC with frontend/src/config/halloween.js:
     - productId  <->  HALLOWEEN_PRODUCTS.*.id
     - slug       <->  last segment of HALLOWEEN_PRODUCTS.*.route
     - PRICE_100ML <-> HALLOWEEN_PRICE_100ML

   TODO(owner): ₹1399 is a PLACEHOLDER (same as the existing
   100 ml perfumes). Confirm the real price, change it here AND in
   the frontend config, then re-run this script.
========================================================= */

require("dotenv").config();
const mongoose = require("mongoose");
const Product = require("./models/Product");

const PRICE_100ML = 1399; // TODO(owner): confirm

const PRODUCTS = [
  {
    productId: "perfume-nocturne",
    name: "NOCTURNE",
    slug: "nocturne",
    // Placeholder art. Replace with the real transparent-PNG Cloudinary URL when the photos arrive.
    images: ["https://kaeorn.com/halloween/nocturne-front.png"],
  },
  {
    productId: "perfume-azur",
    name: "AZUR",
    slug: "azur-blue-oud-perfume",
    images: ["https://kaeorn.com/halloween/azur-front.png"],
  },
];

async function seed() {
  await mongoose.connect(process.env.MONGO_URI);
  console.log(`Connected to database: ${mongoose.connection.name}`);

  for (const product of PRODUCTS) {
    const existing = await Product.findOne({ productId: product.productId });
    if (existing) {
      console.log(
        `Found existing "${existing.productId}" (₹${existing.price}) — updating.`,
      );
    }

    const doc = await Product.findOneAndUpdate(
      { productId: product.productId },
      {
        $set: {
          ...product,
          category: "perfume",
          price: PRICE_100ML,
          isActive: true,
        },
      },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    );

    console.log(`✅ ${doc.productId} — ${doc.name} — ₹${doc.price}`);
  }

  await mongoose.disconnect();
  console.log("Done.");
}

seed().catch((err) => {
  console.error("❌ Seed failed:", err.message);
  process.exit(1);
});
