/* =========================================================
   SEED DISCOVERY SET

   Adds (or updates) the DISCOVERY SET product in MongoDB.
   The server always charges the price stored here, so the
   storefront can't sell the set until this has been run.

   Usage (from /backend, with MONGO_URI in .env):

     node seedDiscoverySet.js

   Safe to re-run: it upserts by productId, so re-running after
   changing PRICE simply updates the price.
========================================================= */

require("dotenv").config();
const mongoose = require("mongoose");
const Product = require("./models/Product");

// Keep in sync with the discovery-set price in
// frontend/src/data/products.js
const PRICE = 1200;

const PRODUCT = {
  productId: "discovery-set",
  name: "DISCOVERY SET",
  slug: "discovery-set",
  category: "perfume",
  price: PRICE,
  // First image is what shows on orders/emails. Swap for a real set photo.
  images: [
    "https://res.cloudinary.com/dvmntn6vf/image/upload/v1775280305/ChatGPT_Image_Apr_4_2026_10_54_03_AM_fjvuq2.png",
  ],
  isActive: true,
};

async function seed() {
  await mongoose.connect(process.env.MONGO_URI);
  console.log(`Connected to database: ${mongoose.connection.name}`);

  const existing = await Product.findOne({ productId: PRODUCT.productId });
  if (existing) {
    console.log(
      `Found existing "${existing.productId}" (₹${existing.price}) — updating.`,
    );
  }

  const doc = await Product.findOneAndUpdate(
    { productId: PRODUCT.productId },
    { $set: PRODUCT },
    { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
  );

  console.log(`✅ ${doc.productId} — ${doc.name} — ₹${doc.price}`);

  await mongoose.disconnect();
}

seed().catch((err) => {
  console.error("❌ Seed failed:", err.message);
  process.exit(1);
});
