/* =========================================================
   SEED 30 ML PRODUCTS

   Adds (or updates) the 30 ml versions of THÉ NOIR, VEIL and
   SOIE FEMME in MongoDB. Each size is its own product, so
   cart, orders and Razorpay all work with no other backend
   changes — the server always charges the price stored here.

   Usage (from /backend, with MONGO_URI in .env):

     node seed30mlProducts.js

   Safe to re-run: it upserts by productId, so re-running
   after changing PRICE_30ML simply updates the price.
========================================================= */

require("dotenv").config();
const mongoose = require("mongoose");
const Product = require("./models/Product");

// Keep in sync with PRICE_30ML in frontend/src/data/products.js
const PRICE_30ML = 599;

const VARIANTS = [
  {
    baseProductId: "the-noir-men",
    productId: "the-noir-men-30ml",
    name: "THÉ NOIR (30 ml)",
    slug: "noir-party-perfume-30ml",
  },
  {
    baseProductId: "perfume-veil-unisex",
    productId: "perfume-veil-unisex-30ml",
    name: "VEIL (30 ml)",
    slug: "veil-fresh-perfume-30ml",
  },
  {
    baseProductId: "perfume-soie-femme",
    productId: "perfume-soie-femme-30ml",
    name: "SOIE FEMME (30 ml)",
    slug: "soie-femme-floral-perfume-30ml",
  },
];

async function seed() {
  await mongoose.connect(process.env.MONGO_URI);
  console.log(`Connected to database: ${mongoose.connection.name}`);

  for (const variant of VARIANTS) {
    // Reuse the 100 ml product's images so orders show the same picture.
    const base = await Product.findOne({ productId: variant.baseProductId });

    if (!base) {
      console.warn(
        `⚠️  Base product "${variant.baseProductId}" not found — ` +
          `${variant.productId} will be created without images.`,
      );
    }

    const doc = await Product.findOneAndUpdate(
      { productId: variant.productId },
      {
        $set: {
          name: variant.name,
          slug: variant.slug,
          category: "perfume",
          price: PRICE_30ML,
          images: base?.images || [],
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
