const mongoose = require("mongoose");

/**
 * Customer product reviews.
 * One review per (user, product). Stored as plain text (rendered escaped by React).
 */
const reviewSchema = new mongoose.Schema(
  {
    // Storefront product id, e.g. "the-noir-men" (see frontend/src/data/products.js)
    productId: { type: String, required: true, index: true, trim: true },

    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    // Public display name, e.g. "Aarav S." — never the email address
    displayName: { type: String, required: true, trim: true, maxlength: 60 },

    rating: { type: Number, required: true, min: 1, max: 5 },
    title: { type: String, trim: true, maxlength: 80, default: "" },
    comment: { type: String, required: true, trim: true, minlength: 10, maxlength: 1000 },

    // true when this user has a paid order containing the product
    verifiedPurchase: { type: Boolean, default: false },

    // published = shown on the storefront; hidden = removed by an admin (kept for records)
    status: { type: String, enum: ["published", "hidden"], default: "published", index: true },
  },
  { timestamps: true }
);

reviewSchema.index({ productId: 1, user: 1 }, { unique: true });

module.exports = mongoose.model("Review", reviewSchema);
