const express = require("express");
const router = express.Router();

const Review = require("../models/Review");
const Order = require("../models/Order");
const userAuth = require("../middleware/userAuth");
const adminAuth = require("../middleware/adminAuth");

/* Storefront product ids that can be reviewed (must match frontend/src/data/products.js).
   30 ml variants ("<id>-30ml") share the review page of their base product. */
const REVIEWABLE_PRODUCTS = [
  "the-noir-men",
  "perfume-veil-unisex",
  "perfume-soie-femme",
  "nox",
  "velion",
  "discovery-set",
];

const PAID_STATUSES = ["Paid", "Processing", "Shipped", "Out for Delivery", "Delivered"];

/* ---------- tiny in-memory rate limiter (per IP) for writes ---------- */
const hits = new Map();
function writeLimiter(max = 10, windowMs = 60 * 60 * 1000) {
  return (req, res, next) => {
    const key = req.ip || "unknown";
    const now = Date.now();
    const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (recent.length >= max) {
      return res.status(429).json({ message: "Too many review submissions. Please try again later." });
    }
    recent.push(now);
    hits.set(key, recent);
    next();
  };
}

/* ---------- helpers ---------- */
const clean = (v) =>
  String(v ?? "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "") // control chars
    .replace(/<[^>]*>/g, "") // no markup in reviews
    .trim();

function publicName(user) {
  const raw = clean(user?.name);
  if (raw) {
    const parts = raw.split(/\s+/);
    const first = parts[0].slice(0, 30);
    const last = parts.length > 1 ? ` ${parts[parts.length - 1][0].toUpperCase()}.` : "";
    return `${first}${last}`;
  }
  return "KAEORN customer";
}

async function hasPurchased(userId, productId) {
  const ids = [productId, `${productId}-30ml`];
  const order = await Order.findOne({
    user: userId,
    status: { $in: PAID_STATUSES },
    "items.productId": { $in: ids },
  }).select("_id");
  return !!order;
}

function shape(r) {
  return {
    _id: r._id,
    name: r.displayName,
    rating: r.rating,
    title: r.title || "",
    comment: r.comment,
    verifiedPurchase: !!r.verifiedPurchase,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
  };
}

async function summaryFor(productId) {
  const rows = await Review.aggregate([
    { $match: { productId, status: "published" } },
    { $group: { _id: "$rating", n: { $sum: 1 } } },
  ]);
  const distribution = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  let count = 0;
  let total = 0;
  for (const r of rows) {
    distribution[r._id] = r.n;
    count += r.n;
    total += r._id * r.n;
  }
  return { count, average: count ? Math.round((total / count) * 10) / 10 : 0, distribution };
}

function validProduct(req, res) {
  if (!REVIEWABLE_PRODUCTS.includes(req.params.productId)) {
    res.status(404).json({ message: "Unknown product" });
    return false;
  }
  return true;
}

/* =====================================================
   ADMIN (registered first so "/admin/..." is not read as a productId)
===================================================== */

router.get("/admin/all", adminAuth, async (req, res) => {
  try {
    const reviews = await Review.find().sort({ createdAt: -1 }).limit(500).populate("user", "email name");
    res.json(reviews);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch reviews" });
  }
});

/* hide / re-publish a review */
router.patch("/admin/:id", adminAuth, async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!["published", "hidden"].includes(status)) {
      return res.status(400).json({ message: "status must be 'published' or 'hidden'" });
    }
    const review = await Review.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!review) return res.status(404).json({ message: "Review not found" });
    res.json(review);
  } catch (err) {
    res.status(500).json({ message: "Failed to update review" });
  }
});

router.delete("/admin/:id", adminAuth, async (req, res) => {
  try {
    await Review.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete review" });
  }
});

/* =====================================================
   PUBLIC
===================================================== */

/* GET /api/reviews/:productId  → { summary, reviews } */
router.get("/:productId", async (req, res) => {
  if (!validProduct(req, res)) return;
  try {
    const { productId } = req.params;
    const [reviews, summary] = await Promise.all([
      Review.find({ productId, status: "published" }).sort({ createdAt: -1 }).limit(100),
      summaryFor(productId),
    ]);
    res.set("Cache-Control", "public, max-age=60");
    res.json({ summary, reviews: reviews.map(shape) });
  } catch (err) {
    console.error("Get reviews error:", err.message);
    res.status(500).json({ message: "Failed to fetch reviews" });
  }
});

/* =====================================================
   LOGGED-IN CUSTOMER
===================================================== */

/* GET /api/reviews/:productId/mine → the current user's review (or null) + purchase flag */
router.get("/:productId/mine", userAuth, async (req, res) => {
  if (!validProduct(req, res)) return;
  try {
    const { productId } = req.params;
    const [mine, purchased] = await Promise.all([
      Review.findOne({ productId, user: req.userId }),
      hasPurchased(req.userId, productId),
    ]);
    res.set("Cache-Control", "no-store");
    res.json({ review: mine ? shape(mine) : null, verifiedPurchase: purchased });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch your review" });
  }
});

/* POST /api/reviews/:productId  { rating, title?, comment } — create, or update your existing review */
router.post("/:productId", userAuth, writeLimiter(), async (req, res) => {
  if (!validProduct(req, res)) return;
  try {
    const { productId } = req.params;
    const rating = Number(req.body?.rating);
    const title = clean(req.body?.title).slice(0, 80);
    const comment = clean(req.body?.comment);

    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ message: "Please choose a rating from 1 to 5 stars." });
    }
    if (comment.length < 10) {
      return res.status(400).json({ message: "Please write at least 10 characters." });
    }
    if (comment.length > 1000) {
      return res.status(400).json({ message: "Reviews can be up to 1000 characters." });
    }

    const verifiedPurchase = await hasPurchased(req.userId, productId);

    const review = await Review.findOneAndUpdate(
      { productId, user: req.userId },
      {
        $set: { rating, title, comment, verifiedPurchase, displayName: publicName(req.user), status: "published" },
        $setOnInsert: { productId, user: req.userId },
      },
      { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true }
    );

    res.status(201).json({ review: shape(review), summary: await summaryFor(productId) });
  } catch (err) {
    console.error("Create review error:", err.message);
    res.status(500).json({ message: "Could not save your review. Please try again." });
  }
});

/* DELETE /api/reviews/:productId/mine — remove your own review */
router.delete("/:productId/mine", userAuth, async (req, res) => {
  if (!validProduct(req, res)) return;
  try {
    await Review.deleteOne({ productId: req.params.productId, user: req.userId });
    res.json({ success: true, summary: await summaryFor(req.params.productId) });
  } catch (err) {
    res.status(500).json({ message: "Could not delete your review." });
  }
});

module.exports = router;
