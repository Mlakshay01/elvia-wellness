const express = require("express");
const router = express.Router();

const Order = require("../models/Order");
const Product = require("../models/Product");
const userAuth = require("../middleware/userAuth");
const adminAuth = require("../middleware/adminAuth");
const queueOrderEmail = require("../utils/emailQueue");

/* =========================================================
   IMAGE HELPER

   Your Product.images field stores an array of image
   objects (e.g. { url, secure_url, ... }), not plain
   strings. This normalizes either shape into a single
   usable URL string.
   ========================================================= */

function resolveProductImage(product) {
  const images = product?.images;

  if (!Array.isArray(images) || images.length === 0) {
    return "";
  }

  const firstImage = images[0];

  if (typeof firstImage === "string") {
    return firstImage;
  }

  if (firstImage && typeof firstImage === "object") {
    return (
      firstImage.url ||
      firstImage.secure_url ||
      firstImage.image ||
      firstImage.src ||
      ""
    );
  }

  return "";
}

/* =========================================================
   CREATE ORDER

   NOTE ON AMOUNTS:
   totalAmount / originalAmount are ALWAYS computed here
   from verified product prices. We no longer fall back to
   req.body.totalAmount / req.body.originalAmount — trusting
   a frontend-supplied amount (even as a fallback) means a
   modified client could pass a custom sale price. If you
   need coupon-based discounts on this route later, compute
   the discount server-side the same way checkoutRazorpay.js
   does, rather than accepting a client-provided total.
   ========================================================= */
router.post("/", userAuth, async (req, res) => {
  try {
    const items = req.body.items || [];

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: "No items provided" });
    }

    const validatedItems = [];

    for (const item of items) {
      const product = await Product.findOne({
        productId: item.productId,
        isActive: true,
      });

      if (!product) {
        return res.status(400).json({
          message: `Invalid product: ${item.productId}`,
        });
      }

      const quantity = Number(item.quantity);

      if (!Number.isInteger(quantity) || quantity < 1) {
        return res.status(400).json({
          message: `Invalid quantity for product: ${item.productId}`,
        });
      }

      const price = Number(product.price);

      if (!Number.isFinite(price) || price <= 0) {
        return res.status(400).json({
          message: `Invalid price for product: ${product.name}`,
        });
      }

      const image = resolveProductImage(product);

      validatedItems.push({
        productId: product.productId,
        name: product.name,
        price,
        quantity,
        image,
      });
    }

    /* ======================================
       SERVER-COMPUTED TOTAL — SOURCE OF TRUTH
    ====================================== */

    const totalAmount = validatedItems.reduce(
      (sum, i) => sum + i.price * i.quantity,
      0,
    );

    const userEmail = req.user?.email || null;

    const order = await Order.create({
      user: req.user?._id || null,
      userEmail,
      items: validatedItems,
      address: req.body.address || null,
      totalAmount,
      originalAmount: totalAmount,
      couponCode: req.body.couponCode || null,
      commissionRecorded: false,
      status: "Pending",
    });

    res.status(201).json(order);
  } catch (error) {
    console.error("Create order error:", error);
    res.status(500).json({ message: "Failed to create order" });
  }
});

/* =========================================================
   USER – GET MY ORDERS
   ========================================================= */
router.get("/my-orders", userAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        message: "Please log in to view your orders",
      });
    }

    const orders = await Order.find({
      user: req.user._id,
    }).sort({
      createdAt: -1,
    });

    res.json(orders);
  } catch (error) {
    console.error("My orders error:", error);
    res.status(500).json({
      message: "Failed to fetch orders",
    });
  }
});

/* =========================================================
   USER – GET SINGLE ORDER
   ========================================================= */
router.get("/my-orders/:id", userAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        message: "Please log in to view your orders",
      });
    }

    const order = await Order.findOne({
      _id: req.params.id,
      user: req.user._id,
    });

    if (!order) {
      return res.status(404).json({
        message: "Order not found",
      });
    }

    res.json(order);
  } catch (error) {
    console.error("Single order error:", error);
    res.status(500).json({
      message: "Failed to fetch order",
    });
  }
});

/* =========================================================
   ADMIN – ALL ORDERS
   ========================================================= */
router.get("/", adminAuth, async (req, res) => {
  try {
    const orders = await Order.find()
      .populate("user", "email name")
      .sort({ createdAt: -1 });

    const formatted = orders.map((order) => ({
      ...order.toObject(),
      customerEmail: order.userEmail || order.user?.email || "N/A",
    }));

    res.json(formatted);
  } catch (error) {
    console.error("Admin orders error:", error);
    res.status(500).json({ message: "Failed to fetch orders" });
  }
});

/* =========================================================
   ADMIN – SINGLE ORDER
   ========================================================= */
router.get("/:id", adminAuth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate(
      "user",
      "email name",
    );
    if (!order) return res.status(404).json({ message: "Order not found" });

    res.json({
      ...order.toObject(),
      customerEmail: order.userEmail || order.user?.email || "N/A",
    });
  } catch (error) {
    console.error("Admin single order error:", error);
    res.status(500).json({ message: "Failed to fetch order" });
  }
});

/* =========================================================
   ADMIN – UPDATE STATUS
   Records commission only when status becomes "Delivered"
   ========================================================= */
router.put("/:id/status", adminAuth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate(
      "user",
      "email name",
    );
    if (!order) return res.status(404).json({ message: "Order not found" });

    const previousStatus = order.status;
    const newStatus = req.body.status;

    order.status = newStatus;
    await order.save();

    // send status update email
    if (previousStatus !== newStatus) {
      queueOrderEmail(order);
    }

    // ── COMMISSION: only when Delivered, only once, only if coupon was used ──
    if (
      newStatus === "Delivered" &&
      previousStatus !== "Delivered" &&
      order.couponCode &&
      !order.commissionRecorded
    ) {
      try {
        const influencerApiUrl = process.env.INFLUENCER_API_URL;

        const commissionRes = await fetch(
          `${influencerApiUrl}/api/coupon/apply`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              orderId: order._id.toString(),
              couponCode: order.couponCode,
              productName: order.items.map((i) => i.name).join(", "),
              originalAmount: order.originalAmount || order.totalAmount,
              finalAmount: order.totalAmount,
              customerName: order.address?.fullName || "",
              customerEmail: order.userEmail || order.address?.email || "",
            }),
          },
        );

        const commissionData = await commissionRes.json();

        if (commissionRes.ok && commissionData.success) {
          // mark so it never fires twice even if status is toggled
          order.commissionRecorded = true;
          await order.save();
          console.log(
            `✅ Commission recorded for order ${order._id} — code ${order.couponCode}`,
          );
        } else {
          console.error(
            "Commission recording failed:",
            commissionData.message,
          );
        }
      } catch (commissionErr) {
        // never block the admin action if influencer portal is down
        console.error("Commission API unreachable:", commissionErr.message);
      }
    }

    res.json(order);
  } catch (error) {
    console.error("Update status error:", error);
    res.status(500).json({ message: "Failed to update status" });
  }
});

/* =========================================================
   ADMIN – DELETE ORDER
   ========================================================= */
router.delete("/:id", adminAuth, async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error("Delete order error:", error);
    res.status(500).json({ message: "Failed to delete order" });
  }
});

module.exports = router;