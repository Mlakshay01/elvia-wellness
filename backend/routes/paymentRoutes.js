const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");

const Order = require("../models/Order");
const Product = require("../models/Product");
const userAuth = require("../middleware/userAuth");

const router = express.Router();

/* ======================================
   VERIFY ENV VARIABLES
====================================== */
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.error("❌ Razorpay keys missing in environment variables");
}

/* ======================================
   RAZORPAY INSTANCE
====================================== */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

/* ======================================
   CREATE PAYMENT ORDER
====================================== */
router.post("/create-order", userAuth, async (req, res) => {
  try {
    const { amount, cartItems, address } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: "Invalid amount" });
    }

    if (!cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({ message: "Invalid cart items" });
    }

    const options = {
      amount: Math.round(amount * 100),
      currency: "INR",
      receipt: "kaeorn_" + Date.now(),
      notes: {
        userId: req.user || "guest",
        email: req.userEmail || "guest",
        cart: JSON.stringify(cartItems),
        address: JSON.stringify(address || {}),
      },
    };

    const order = await razorpay.orders.create(options);

    res.json(order);
  } catch (err) {
    console.error("🔥 Razorpay create error:", err.message);
    res.status(500).json({
      message: "Razorpay order failed",
      error: err.message,
    });
  }
});

/* ======================================
   VERIFY PAYMENT SIGNATURE (CRITICAL)
====================================== */
router.post("/verify", async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
    } = req.body;

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res.status(400).json({ success: false });
    }

    const body = `${razorpay_order_id}|${razorpay_payment_id}`;

    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest("hex");

    if (expectedSignature !== razorpay_signature) {
      console.log("❌ Invalid payment signature");
      return res.status(400).json({ success: false });
    }

    console.log("✅ Payment verified:", razorpay_payment_id);

    res.json({ success: true });
  } catch (err) {
    console.error("🔥 Verify error:", err.message);
    res.status(500).json({ success: false });
  }
});

/* ======================================
   WEBHOOK — ENTERPRISE ORDER CREATION
====================================== */
router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-razorpay-signature"];

      const expectedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)
        .update(req.body)
        .digest("hex");

      if (signature !== expectedSignature) {
        console.log("❌ Invalid webhook signature");
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());

      /* ======================================
         PAYMENT CAPTURED
      ======================================= */
      if (event.event === "payment.captured") {
        const payment = event.payload.payment.entity;

        const existing = await Order.findOne({
          "payment.razorpayPaymentId": payment.id,
        });

        if (existing) {
          console.log("⚠️ Duplicate payment ignored:", payment.id);
          return res.json({ status: "duplicate ignored" });
        }

        const notes = payment.notes || {};
        const cartItems = JSON.parse(notes.cart || "[]");
        const address = JSON.parse(notes.address || "{}");

        const validatedItems = [];

        for (const item of cartItems) {
          const product = await Product.findOne({
            productId: item.productId,
            isActive: true,
          });

          if (!product) continue;

          validatedItems.push({
            productId: product.productId,
            name: product.name,
            price: product.price,
            quantity: item.quantity,
            image: item.image,
          });
        }

        const totalAmount = validatedItems.reduce(
          (sum, i) => sum + i.price * i.quantity,
          0
        );

        await Order.create({
          userEmail: notes.email,
          items: validatedItems,
          address,
          totalAmount,
          payment: {
            razorpayPaymentId: payment.id,
            razorpayOrderId: payment.order_id,
          },
          status: "Paid",
        });

        console.log("✅ ORDER CREATED VIA WEBHOOK");
      }

      /* ======================================
         PAYMENT FAILED
      ======================================= */
      if (event.event === "payment.failed") {
        console.log(
          "❌ Payment failed:",
          event.payload.payment.entity.id
        );
      }

      res.json({ status: "ok" });
    } catch (err) {
      console.error("🔥 Webhook error:", err.message);
      res.status(500).send("Webhook failed");
    }
  }
);

module.exports = router;