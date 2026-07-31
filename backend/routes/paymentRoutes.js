const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");

const Order = require("../models/Order");
const Product = require("../models/Product");
const userAuth = require("../middleware/userAuth");
const PartnerUser = require("../models/PartnerUser");

const router = express.Router();

/* ======================================
   ENVIRONMENT CHECK
====================================== */

if (!process.env.RAZORPAY_KEY_ID) {
  console.error("❌ RAZORPAY_KEY_ID is missing");
}

if (!process.env.RAZORPAY_KEY_SECRET) {
  console.error("❌ RAZORPAY_KEY_SECRET is missing");
}

if (!process.env.RAZORPAY_WEBHOOK_SECRET) {
  console.warn("⚠️ RAZORPAY_WEBHOOK_SECRET is missing");
}

/* ======================================
   RAZORPAY
====================================== */

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

/* ======================================
   MONEY HELPER
====================================== */

function roundMoney(amount) {
  return Math.round(Number(amount) * 100) / 100;
}

/* ======================================
   IMAGE HELPER

   Your Product.images field stores an array of
   image objects (e.g. { url, secure_url, ... }),
   not plain strings. This normalizes either shape
   into a single usable URL string so it never gets
   saved as "[object Object]" or dropped silently.
====================================== */

function resolveProductImage(cartItemImage, product) {
  // 1. Prefer a real string sent from the frontend cart.
  if (typeof cartItemImage === "string" && cartItemImage.trim()) {
    return cartItemImage;
  }

  // 2. Fall back to the product's own images array.
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

/* ======================================
   COUPON VALIDATION

   IMPORTANT:

   Replace this function with your actual
   coupon database/system if you have one.

   NEVER trust frontend discountAmount.

   The frontend sends only couponCode.

   Backend determines discountAmount.
====================================== */

async function validateCoupon(couponCode, originalAmount) {
  if (!couponCode) {
    return {
      valid: true,
      couponCode: null,
      discountAmount: 0,
      discountPercent: 0,
      influencerName: null,
      commissionPercent: 0,
    };
  }

  const normalizedCode = String(couponCode).trim().toUpperCase();

  try {
    const partner = await PartnerUser.findOne({
      couponCode: normalizedCode,
      role: "influencer",
      isActive: true,
    }).select("name couponCode discountPercent commissionPercent");

    if (!partner) {
      return {
        valid: false,
        couponCode: normalizedCode,
        discountAmount: 0,
      };
    }

    const discountPercent = Math.max(
      0,
      Math.min(100, Number(partner.discountPercent || 0)),
    );

    const discountAmount = roundMoney(
      Number(originalAmount) * (discountPercent / 100),
    );

    return {
      valid: true,
      couponCode: partner.couponCode,
      discountAmount,
      discountPercent,
      influencerName: partner.name,
      commissionPercent: Number(partner.commissionPercent || 0),
    };
  } catch (error) {
    console.error("❌ Partner coupon validation failed:", error);
    throw error;
  }
}

/* ======================================
   CREATE ORDER
====================================== */

router.post("/create-order", userAuth, async (req, res) => {
  try {
    const { cartItems, address, couponCode } = req.body;

    /* ======================================
       AUTHENTICATION

       userAuth guarantees req.user exists.
    ====================================== */

    if (!req.user || !req.user._id) {
      return res.status(401).json({
        success: false,
        message: "Please login before placing an order.",
      });
    }

    const userId = req.user._id;

    const userEmail = req.userEmail || req.user.email;

    if (!userEmail) {
      return res.status(400).json({
        success: false,
        message: "Your account email is required.",
      });
    }

    console.log("======================================");
    console.log("🛒 CREATE PAYMENT ORDER");
    console.log("User ID:", userId.toString());
    console.log("User Email:", userEmail);
    console.log("Coupon:", couponCode);
    console.log("======================================");

    /* ======================================
       VALIDATE CART
    ====================================== */

    if (!Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Your cart is empty.",
      });
    }

    /* ======================================
       VALIDATE ADDRESS
    ====================================== */

    if (!address || typeof address !== "object") {
      return res.status(400).json({
        success: false,
        message: "Delivery address is required.",
      });
    }

    if (
      !address.fullName ||
      !address.phone ||
      !address.street ||
      !address.city ||
      !address.state ||
      !address.postalCode
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide complete delivery details.",
      });
    }

    /* ======================================
       NORMALIZE EMAIL

       Account email is the source of truth.

       We do NOT allow checkout to change
       the account's userEmail.
    ====================================== */

    const customerEmail = String(userEmail).trim().toLowerCase();

    /* ======================================
       GET VERIFIED PRODUCTS

       FRONTEND PRICES ARE NEVER TRUSTED.

       We only accept:
       - product ID
       - quantity

       Backend gets:
       - name
       - price
       - image
    ====================================== */

    const validatedItems = [];

    for (const cartItem of cartItems) {
      const productId = cartItem.id || cartItem.productId;

      if (!productId) {
        return res.status(400).json({
          success: false,
          message: "Invalid product in cart.",
        });
      }

      const quantity = Number(cartItem.quantity);

      if (!Number.isInteger(quantity) || quantity < 1) {
        return res.status(400).json({
          success: false,
          message: "Invalid product quantity.",
        });
      }

      const product = await Product.findOne({
        productId: String(productId),
        isActive: true,
      });

      if (!product) {
        return res.status(400).json({
          success: false,
          message: `Product not available: ${productId}`,
        });
      }

      const productPrice = Number(product.price);

      if (!Number.isFinite(productPrice) || productPrice <= 0) {
        console.error(
          "❌ Invalid product price:",
          product.productId,
          product.price,
        );

        return res.status(400).json({
          success: false,
          message: `Invalid price for product: ${product.name}`,
        });
      }

      validatedItems.push({
        productId: product.productId,
        name: product.name,
        price: roundMoney(productPrice),
        quantity,
        image: resolveProductImage(cartItem.image, product),
      });
    }

    /* ======================================
       CALCULATE ORIGINAL TOTAL

       SERVER SOURCE OF TRUTH
    ====================================== */

    const originalAmount = roundMoney(
      validatedItems.reduce(
        (sum, item) => sum + Number(item.price) * Number(item.quantity),
        0,
      ),
    );

    if (!Number.isFinite(originalAmount) || originalAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid order amount.",
      });
    }

    /* ======================================
       VALIDATE COUPON

       Frontend finalTotal is NOT trusted.

       Backend calculates discount.
    ====================================== */

    const couponResult = await validateCoupon(couponCode, originalAmount);

    if (!couponResult.valid) {
      return res.status(400).json({
        success: false,
        message: `Invalid or expired coupon: ${couponResult.couponCode}`,
      });
    }

    const finalCouponCode = couponResult.couponCode;

    const discountAmount = roundMoney(
      Math.min(Math.max(0, couponResult.discountAmount), originalAmount),
    );

    /* ======================================
       FINAL TOTAL

       THIS IS THE ONLY AMOUNT USED
       FOR RAZORPAY.
    ====================================== */

    const totalAmount = roundMoney(originalAmount - discountAmount);

    if (!Number.isFinite(totalAmount) || totalAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid final order amount.",
      });
    }

    const razorpayAmount = Math.round(totalAmount * 100);

    if (!Number.isInteger(razorpayAmount) || razorpayAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid Razorpay amount.",
      });
    }

    /* ======================================
       CREATE MONGODB ORDER

       IMPORTANT:

       The user ID is ALWAYS from
       authenticated req.user._id.

       NEVER from frontend.
    ====================================== */

    const newOrder = await Order.create({
      user: userId,
      userEmail: customerEmail,
      items: validatedItems,

      address: {
        fullName: String(address.fullName).trim(),
        email: customerEmail,
        phone: String(address.phone).trim(),
        street: String(address.street).trim(),
        city: String(address.city).trim(),
        state: String(address.state).trim(),
        postalCode: String(address.postalCode).trim(),
        country: address.country || "India",
      },

      originalAmount,
      discountAmount,
      totalAmount,
      couponCode: finalCouponCode,

      payment: {
        method: "Razorpay",
        status: "Pending",
      },

      status: "Payment Pending",
    });

    console.log("✅ MongoDB order created");
    console.log("Mongo Order ID:", newOrder._id.toString());
    console.log("User ID:", newOrder.user.toString());
    console.log("Email:", newOrder.userEmail);
    console.log("Items:", newOrder.items);
    console.log("Original:", newOrder.originalAmount);
    console.log("Discount:", newOrder.discountAmount);
    console.log("Final:", newOrder.totalAmount);
    console.log("Coupon:", newOrder.couponCode);

    /* ======================================
       CREATE RAZORPAY ORDER

       RAZORPAY AMOUNT COMES FROM
       SERVER-CALCULATED totalAmount.

       NEVER FROM:
       - localStorage
       - frontend finalTotal
       - frontend discount
    ====================================== */

    let razorpayOrder;

    try {
      razorpayOrder = await razorpay.orders.create({
        amount: razorpayAmount,
        currency: "INR",
        receipt: `kaeorn_${newOrder._id}`,
        notes: {
          orderId: newOrder._id.toString(),
          userId: userId.toString(),
          couponCode: finalCouponCode || "",
        },
      });
    } catch (razorpayError) {
      console.error("❌ Razorpay order creation failed:", razorpayError);

      newOrder.status = "Cancelled";
      newOrder.payment.status = "Failed";
      await newOrder.save();

      return res.status(500).json({
        success: false,
        message: "Unable to start payment.",
      });
    }

    /* ======================================
       SAVE RAZORPAY ORDER ID
    ====================================== */

    newOrder.payment.razorpayOrderId = razorpayOrder.id;
    await newOrder.save();

    console.log("✅ Razorpay order created:", razorpayOrder.id);

    /* ======================================
       FINAL RESPONSE

       Frontend should use the returned
       server amount for display.

       Frontend still cannot control
       Razorpay's actual amount.
    ====================================== */

    return res.json({
      success: true,

      order: {
        id: newOrder._id,
        user: newOrder.user,
        userEmail: newOrder.userEmail,
        items: newOrder.items,
        originalAmount: newOrder.originalAmount,
        discountAmount: newOrder.discountAmount,
        totalAmount: newOrder.totalAmount,
        couponCode: newOrder.couponCode,
      },

      razorpay: {
        id: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency,
      },
    });
  } catch (err) {
    console.error("🔥 Create order error:", err);

    return res.status(500).json({
      success: false,
      message: "Failed to create payment order.",
      error: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  }
});

/* ======================================
   VERIFY PAYMENT
====================================== */

router.post("/verify", userAuth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
      req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        success: false,
        message: "Incomplete payment verification data.",
      });
    }

    /* ======================================
       VERIFY SIGNATURE
    ====================================== */

    const body = `${razorpay_order_id}|${razorpay_payment_id}`;

    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest("hex");

    if (
      !crypto.timingSafeEqual(
        Buffer.from(expectedSignature, "utf8"),
        Buffer.from(razorpay_signature, "utf8"),
      )
    ) {
      console.error("❌ Invalid payment signature");

      return res.status(400).json({
        success: false,
        message: "Invalid payment signature.",
      });
    }

    /* ======================================
       FIND ORDER

       IMPORTANT:

       Find using BOTH:
       - Razorpay Order ID
       - Authenticated User ID

       This prevents one user from verifying
       another user's order.
    ====================================== */

    const order = await Order.findOne({
      "payment.razorpayOrderId": razorpay_order_id,
      user: req.user._id,
    });

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order record not found.",
      });
    }

    /* ======================================
       DUPLICATE PAYMENT
    ====================================== */

    if (order.payment && order.payment.razorpayPaymentId) {
      return res.json({
        success: true,
        message: "Payment already verified.",
        orderId: order._id,
      });
    }

    /* ======================================
       UPDATE PAYMENT
    ====================================== */

    order.payment.razorpayPaymentId = razorpay_payment_id;
    order.payment.status = "Paid";
    order.status = "Paid";

    await order.save();

    console.log("======================================");
    console.log("✅ PAYMENT VERIFIED");
    console.log("Mongo Order:", order._id.toString());
    console.log("User:", order.user.toString());
    console.log("Email:", order.userEmail);
    console.log("Items:", order.items);
    console.log("Original:", order.originalAmount);
    console.log("Discount:", order.discountAmount);
    console.log("Total:", order.totalAmount);
    console.log("Coupon:", order.couponCode);
    console.log("======================================");

    return res.json({
      success: true,
      message: "Payment verified successfully.",
      orderId: order._id,

      order: {
        id: order._id,
        user: order.user,
        userEmail: order.userEmail,
        items: order.items,
        originalAmount: order.originalAmount,
        discountAmount: order.discountAmount,
        totalAmount: order.totalAmount,
        couponCode: order.couponCode,
        status: order.status,
      },
    });
  } catch (err) {
    console.error("🔥 Payment verification error:", err);

    return res.status(500).json({
      success: false,
      message: "Payment verification failed.",
    });
  }
});

/* ======================================
   RAZORPAY WEBHOOK
====================================== */

router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-razorpay-signature"];

      if (!signature) {
        return res.status(400).send("Missing webhook signature");
      }

      if (!process.env.RAZORPAY_WEBHOOK_SECRET) {
        console.error("❌ Webhook secret missing");

        return res.status(500).send("Webhook configuration error");
      }

      /* ======================================
         VERIFY WEBHOOK
      ====================================== */

      const expectedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)
        .update(req.body)
        .digest("hex");

      if (
        !crypto.timingSafeEqual(
          Buffer.from(expectedSignature, "utf8"),
          Buffer.from(signature, "utf8"),
        )
      ) {
        console.error("❌ Invalid webhook signature");

        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());

      console.log("📩 Razorpay webhook:", event.event);

      /* ======================================
         PAYMENT CAPTURED
      ====================================== */

      if (event.event === "payment.captured") {
        const payment = event.payload.payment.entity;

        const razorpayOrderId = payment.order_id;

        const order = await Order.findOne({
          "payment.razorpayOrderId": razorpayOrderId,
        });

        if (!order) {
          console.error(
            "❌ Order not found for Razorpay order:",
            razorpayOrderId,
          );

          /*
            The webhook was valid, but there
            is no matching local order.

            Return 200 to avoid infinite retries.
          */

          return res.json({ status: "order not found" });
        }

        /* ======================================
           DUPLICATE WEBHOOK
        ====================================== */

        if (
          order.payment &&
          order.payment.razorpayPaymentId === payment.id
        ) {
          return res.json({ status: "duplicate ignored" });
        }

        /* ======================================
           IMPORTANT AMOUNT CHECK

           Razorpay amount is in paise.

           Our database amount is in rupees.

           If they don't match, DO NOT mark
           the order as paid automatically.
        ====================================== */

        const expectedAmount = Math.round(Number(order.totalAmount) * 100);

        const receivedAmount = Number(payment.amount);

        if (expectedAmount !== receivedAmount) {
          console.error("❌ PAYMENT AMOUNT MISMATCH");
          console.error("Expected:", expectedAmount);
          console.error("Received:", receivedAmount);

          /*
            Do not mark as Paid.

            This protects against inconsistent
            payment/order records.
          */

          return res.status(400).json({
            success: false,
            message: "Payment amount mismatch.",
          });
        }

        /* ======================================
           MARK PAID
        ====================================== */

        order.payment.razorpayPaymentId = payment.id;
        order.payment.status = "Paid";
        order.status = "Paid";

        await order.save();

        console.log("✅ WEBHOOK PAYMENT CAPTURED");
        console.log("Order:", order._id.toString());
        console.log("User:", order.user.toString());
        console.log("Email:", order.userEmail);
        console.log("Coupon:", order.couponCode);
        console.log("Amount:", order.totalAmount);
      }

      /* ======================================
         PAYMENT FAILED
      ====================================== */

      if (event.event === "payment.failed") {
        const payment = event.payload.payment.entity;

        const razorpayOrderId = payment.order_id;

        const order = await Order.findOne({
          "payment.razorpayOrderId": razorpayOrderId,
        });

        if (order) {
          /*
            Don't overwrite a successfully
            paid order with failed status.
          */

          if (order.payment.status !== "Paid") {
            order.payment.status = "Failed";
            order.status = "Cancelled";

            await order.save();

            console.log("❌ Payment failed:", order._id.toString());
          }
        }
      }

      return res.json({ status: "ok" });
    } catch (err) {
      console.error("🔥 Razorpay webhook error:", err);

      return res.status(500).send("Webhook failed");
    }
  },
);

module.exports = router;