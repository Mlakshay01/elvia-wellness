const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema(
  {
    /* ======================================
       ACCOUNT
    ====================================== */

    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    userEmail: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    /* ======================================
       ITEMS

       SNAPSHOT OF PRODUCTS AT PURCHASE TIME

       These values are copied into the order
       when checkout starts.

       Future product changes will NOT change
       historical orders.
    ====================================== */

    items: {
      type: [
        {
          productId: {
            type: String,
            required: true,
          },

          name: {
            type: String,
            required: true,
          },

          price: {
            type: Number,
            required: true,
            min: 0,
          },

          quantity: {
            type: Number,
            required: true,
            min: 1,
          },

          image: {
            type: String,
            default: "",
          },
        },
      ],

      required: true,

      validate: {
        validator: function (items) {
          return (
            Array.isArray(items) &&
            items.length > 0
          );
        },

        message:
          "An order must contain at least one item.",
      },
    },

    /* ======================================
       DELIVERY ADDRESS
    ====================================== */

    address: {
      fullName: {
        type: String,
        required: true,
        trim: true,
      },

      email: {
        type: String,
        lowercase: true,
        trim: true,
        default: "",
      },

      phone: {
        type: String,
        required: true,
        trim: true,
      },

      street: {
        type: String,
        required: true,
        trim: true,
      },

      city: {
        type: String,
        required: true,
        trim: true,
      },

      state: {
        type: String,
        required: true,
        trim: true,
      },

      postalCode: {
        type: String,
        required: true,
        trim: true,
      },

      country: {
        type: String,
        default: "India",
        trim: true,
      },
    },

    /* ======================================
       PAYMENT
    ====================================== */

    payment: {
      razorpayPaymentId: {
        type: String,
        unique: true,
        sparse: true,
      },

      razorpayOrderId: {
        type: String,
        unique: true,
        sparse: true,
      },

      method: {
        type: String,
        default: "Razorpay",
      },

      status: {
        type: String,
        enum: [
          "Pending",
          "Paid",
          "Failed",
          "Refunded",
        ],
        default: "Pending",
      },
    },

    /* ======================================
       PRICING
    ====================================== */

    /*
      Product total BEFORE coupon discount
    */

    originalAmount: {
      type: Number,
      required: true,
      min: 0,
    },

    /*
      Amount actually discounted by coupon
    */

    discountAmount: {
      type: Number,
      default: 0,
      min: 0,
    },

    /*
      Final amount charged / payable

      This MUST match Razorpay amount / 100.
    */

    totalAmount: {
      type: Number,
      required: true,
      min: 1,
    },

    /* ======================================
       COUPON
    ====================================== */

    /*
      The actual coupon code used by customer.

      Example:
      SHAQUIB10
    */

    couponCode: {
      type: String,
      default: null,
      trim: true,
      uppercase: true,
    },

    /* ======================================
       PARTNER / INFLUENCER SNAPSHOT

       Partner data comes from the separate
       Partners MongoDB database.

       We store a snapshot here instead of
       using mongoose ref because the partner
       user exists in another database.

       Example:

       partner: {
         partnerId: "6a1d2566e4dd0541d6a8d39f",
         name: "Shaquib Khan",
         couponCode: "SHAQUIB10",
         discountPercent: 10,
         commissionPercent: 10
       }

       This preserves the exact partner data
       used when the order was placed.
    ====================================== */

    partner: {
      partnerId: {
        type: String,
        default: null,
        trim: true,
      },

      name: {
        type: String,
        default: null,
        trim: true,
      },

      couponCode: {
        type: String,
        default: null,
        trim: true,
        uppercase: true,
      },

      discountPercent: {
        type: Number,
        default: 0,
        min: 0,
        max: 100,
      },

      commissionPercent: {
        type: Number,
        default: 0,
        min: 0,
        max: 100,
      },
    },

    /* ======================================
       COMMISSION
    ====================================== */

    /*
      Commission amount calculated from the
      partner's commission percentage.

      This is stored as a snapshot so that
      future changes to the partner's
      commissionPercent do NOT alter old orders.
    */

    commissionAmount: {
      type: Number,
      default: 0,
      min: 0,
    },

    /*
      Prevents the same order from being
      counted multiple times toward partner
      revenue and commission.
    */

    commissionRecorded: {
      type: Boolean,
      default: false,
    },

    /* ======================================
       ORDER STATUS
    ====================================== */

    status: {
      type: String,

      enum: [
        "Payment Pending",
        "Paid",
        "Processing",
        "Shipped",
        "Out for Delivery",
        "Delivered",
        "Cancelled",
        "Refunded",
      ],

      default: "Payment Pending",

      index: true,
    },
  },

  {
    timestamps: true,
  }
);

/* ======================================
   USEFUL INDEX FOR "MY ORDERS"

   Allows efficient queries like:

   Order.find({
     user: req.user._id
   })
====================================== */

orderSchema.index({
  user: 1,
  createdAt: -1,
});

/* ======================================
   USEFUL INDEX FOR PARTNER ORDERS

   Allows efficient queries for:

   - Partner sales
   - Partner revenue
   - Commission tracking
====================================== */

orderSchema.index({
  "partner.partnerId": 1,
  createdAt: -1,
});

/* ======================================
   USEFUL INDEX FOR COUPON LOOKUPS

   Allows finding orders by coupon code.
====================================== */

orderSchema.index({
  couponCode: 1,
});

/* ======================================
   EXPORT
====================================== */

module.exports =
  mongoose.model(
    "Order",
    orderSchema
  );