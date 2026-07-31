const mongoose = require("mongoose");
const partnerDb = require("../config/partnerDb");

const partnerUserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
    },

    email: {
      type: String,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
    },

    role: {
      type: String,
    },

    isActive: {
      type: Boolean,
      default: true,
    },

    couponCode: {
      type: String,
      uppercase: true,
      trim: true,
      default: null,
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

    totalRevenue: {
      type: Number,
      default: 0,
    },

    totalCommission: {
      type: Number,
      default: 0,
    },

    paidOut: {
      type: Number,
      default: 0,
    },

    paymentDetails: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
    collection: "users",
  }
);

module.exports = partnerDb.model(
  "PartnerUser",
  partnerUserSchema
);