const mongoose = require("mongoose");

const partnerDb = mongoose.createConnection(process.env.PARTNER_MONGO_URI, {
  serverSelectionTimeoutMS: 10000,
});

partnerDb.on("connected", () => {
  console.log("✅ Partner MongoDB connected");
});

partnerDb.on("error", (err) => {
  console.error("❌ Partner MongoDB Error:", err);
  console.log("PARTNER_MONGO_URI =", process.env.PARTNER_MONGO_URI);
});

module.exports = partnerDb;