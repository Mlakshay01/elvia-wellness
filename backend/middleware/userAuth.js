const jwt = require("jsonwebtoken");
const User = require("../models/User");

module.exports = async function userAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    /*
      Checkout/payment routes require authentication.

      If there is no token, reject the request.
      This prevents orders from being created without
      a valid user ID and fixes the "My Orders" issue.
    */

    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        success: false,
        message: "Authentication required. Please login.",
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is missing.",
      });
    }

    /*
      VERIFY JWT
    */

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (!decoded || !decoded.id) {
      return res.status(401).json({
        success: false,
        message: "Invalid authentication token.",
      });
    }

    /*
      FETCH REAL USER FROM DATABASE

      This is important.

      We do not blindly trust the JWT payload.
      We fetch the actual current user.

      req.user._id
      req.user.email
    */

    const user = await User.findById(
      decoded.id
    ).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User account no longer exists.",
      });
    }

    /*
      ATTACH AUTHENTICATED USER
    */

    req.user = user;

    req.userId = user._id;

    req.userEmail = user.email
      ? String(user.email)
          .trim()
          .toLowerCase()
      : null;

    next();
  } catch (err) {
    console.error(
      "❌ Authentication error:",
      err.message
    );

    /*
      Invalid / expired JWT
    */

    if (
      err.name === "JsonWebTokenError" ||
      err.name === "TokenExpiredError"
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Your session has expired. Please login again.",
      });
    }

    return res.status(500).json({
      success: false,
      message:
        "Authentication service error.",
    });
  }
};