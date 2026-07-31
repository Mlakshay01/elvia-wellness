import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useCart } from "../context/CartContext";
import PageLoader from "../components/PageLoader";

export default function Cart() {
  const navigate = useNavigate();

  const {
    cartItems,
    increaseQty,
    decreaseQty,
    removeFromCart,
    getCartTotal,

    // Coupon state from CartContext
    // NOTE: context now exposes this key directly as `appliedCoupon`,
    // so no renaming/aliasing is needed here anymore.
    appliedCoupon,
    applyCoupon: saveCoupon,
    removeCoupon: clearCoupon,
  } = useCart();

  const [navigating, setNavigating] = useState(false);

  // Input field only
  const [couponCode, setCouponCode] = useState("");

  // Validation status
  const [couponStatus, setCouponStatus] = useState(null);

  /* =========================================================
     RESTORE COUPON ON PAGE LOAD
     ========================================================= */

  useEffect(() => {
    if (appliedCoupon?.code) {
      setCouponCode(appliedCoupon.code);
      setCouponStatus("valid");
    }
  }, [appliedCoupon]);

  /* =========================================================
     VALIDATE COUPON WITH INFLUENCER API
     ========================================================= */

  async function applyCouponByCode(code) {
    const cleanCode = code?.trim().toUpperCase();

    if (!cleanCode) {
      setCouponStatus("invalid");
      return;
    }

    setCouponStatus("loading");

    try {
      const res = await fetch(
        `${import.meta.env.VITE_INFLUENCER_API}/api/coupon/validate/${encodeURIComponent(
          cleanCode,
        )}`,
      );

      const data = await res.json();

      if (!data.success || !data.data) {
        setCouponStatus("invalid");

        // Clear old coupon if user tries invalid coupon
        clearCoupon();

        return;
      }

      const coupon = data.data;

      /*
        IMPORTANT:

        Store the validated coupon in CartContext.

        Your influencer API returns:
          discountPercent
          influencerName

        CartContext's applyCoupon() normalizes either
        { discountType, discountValue } or { discountPercent }
        into the same canonical shape, so we can pass
        discountPercent straight through.
      */

      const couponToSave = {
        code: cleanCode,

        discountType: "percentage",

        discountValue: Number(coupon.discountPercent || 0),

        // Keep influencer information
        // for commission tracking later.
        influencerName: coupon.influencerName || null,
      };

      saveCoupon(couponToSave);

      setCouponCode(cleanCode);
      setCouponStatus("valid");
    } catch (error) {
      console.error("Coupon validation error:", error);

      setCouponStatus("invalid");
    }
  }

  /* =========================================================
     APPLY BUTTON
     ========================================================= */

  function handleApplyCoupon() {
    applyCouponByCode(couponCode);
  }

  /* =========================================================
     REMOVE COUPON
     ========================================================= */

  function handleRemoveCoupon() {
    setCouponCode("");
    setCouponStatus(null);

    // Remove from CartContext
    clearCoupon();
  }

  /* =========================================================
     AUTO-APPLY COUPON

     Supports:
       /cart?coupon=ABC123

     and:
       localStorage.pendingCoupon
  ========================================================= */

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);

    const couponFromUrl = params.get("coupon");

    const pendingCoupon = localStorage.getItem("pendingCoupon");

    const codeToApply = couponFromUrl || pendingCoupon;

    if (codeToApply) {
      applyCouponByCode(codeToApply);

      localStorage.removeItem("pendingCoupon");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* =========================================================
     PRICING

     Uses appliedCoupon.discountType / discountValue, which
     now matches exactly what CartContext stores and what
     getCouponDiscount()/getFinalTotal() compute internally.
  ========================================================= */

  const originalAmount = getCartTotal();

  const discountPercent =
    appliedCoupon?.discountType === "percentage"
      ? Number(appliedCoupon.discountValue || 0)
      : 0;

  const discount =
    appliedCoupon?.discountType === "percentage"
      ? Math.round((originalAmount * discountPercent) / 100)
      : appliedCoupon?.discountType === "fixed"
        ? Math.min(Number(appliedCoupon.discountValue || 0), originalAmount)
        : 0;

  const finalTotal = Math.max(originalAmount - discount, 0);

  /* =========================================================
     LOADING
  ========================================================= */

  if (navigating) {
    return <PageLoader />;
  }

  /* =========================================================
     EMPTY CART
  ========================================================= */

  if (!cartItems || cartItems.length === 0) {
    return (
      <div style={styles.emptyPage}>
        <h2 style={styles.emptyTitle}>Your cart is empty</h2>

        <p style={styles.emptyText}>
          Discover refined skincare crafted for modern elegance.
        </p>

        <button style={styles.backBtn} onClick={() => navigate("/")}>
          Continue Shopping
        </button>
      </div>
    );
  }

  /* =========================================================
     CART UI
  ========================================================= */

  return (
    <>
      <Helmet>
        <title>Your Cart | KAEORN</title>

        <meta
          name="description"
          content="Review your selected KAEORN perfumes and proceed to checkout securely."
        />
      </Helmet>

      <div style={styles.page}>
        <h1 style={styles.heading}>Your Cart</h1>

        {/* =================================================
            ITEMS
        ================================================= */}

        <div style={styles.itemsWrap}>
          {cartItems.map((item) => (
            <div key={item.id} style={styles.card}>
              <img src={item.image} alt={item.name} style={styles.image} />

              <div style={styles.details}>
                <p style={styles.category}>EAU DE PARFUM</p>

                <h2 style={styles.title}>{item.name}</h2>

                <p style={styles.price}>₹{item.price}</p>

                <div style={styles.qtyRow}>
                  <button
                    style={styles.qtyBtn}
                    onClick={() => decreaseQty(item.id)}
                  >
                    −
                  </button>

                  <span style={styles.qty}>{item.quantity}</span>

                  <button
                    style={styles.qtyBtn}
                    onClick={() => increaseQty(item.id)}
                  >
                    +
                  </button>
                </div>

                <button
                  style={styles.removeBtn}
                  onClick={() => removeFromCart(item.id)}
                >
                  Remove
                </button>
              </div>

              <p style={styles.itemTotal}>₹{item.price * item.quantity}</p>
            </div>
          ))}
        </div>

        {/* =================================================
            COUPON
        ================================================= */}

        <div style={styles.offerBox} onClick={(e) => e.stopPropagation()}>
          <input
            placeholder="Enter influencer / offer code"
            style={styles.offerInput}
            value={couponCode}
            onChange={(e) => setCouponCode(e.target.value.toUpperCase())}
            disabled={couponStatus === "valid" || couponStatus === "loading"}
            onKeyDown={(e) => {
              e.stopPropagation();

              if (e.key === "Enter" && couponStatus !== "loading") {
                handleApplyCoupon();
              }
            }}
            onClick={(e) => e.stopPropagation()}
          />

          {couponStatus === "valid" ? (
            <button
              style={{
                ...styles.applyBtn,
                background: "#c00",
              }}
              onClick={(e) => {
                e.stopPropagation();
                handleRemoveCoupon();
              }}
            >
              Remove
            </button>
          ) : (
            <button
              style={styles.applyBtn}
              onClick={(e) => {
                e.stopPropagation();
                handleApplyCoupon();
              }}
              disabled={couponStatus === "loading"}
            >
              {couponStatus === "loading" ? "..." : "Apply"}
            </button>
          )}
        </div>

        {/* =================================================
            COUPON SUCCESS
        ================================================= */}

        {couponStatus === "valid" && appliedCoupon && (
          <div style={styles.couponSuccess}>
            ✓ Code <strong>{appliedCoupon.code}</strong> applied —{" "}
            {discountPercent}% off
            {appliedCoupon.influencerName
              ? ` via ${appliedCoupon.influencerName}`
              : ""}
          </div>
        )}

        {/* =================================================
            COUPON ERROR
        ================================================= */}

        {couponStatus === "invalid" && (
          <div style={styles.couponError}>✗ Invalid or expired coupon code</div>
        )}

        {/* =================================================
            SUMMARY
        ================================================= */}

        <div style={styles.summary}>
          {/* ORIGINAL AMOUNT */}

          <div style={styles.row}>
            <span>Subtotal</span>

            <span>₹{originalAmount}</span>
          </div>

          {/* COUPON DISCOUNT */}

          {discount > 0 && (
            <div
              style={{
                ...styles.row,
                color: "#166534",
              }}
            >
              <span>Discount ({discountPercent}%)</span>

              <span>−₹{discount}</span>
            </div>
          )}

          {/* DELIVERY */}

          <div style={styles.row}>
            <span>Delivery</span>

            <span>Free</span>
          </div>

          {/* FINAL TOTAL */}

          <div style={styles.totalRow}>
            <span>Total</span>

            <span>₹{finalTotal}</span>
          </div>
        </div>

        {/* =================================================
            CHECKOUT
        ================================================= */}

        <button
          style={styles.checkoutBtn}
          onClick={() => {
            setNavigating(true);

            /*
              These values are only for
              temporary frontend convenience.

              IMPORTANT:
              The backend should NOT trust
              cartFinalTotal.

              The backend will validate:
                - Product IDs
                - Product prices
                - Quantities
                - Coupon
                - Final amount

              before creating Razorpay order.
            */

            localStorage.setItem("cartFinalTotal", String(finalTotal));

            localStorage.setItem("cartOriginalTotal", String(originalAmount));

            localStorage.setItem("cartDiscount", String(discount));

            if (appliedCoupon) {
              localStorage.setItem("cartCoupon", JSON.stringify(appliedCoupon));
            } else {
              localStorage.removeItem("cartCoupon");
            }

            setTimeout(() => {
              navigate("/checkout/address");
            }, 300);
          }}
        >
          Proceed to Checkout
        </button>

        <p style={styles.checkoutNote}>
          Free shipping · Secure checkout · Easy returns
        </p>
      </div>
    </>
  );
}

/* =========================================================
   STYLES
========================================================= */

const styles = {
  page: {
    maxWidth: "1000px",
    margin: "20px auto",
    padding: "80px 45px",
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
  },

  heading: {
    fontSize: "30px",
    fontWeight: "500",
    marginBottom: "36px",
  },

  emptyPage: {
    minHeight: "70vh",
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    alignItems: "center",
    textAlign: "center",
    padding: "40px 20px",
  },

  emptyTitle: {
    fontSize: "26px",
    marginBottom: "12px",
  },

  emptyText: {
    color: "#666",
    marginBottom: "24px",
  },

  backBtn: {
    padding: "14px 28px",
    borderRadius: "40px",
    border: "none",
    background: "#111",
    color: "#fff",
    fontSize: "15px",
    cursor: "pointer",
  },

  itemsWrap: {
    display: "flex",
    flexDirection: "column",
    gap: "28px",
  },

  card: {
    display: "flex",
    gap: "24px",
    alignItems: "center",
    borderBottom: "1px solid #eee",
    paddingBottom: "24px",
    flexWrap: "wrap",
  },

  image: {
    width: "120px",
    height: "140px",
    borderRadius: "14px",
    objectFit: "cover",
  },

  details: {
    flex: 1,
    minWidth: "220px",
  },

  category: {
    fontSize: "11px",
    letterSpacing: "2px",
    color: "#888",
    marginBottom: "6px",
  },

  title: {
    fontSize: "18px",
    marginBottom: "6px",
  },

  price: {
    color: "#555",
    marginBottom: "14px",
  },

  qtyRow: {
    display: "flex",
    alignItems: "center",
    gap: "14px",
    marginBottom: "10px",
  },

  qtyBtn: {
    width: "32px",
    height: "32px",
    borderRadius: "50%",
    border: "1px solid #ccc",
    background: "white",
    cursor: "pointer",
    fontSize: "18px",
    lineHeight: "0",
  },

  qty: {
    minWidth: "20px",
    textAlign: "center",
    fontSize: "14px",
  },

  removeBtn: {
    border: "none",
    background: "none",
    color: "#999",
    fontSize: "13px",
    cursor: "pointer",
    padding: 0,
  },

  itemTotal: {
    fontSize: "16px",
    fontWeight: "500",
    minWidth: "80px",
    textAlign: "right",
  },

  offerBox: {
    display: "flex",
    gap: "12px",
    marginTop: "36px",
    marginBottom: "16px",
    flexWrap: "wrap",
  },

  offerInput: {
    flex: 1,
    minWidth: "220px",
    padding: "14px",
    borderRadius: "10px",
    border: "1px solid #ccc",
    fontSize: "14px",
  },

  applyBtn: {
    padding: "14px 24px",
    borderRadius: "10px",
    border: "none",
    background: "#111",
    color: "white",
    cursor: "pointer",
    fontSize: "14px",
  },

  couponSuccess: {
    background: "#f0fdf0",
    border: "1px solid #bbf7d0",
    borderRadius: 10,
    padding: "12px 16px",
    marginBottom: 16,
    fontSize: 13,
    color: "#166534",
  },

  couponError: {
    background: "#fff5f5",
    border: "1px solid #fecaca",
    borderRadius: 10,
    padding: "12px 16px",
    marginBottom: 16,
    fontSize: 13,
    color: "#c00",
  },

  summary: {
    borderTop: "1px solid #eee",
    paddingTop: "24px",
    marginBottom: "36px",
  },

  row: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: "12px",
    color: "#555",
  },

  totalRow: {
    display: "flex",
    justifyContent: "space-between",
    fontSize: "18px",
    fontWeight: "500",
  },

  checkoutBtn: {
    width: "100%",
    padding: "18px",
    borderRadius: "40px",
    border: "none",
    background: "#111",
    color: "white",
    fontSize: "16px",
    cursor: "pointer",
  },

  checkoutNote: {
    marginTop: "14px",
    fontSize: "13px",
    color: "#777",
    textAlign: "center",
  },
};
