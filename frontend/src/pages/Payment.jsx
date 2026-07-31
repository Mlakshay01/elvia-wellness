import { useNavigate } from "react-router-dom";
import { useCart } from "../context/CartContext";
import { useEffect, useState } from "react";

export default function Payment() {
  const navigate = useNavigate();

  const { cartItems, getCartTotal, clearCart } = useCart();

  const [loading, setLoading] = useState(false);

  const [razorpayLoaded, setRazorpayLoaded] = useState(false);

  const [serverPricing, setServerPricing] = useState(null);

  /* ======================================
     LOCAL CHECKOUT DATA

     These are used only for display /
     sending checkout information.

     They are NOT trusted for payment amount.
  ====================================== */

  let appliedCoupon = null;

  try {
    appliedCoupon = JSON.parse(localStorage.getItem("appliedCoupon") || "null");
  } catch (error) {
    console.error("Invalid appliedCoupon data:", error);
  }

  let address = {};

  try {
    address = JSON.parse(localStorage.getItem("deliveryAddress") || "{}");
  } catch (error) {
    console.error("Invalid delivery address data:", error);
  }

  const frontendSubtotal = Number(getCartTotal()) || 0;

  const couponCode = appliedCoupon?.code
    ? String(appliedCoupon.code).trim().toUpperCase()
    : null;

  /*
    Before backend pricing is loaded,
    we display the local checkout value.

    IMPORTANT:

    This is display-only.

    Razorpay will use the backend
    calculated amount.
  */

  const displayOriginalAmount = serverPricing
    ? serverPricing.originalAmount
    : frontendSubtotal;

  const displayDiscount = serverPricing
    ? serverPricing.discountAmount
    : Math.max(
        Number(
          frontendSubtotal - Number(localStorage.getItem("cartFinalTotal")),
        ) || 0,
        0,
      );

  const displayTotal = serverPricing
    ? serverPricing.totalAmount
    : Math.max(frontendSubtotal - displayDiscount, 0);

  /* ======================================
     LOAD RAZORPAY
  ====================================== */

  useEffect(() => {
    if (typeof window !== "undefined" && window.Razorpay) {
      setRazorpayLoaded(true);
      return;
    }

    const existingScript = document.getElementById("razorpay-script");

    if (existingScript) {
      existingScript.onload = () => setRazorpayLoaded(true);

      existingScript.onerror = () => {
        alert("Failed to load payment system. Please refresh.");
      };

      return;
    }

    const script = document.createElement("script");

    script.id = "razorpay-script";

    script.src = "https://checkout.razorpay.com/v1/checkout.js";

    script.async = true;

    script.onload = () => {
      setRazorpayLoaded(true);
    };

    script.onerror = () => {
      alert("Failed to load payment system. Please refresh.");
    };

    document.body.appendChild(script);
  }, []);

  /* ======================================
     HANDLE PAYMENT
  ====================================== */

  async function handlePay() {
    try {
      if (loading) {
        return;
      }

      if (!razorpayLoaded) {
        alert("Payment system is still loading. Please wait.");

        return;
      }

      if (!cartItems || cartItems.length === 0) {
        alert("Your cart is empty.");

        return;
      }

      if (
        !address.name ||
        !address.phone ||
        !address.address ||
        !address.city ||
        !address.state ||
        !address.pincode
      ) {
        alert("Delivery address is missing. Please go back and complete it.");

        return;
      }

      const token = localStorage.getItem("kaeorn_token");

      if (!token) {
        alert("Please login first.");

        navigate("/login");

        return;
      }

      setLoading(true);

      /* ======================================
         CREATE ORDER

         SEND ONLY:

         - product ID
         - quantity
         - address
         - coupon code

         DO NOT SEND finalTotal as a trusted
         amount.
      ====================================== */

      const orderRes = await fetch(
        `${import.meta.env.VITE_API_BASE}/api/payment/create-order`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",

            Authorization: `Bearer ${token}`,
          },

          body: JSON.stringify({
            cartItems: cartItems.map((item) => ({
              id: item.id || item.productId,

              quantity: Number(item.quantity),
            })),

            address: {
              fullName: address.name,

              email: address.email || "",

              phone: address.phone,

              street: address.address,

              city: address.city,

              state: address.state,

              postalCode: address.pincode,

              country: "India",
            },

            couponCode: couponCode,
          }),
        },
      );

      const orderData = await orderRes.json();

      if (!orderRes.ok || !orderData.success) {
        throw new Error(orderData.message || "Payment initialization failed.");
      }

      /* ======================================
         SERVER PRICING

         THIS IS NOW THE SOURCE OF TRUTH
         FOR WHAT THE CUSTOMER PAYS.
      ====================================== */

      const mongoOrderId = orderData.order?.id;

      const razorpayOrder = orderData.razorpay;

      const serverOriginalAmount = Number(orderData.order?.originalAmount);

      const serverDiscountAmount = Number(orderData.order?.discountAmount);

      const serverTotalAmount = Number(orderData.order?.totalAmount);

      if (
        !mongoOrderId ||
        !razorpayOrder?.id ||
        !Number.isFinite(razorpayOrder.amount) ||
        razorpayOrder.amount <= 0
      ) {
        throw new Error("Invalid payment order response from server.");
      }

      if (
        !Number.isFinite(serverOriginalAmount) ||
        !Number.isFinite(serverDiscountAmount) ||
        !Number.isFinite(serverTotalAmount)
      ) {
        throw new Error("Invalid pricing returned by server.");
      }

      /*
        Verify server's Razorpay amount.

        Razorpay uses paise.
      */

      const expectedPaise = Math.round(serverTotalAmount * 100);

      if (Number(razorpayOrder.amount) !== expectedPaise) {
        throw new Error("Payment amount mismatch. Please try again.");
      }

      /*
        Update UI with backend values.

        This means the displayed total now
        reflects the actual amount that
        Razorpay will charge.
      */

      setServerPricing({
        originalAmount: serverOriginalAmount,

        discountAmount: serverDiscountAmount,

        totalAmount: serverTotalAmount,

        couponCode: orderData.order?.couponCode || null,
      });

      /* ======================================
         OPEN RAZORPAY
      ====================================== */

      const options = {
        key: import.meta.env.VITE_RAZORPAY_KEY_ID,

        /*
          IMPORTANT:

          This amount comes from Razorpay
          order created by backend.

          User cannot reduce it by changing
          localStorage.cartFinalTotal.
        */

        amount: razorpayOrder.amount,

        currency: razorpayOrder.currency || "INR",

        order_id: razorpayOrder.id,

        name: "KAEORN",

        description: "Secure Luxury Checkout",

        prefill: {
          name: address.name,

          email: address.email || "",

          contact: address.phone,
        },

        notes: {
          orderId: String(mongoOrderId),

          couponCode: couponCode || "",
        },

        theme: {
          color: "#141210",
        },

        handler: async function (response) {
          try {
            /* ==================================
                 VERIFY PAYMENT

                 The backend finds the existing
                 order by Razorpay Order ID +
                 authenticated User ID.
              ================================== */

            const verifyRes = await fetch(
              `${import.meta.env.VITE_API_BASE}/api/payment/verify`,
              {
                method: "POST",

                headers: {
                  "Content-Type": "application/json",

                  Authorization: `Bearer ${token}`,
                },

                body: JSON.stringify({
                  razorpay_order_id: response.razorpay_order_id,

                  razorpay_payment_id: response.razorpay_payment_id,

                  razorpay_signature: response.razorpay_signature,
                }),
              },
            );

            const verifyData = await verifyRes.json();

            if (!verifyRes.ok || !verifyData.success) {
              throw new Error(
                verifyData.message || "Payment verification failed.",
              );
            }

            /* ==============================
                 SUCCESS
              ============================== */

            clearCart();

            localStorage.removeItem("deliveryAddress");

            localStorage.removeItem("cartFinalTotal");

            localStorage.removeItem("appliedCoupon");

            navigate("/success");
          } catch (err) {
            console.error("Post-payment error:", err);

            alert(
              `Payment completed, but order verification failed.\n\n${err.message}`,
            );

            setLoading(false);
          }
        },

        modal: {
          ondismiss: function () {
            setLoading(false);
          },
        },
      };

      const rzp = new window.Razorpay(options);

      rzp.on("payment.failed", function (response) {
        console.error("Razorpay payment failed:", response.error);

        alert(
          response.error?.description || "Payment failed. Please try again.",
        );

        setLoading(false);
      });

      rzp.open();
    } catch (err) {
      console.error("Payment initialization error:", err);

      alert(err.message || "Unable to start payment.");

      setLoading(false);
    }
  }

  return (
    <div style={styles.page}>
      <Steps current={2} />

      <h1 style={styles.heading}>Confirm &amp; Pay</h1>

      <p style={styles.subtext}>
        Review your order details below, then complete payment securely via
        Razorpay.
      </p>

      {/* DELIVERY ADDRESS */}

      <div style={styles.card}>
        <div style={styles.cardHeader}>
          <span style={styles.cardLabel}>Delivering to</span>

          <span
            style={styles.editLink}
            onClick={() => navigate("/checkout/address")}
          >
            Change
          </span>
        </div>

        <p style={styles.addressName}>{address.name}</p>

        <p style={styles.addressLine}>{address.address}</p>

        <p style={styles.addressLine}>
          {address.city}, {address.state} &ndash; {address.pincode}
        </p>

        <p style={styles.addressPhone}>{address.phone}</p>

        {address.email && <p style={styles.addressPhone}>{address.email}</p>}
      </div>

      {/* ORDER ITEMS */}

      <div style={styles.card}>
        <span style={styles.cardLabel}>
          Order &middot; {cartItems?.length || 0}{" "}
          {cartItems?.length === 1 ? "item" : "items"}
        </span>

        <div style={styles.itemList}>
          {cartItems?.map((item, i) => (
            <div key={`${item.id || item.productId}-${i}`} style={styles.item}>
              {item.image && (
                <img
                  src={item.image}
                  alt={item.name}
                  style={styles.itemImage}
                />
              )}

              <div style={styles.itemInfo}>
                <p style={styles.itemName}>{item.name}</p>

                <p style={styles.itemQty}>Qty {item.quantity}</p>
              </div>

              <p style={styles.itemPrice}>
                ₹{Number(item.price) * Number(item.quantity)}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* ORDER SUMMARY */}

      <div style={styles.card}>
        <div style={styles.summaryRow}>
          <span style={styles.summaryLabel}>Subtotal</span>

          <span style={styles.summaryValue}>₹{displayOriginalAmount}</span>
        </div>

        {displayDiscount > 0 && (
          <div style={styles.summaryRow}>
            <span style={styles.summaryLabel}>
              Discount {couponCode ? `(${couponCode})` : ""}
            </span>

            <span style={styles.discountValue}>
              &minus;₹
              {displayDiscount}
            </span>
          </div>
        )}

        {couponCode && displayDiscount === 0 && (
          <div style={styles.summaryRow}>
            <span style={styles.summaryLabel}>Coupon</span>

            <span style={styles.couponValue}>{couponCode}</span>
          </div>
        )}

        <div style={styles.divider} />

        <div style={styles.summaryRow}>
          <span style={styles.totalLabel}>Total</span>

          <span style={styles.totalValue}>₹{displayTotal}</span>
        </div>
      </div>

      <button
        onClick={handlePay}
        disabled={loading}
        style={{
          ...styles.button,
          opacity: loading ? 0.6 : 1,
        }}
      >
        {loading ? (
          <span style={styles.buttonContent}>
            <span style={styles.spinner} />
            Processing...
          </span>
        ) : (
          `Pay ₹${displayTotal}`
        )}
      </button>

      <p style={styles.securityNote}>
        🔒 Payments secured &amp; encrypted by Razorpay
      </p>
    </div>
  );
}

function Steps({ current }) {
  const items = ["Address", "Payment"];

  return (
    <div style={styles.steps}>
      {items.map((label, i) => {
        const step = i + 1;

        const active = step === current;

        const done = step < current;

        return (
          <div key={label} style={styles.stepItem}>
            <div
              style={{
                ...styles.stepDot,
                ...(active ? styles.stepDotActive : {}),
                ...(done ? styles.stepDotDone : {}),
              }}
            >
              {done ? "✓" : step}
            </div>

            <span
              style={{
                ...styles.stepLabel,
                ...(active ? styles.stepLabelActive : {}),
              }}
            >
              {label}
            </span>

            {step !== items.length && <span style={styles.stepRule} />}
          </div>
        );
      })}
    </div>
  );
}

/* ======================================
   STYLES
====================================== */

const GOLD = "#B08D57";

const INK = "#141210";

const HAIRLINE = "#E7E1D6";

const MUTED = "#8A8177";

const styles = {
  page: {
    maxWidth: "560px",
    margin: "0 auto",
    padding: "48px 20px 80px",
    fontFamily: "'DM Sans', sans-serif",
    color: INK,
  },

  steps: {
    display: "flex",
    alignItems: "center",
    marginBottom: "40px",
  },

  stepItem: {
    display: "flex",
    alignItems: "center",
  },

  stepDot: {
    width: 26,
    height: 26,
    borderRadius: "50%",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: HAIRLINE,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 12,
    color: MUTED,
    background: "#fff",
    marginRight: 8,
  },

  stepDotActive: {
    borderColor: INK,
    color: INK,
    fontWeight: 600,
  },

  stepDotDone: {
    background: GOLD,
    borderColor: GOLD,
    color: "#fff",
  },

  stepLabel: {
    fontSize: 13,
    color: MUTED,
    marginRight: 16,
  },

  stepLabelActive: {
    color: INK,
    fontWeight: 600,
  },

  stepRule: {
    width: 32,
    height: 1,
    background: HAIRLINE,
    marginRight: 16,
  },

  heading: {
    fontFamily: "'Playfair Display', serif",
    fontSize: "32px",
    fontWeight: 500,
    marginBottom: "10px",
  },

  subtext: {
    fontSize: "14px",
    color: MUTED,
    marginBottom: "28px",
    lineHeight: 1.7,
  },

  card: {
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: HAIRLINE,
    borderRadius: "16px",
    padding: "20px 22px",
    marginBottom: "16px",
    background: "#fff",
  },

  cardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "10px",
  },

  cardLabel: {
    fontSize: "11px",
    letterSpacing: "0.06em",
    textTransform: "uppercase",
    color: MUTED,
  },

  editLink: {
    fontSize: "12px",
    color: INK,
    textDecoration: "underline",
    cursor: "pointer",
  },

  addressName: {
    fontWeight: 600,
    fontSize: 14,
    margin: "0 0 4px",
  },

  addressLine: {
    fontSize: 13,
    color: MUTED,
    margin: 0,
    lineHeight: 1.6,
  },

  addressPhone: {
    fontSize: 13,
    color: MUTED,
    marginTop: 4,
  },

  itemList: {
    marginTop: "14px",
    display: "flex",
    flexDirection: "column",
    gap: "14px",
  },

  item: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
  },

  itemImage: {
    width: 48,
    height: 48,
    borderRadius: "10px",
    objectFit: "cover",
    borderWidth: "1px",
    borderStyle: "solid",
    borderColor: HAIRLINE,
  },

  itemInfo: {
    flex: 1,
  },

  itemName: {
    fontSize: 14,
    fontWeight: 500,
    margin: 0,
  },

  itemQty: {
    fontSize: 12,
    color: MUTED,
    margin: "2px 0 0",
  },

  itemPrice: {
    fontSize: 14,
    fontWeight: 500,
  },

  summaryRow: {
    display: "flex",
    justifyContent: "space-between",
    fontSize: "13.5px",
    marginBottom: "10px",
  },

  summaryLabel: {
    color: MUTED,
  },

  summaryValue: {
    color: INK,
  },

  discountValue: {
    color: "#5E7A5B",
  },

  couponValue: {
    color: GOLD,
    fontWeight: 600,
  },

  divider: {
    height: 1,
    background: HAIRLINE,
    margin: "6px 0 12px",
  },

  totalLabel: {
    fontFamily: "'Playfair Display', serif",
    fontSize: 18,
    fontWeight: 600,
  },

  totalValue: {
    fontFamily: "'Playfair Display', serif",
    fontSize: 18,
    fontWeight: 600,
  },

  button: {
    width: "100%",
    padding: "18px",
    borderRadius: "40px",
    border: "none",
    background: INK,
    color: "#fff",
    cursor: "pointer",
    fontSize: "15px",
    letterSpacing: "0.02em",
    marginTop: "8px",
  },

  buttonContent: {
    display: "inline-flex",
    alignItems: "center",
    gap: "10px",
  },

  spinner: {
    width: 14,
    height: 14,
    borderRadius: "50%",
    borderWidth: "2px",
    borderStyle: "solid",
    borderColor: "rgba(255,255,255,0.35)",
    borderTopColor: "#fff",
    display: "inline-block",
    animation: "kaeorn-spin 0.7s linear infinite",
  },

  securityNote: {
    textAlign: "center",
    fontSize: "12px",
    color: MUTED,
    marginTop: "14px",
  },
};

/* ======================================
   SPINNER ANIMATION
====================================== */

if (
  typeof document !== "undefined" &&
  !document.getElementById("kaeorn-spin-kf")
) {
  const styleTag = document.createElement("style");

  styleTag.id = "kaeorn-spin-kf";

  styleTag.textContent =
    "@keyframes kaeorn-spin { to { transform: rotate(360deg); } }";

  document.head.appendChild(styleTag);
}
