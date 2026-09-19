import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";

export default function OrderSuccess() {
  const navigate = useNavigate();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    setTimeout(() => setVisible(true), 120);
  }, []);

  return (
    <main
      style={{
        ...styles.page,
        opacity: visible ? 1 : 0,
        transform: visible ? "translateY(0)" : "translateY(12px)",
        transition: "all 0.9s cubic-bezier(0.22,1,0.36,1)",
      }}
    >
      {/* ICON */}
      <div style={styles.iconWrap}>✓</div>

      {/* BRAND */}
      <p style={styles.brand}>KAEORN</p>

      {/* TITLE */}
      <h1 style={styles.title}>Order Confirmed</h1>

      {/* MESSAGE */}
      <p style={styles.text}>
        Thank you for choosing KAEORN.
        <br />
        Your order has been placed successfully and is now being prepared with
        care.
      </p>

      {/* INFO CARD */}
      <div style={styles.card}>
        <p style={styles.cardText}>
          ✨ You will receive an order confirmation email shortly.
        </p>
        <p style={styles.cardText}>
          🚚 Estimated delivery within <strong>3–5 business days</strong>.
        </p>
        <p style={styles.cardText}>
          📦 Your products are packaged with care to preserve quality.
        </p>
      </div>

      {/* ACTION */}
      <button style={styles.button} onClick={() => navigate("/")}>
        Continue Shopping
      </button>
    </main>
  );
}

/* ---------------- STYLES ---------------- */

const styles = {
  page: {
    minHeight: "85vh",
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    alignItems: "center",
    textAlign: "center",
    padding: "40px 20px",
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
  },

  iconWrap: {
    width: "64px",
    height: "64px",
    borderRadius: "50%",
    background: "rgba(0,0,0,0.06)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "28px",
    color: "#111",
    marginBottom: "18px",
  },

  brand: {
    fontSize: "11px",
    letterSpacing: "3px",
    color: "#888",
    marginBottom: "10px",
  },

  title: {
    fontSize: "32px",
    fontWeight: "500",
    marginBottom: "14px",
  },

  text: {
    maxWidth: "520px",
    fontSize: "15px",
    lineHeight: 1.8,
    color: "#555",
    marginBottom: "36px",
  },

  card: {
    background: "#fafafa",
    borderRadius: "18px",
    padding: "22px",
    maxWidth: "520px",
    width: "100%",
    marginBottom: "36px",
  },

  cardText: {
    fontSize: "14px",
    color: "#444",
    marginBottom: "10px",
    lineHeight: 1.6,
  },

  button: {
    padding: "16px 36px",
    borderRadius: "40px",
    border: "none",
    background: "#111",
    color: "#fff",
    fontSize: "15px",
    cursor: "none",
    letterSpacing: "0.4px",
  },
};
