import { useNavigate } from "react-router-dom";
import { useCart } from "../context/CartContext";

export default function Cart() {
  const navigate = useNavigate();
  const {
    cartItems,
    increaseQty,
    decreaseQty,
    removeFromCart,
    getCartTotal,
  } = useCart();

  /* ---------------- EMPTY CART ---------------- */
  if (!cartItems || cartItems.length === 0) {
    return (
      <div style={styles.emptyPage}>
        <h2 style={styles.emptyTitle}>Your cart is empty</h2>
        <p style={styles.emptyText}>
          Discover refined skincare crafted for modern elegance.
        </p>
        <button
          style={styles.backBtn}
          onClick={() => navigate("/")}
        >
          Continue Shopping
        </button>
      </div>
    );
  }

  /* ---------------- CART UI ---------------- */
  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>Your Cart</h1>

      {/* ITEMS */}
      <div style={styles.itemsWrap}>
        {cartItems.map((item) => (
          <div key={item.id} style={styles.card}>
            <img
              src={item.image}
              alt={item.name}
              style={styles.image}
            />

            <div style={styles.details}>
              <p style={styles.category}>SUN PROTECTION</p>
              <h2 style={styles.title}>{item.name}</h2>
              <p style={styles.price}>₹{item.price}</p>

              {/* QUANTITY */}
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

            <p style={styles.itemTotal}>
              ₹{item.price * item.quantity}
            </p>
          </div>
        ))}
      </div>

      {/* OFFER CODE */}
      <div style={styles.offerBox}>
        <input
          placeholder="Enter offer code"
          style={styles.offerInput}
        />
        <button style={styles.applyBtn}>Apply</button>
      </div>

      {/* SUMMARY */}
      <div style={styles.summary}>
        <div style={styles.row}>
          <span>Subtotal</span>
          <span>₹{getCartTotal()}</span>
        </div>

        <div style={styles.row}>
          <span>Delivery</span>
          <span>Free</span>
        </div>

        <div style={styles.totalRow}>
          <span>Total</span>
          <span>₹{getCartTotal()}</span>
        </div>
      </div>

      {/* CHECKOUT */}
      <button
        style={styles.checkoutBtn}
        onClick={() => navigate("/checkout/address")}
      >
        Proceed to Checkout
      </button>

      <p style={styles.checkoutNote}>
        Free shipping · Secure checkout · Easy returns
      </p>
    </div>
  );
}

/* ---------------- STYLES ---------------- */

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

  /* EMPTY CART */
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

  /* ITEMS */
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

  /* OFFER */
  offerBox: {
    display: "flex",
    gap: "12px",
    marginTop: "36px",
    marginBottom: "36px",
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

  /* SUMMARY */
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

  /* CHECKOUT */
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
