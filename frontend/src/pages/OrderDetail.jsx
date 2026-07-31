import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import OrderTimeline from "../components/OrderTimeline";
import { useCart } from "../context/CartContext";

const STATUS_COPY = {
  Pending: "We’ve received your order and are preparing it with care.",
  Shipped: "Your order has left our facility and is on its way to you.",
  "Out for Delivery": "Your order is out for delivery and will reach you soon.",
  Delivered: "Your order has been delivered. We hope you love it.",
};

export default function OrderDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { setCart } = useCart();

  const [order, setOrder] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem("kaeorn_token");

    fetch(`${import.meta.env.VITE_API_BASE}/api/orders/my-orders/${id}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => res.json())
      .then(setOrder);
  }, [id]);

  if (!order) {
    return <p style={{ textAlign: "center" }}>Loading order…</p>;
  }

  function handleReorder() {
    const items = order.items.map((item) => ({
      id: item.productId || item.id,
      name: item.name,
      price: item.price,
      quantity: item.quantity,
      image: item.image,
    }));

    setCart(items);
    navigate("/cart");
  }

  return (
    <div style={styles.page}>
      <h2 style={styles.heading}>Order #{order._id.slice(-6).toUpperCase()}</h2>

      {/* TRACKING HEADER */}
      <div style={styles.trackingCard}>
        <h3 style={styles.statusTitle}>{order.status}</h3>
        <p style={styles.statusText}>{STATUS_COPY[order.status]}</p>

        <p style={styles.eta}>
          Estimated delivery: <b>3–5 business days</b>
        </p>
      </div>

      {/* TIMELINE */}
      <OrderTimeline status={order.status} />

      {/* ITEMS */}
      <div style={styles.card}>
        <h3 style={styles.section}>Items</h3>
        {order.items.map((item, i) => (
          <p key={i}>
            {item.name} × {item.quantity}
          </p>
        ))}
        <h3 style={styles.total}>Total ₹{order.totalAmount}</h3>
      </div>

      {/* ADDRESS */}
      <div style={styles.card}>
        <h3 style={styles.section}>Delivery Address</h3>
        <p>
          {order.address.fullName}
          <br />
          {order.address.street}
          <br />
          {order.address.city}, {order.address.state} –{" "}
          {order.address.postalCode}
        </p>
      </div>

      {/* ACTIONS */}
      <div style={styles.actions}>
        <button style={styles.primaryBtn} onClick={handleReorder}>
          Re-order
        </button>

        <button style={styles.secondaryBtn} onClick={() => navigate("/")}>
          Continue Shopping
        </button>
      </div>

      {/* TRUST COPY */}
      <p style={styles.trustText}>
        Need help? Reach out to us anytime — we’re here to help.
      </p>
    </div>
  );
}

/* ---------------- STYLES ---------------- */

const styles = {
  page: {
    maxWidth: 720,
    margin: "48px auto",
    padding: 20,
  },
  heading: {
    marginBottom: 24,
  },
  trackingCard: {
    background: "#fff",
    border: "1px solid #eee",
    borderRadius: 16,
    padding: 24,
    marginBottom: 28,
  },
  statusTitle: {
    fontSize: 18,
    marginBottom: 6,
  },
  statusText: {
    fontSize: 14,
    color: "#555",
    lineHeight: 1.6,
  },
  eta: {
    marginTop: 12,
    fontSize: 13,
    color: "#333",
  },
  card: {
    background: "#fff",
    border: "1px solid #eee",
    borderRadius: 16,
    padding: 24,
    marginBottom: 24,
  },
  section: {
    fontSize: 13,
    letterSpacing: "1.5px",
    color: "#777",
    marginBottom: 12,
  },
  total: {
    marginTop: 16,
    fontSize: 20,
  },
  actions: {
    display: "flex",
    gap: 16,
    marginTop: 32,
    flexWrap: "wrap",
  },
  primaryBtn: {
    flex: 1,
    padding: "16px",
    borderRadius: 40,
    border: "none",
    background: "#111",
    color: "#fff",
    cursor: "pointer",
  },
  secondaryBtn: {
    flex: 1,
    padding: "16px",
    borderRadius: 40,
    border: "1px solid #111",
    background: "transparent",
    cursor: "pointer",
  },
  trustText: {
    marginTop: 32,
    fontSize: 13,
    color: "#666",
    textAlign: "center",
  },
};
