import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import Sidebar from "./Sidebar";

export default function OrderView() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [order, setOrder] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("adminToken");

    if (!token) {
      navigate("/admin/login");
      return;
    }

    async function loadOrder() {
      try {
        const res = await fetch(
          `${import.meta.env.VITE_API_BASE}/api/orders/${id}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          },
        );

        if (!res.ok) {
          throw new Error("Failed to load order");
        }

        const data = await res.json();

        // Useful for checking exactly what the backend returns
        console.log("ADMIN SINGLE ORDER:", data);

        setOrder(data);
      } catch (error) {
        console.error("Order load error:", error);
        navigate("/admin/orders");
      } finally {
        setLoading(false);
      }
    }

    loadOrder();
  }, [id, navigate]);

  /* ---------------- LOADING ---------------- */

  if (loading) {
    return <p style={{ padding: "40px" }}>Loading order…</p>;
  }

  /* ---------------- NOT FOUND ---------------- */

  if (!order) {
    return <p style={{ padding: "40px" }}>Order not found</p>;
  }

  /* =========================================================
     CUSTOMER INFORMATION

     email + phone + name live inside order.address
     (confirmed from actual DB documents), so we read
     them from there directly rather than guessing across
     multiple possible top-level fields.
  ========================================================= */

  const address = order.address || {};

  const customerName = address.fullName || "—";

  const customerPhone = address.phone || "—";

  const customerEmail = address.email || order.userEmail || "—";

  /* =========================================================
     DELIVERY ADDRESS
  ========================================================= */

  const addressParts = [
    address.street,
    address.city,
    address.state,
    address.postalCode,
    address.country,
  ].filter(Boolean);

  const addressText = addressParts.length > 0 ? addressParts.join(", ") : "—";

  /* =========================================================
     ORDER ITEMS
  ========================================================= */

  const items = Array.isArray(order.items) ? order.items : [];

  /* =========================================================
     RENDER
  ========================================================= */

  return (
    <div style={styles.layout}>
      <Sidebar />

      <main style={styles.main}>
        {/* BACK BUTTON */}

        <button style={styles.back} onClick={() => navigate(-1)}>
          ← Back to Orders
        </button>

        {/* ORDER HEADING */}

        <h1 style={styles.heading}>
          Order #{order._id.slice(-6).toUpperCase()}
        </h1>

        {/* =================================================
            ORDER STATUS
        ================================================= */}

        <div style={styles.card}>
          <h3 style={styles.label}>ORDER STATUS</h3>

          <p style={styles.status}>{order.status || "Pending"}</p>

          <p style={styles.meta}>
            Created:{" "}
            {order.createdAt ? new Date(order.createdAt).toLocaleString() : "—"}
          </p>
        </div>

        {/* =================================================
            CUSTOMER
        ================================================= */}

        <div style={styles.card}>
          <h3 style={styles.label}>CUSTOMER</h3>

          <p>
            <b>Name:</b> {customerName}
          </p>

          <p>
            <b>Phone:</b> {customerPhone}
          </p>

          <p>
            <b>Email:</b> {customerEmail}
          </p>
        </div>

        {/* =================================================
            DELIVERY ADDRESS
        ================================================= */}

        <div style={styles.card}>
          <h3 style={styles.label}>DELIVERY ADDRESS</h3>

          <p style={styles.address}>
            {address.fullName && (
              <>
                {address.fullName}
                <br />
              </>
            )}

            {address.street && (
              <>
                {address.street}
                <br />
              </>
            )}

            {(address.city || address.state) && (
              <>
                {address.city || ""}
                {address.city && address.state ? ", " : ""}
                {address.state || ""}
                <br />
              </>
            )}

            {address.postalCode && (
              <>
                {address.postalCode}
                <br />
              </>
            )}

            {address.country || ""}
          </p>
        </div>

        {/* =================================================
            ITEMS
        ================================================= */}

        <div style={styles.card}>
          <h3 style={styles.label}>ITEMS</h3>

          {items.length === 0 ? (
            <p style={styles.empty}>No item details available.</p>
          ) : (
            <div>
              {items.map((item, index) => {
                const quantity = Number(item.quantity) || 0;

                const price = Number(item.price) || 0;

                const itemTotal = quantity * price;

                return (
                  <div key={index} style={styles.itemRow}>
                    {/* PRODUCT LEFT SIDE */}

                    <div style={styles.itemLeft}>
                      {item.image ? (
                        <img
                          src={item.image}
                          alt={item.name || "Product"}
                          style={styles.itemImage}
                        />
                      ) : (
                        <div style={styles.imagePlaceholder}>No Image</div>
                      )}

                      <div>
                        <p style={styles.itemName}>
                          {item.name || "Unknown Product"}
                        </p>

                        <p style={styles.itemMeta}>
                          Product ID: {item.productId || "—"}
                        </p>

                        <p style={styles.itemMeta}>Quantity: {quantity}</p>
                      </div>
                    </div>

                    {/* PRODUCT RIGHT SIDE */}

                    <div style={styles.itemRight}>
                      <p style={styles.itemPrice}>
                        ₹{price} × {quantity}
                      </p>

                      <strong>₹{itemTotal}</strong>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* ORDER TOTAL */}

          <div style={styles.totalRow}>
            <strong>Total</strong>

            <strong style={styles.total}>₹{order.totalAmount || 0}</strong>
          </div>
        </div>

        {/* =================================================
            PAYMENT DETAILS
        ================================================= */}

        {order.payment && (
          <div style={styles.card}>
            <h3 style={styles.label}>PAYMENT</h3>

            <p>
              <b>Payment ID:</b> {order.payment.razorpayPaymentId || "—"}
            </p>

            <p>
              <b>Razorpay Order ID:</b> {order.payment.razorpayOrderId || "—"}
            </p>

            <p>
              <b>Status:</b> {order.status || "—"}
            </p>
          </div>
        )}
      </main>
    </div>
  );
}

/* =========================================================
   STYLES
========================================================= */

const styles = {
  layout: {
    display: "flex",
    minHeight: "100vh",
    background: "#fafafa",
    fontFamily: "Inter, sans-serif",
  },

  main: {
    flex: 1,
    padding: "48px",
    maxWidth: "1000px",
  },

  back: {
    background: "none",
    border: "none",
    cursor: "pointer",
    fontSize: "14px",
    marginBottom: "20px",
    color: "#555",
  },

  heading: {
    fontSize: "30px",
    marginBottom: "32px",
  },

  card: {
    background: "#fff",
    borderRadius: "16px",
    padding: "24px",
    marginBottom: "24px",
    border: "1px solid #eee",
  },

  label: {
    fontSize: "12px",
    letterSpacing: "2px",
    color: "#777",
    marginBottom: "16px",
  },

  status: {
    fontSize: "20px",
    fontWeight: "600",
    margin: 0,
  },

  meta: {
    fontSize: "13px",
    color: "#777",
    marginTop: "8px",
  },

  address: {
    lineHeight: "1.7",
    margin: 0,
  },

  empty: {
    color: "#777",
  },

  itemRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "16px 0",
    borderBottom: "1px solid #f0f0f0",
    gap: "20px",
  },

  itemLeft: {
    display: "flex",
    alignItems: "center",
    gap: "16px",
    minWidth: 0,
  },

  itemImage: {
    width: "64px",
    height: "64px",
    objectFit: "cover",
    borderRadius: "10px",
    border: "1px solid #eee",
    flexShrink: 0,
  },

  imagePlaceholder: {
    width: "64px",
    height: "64px",
    borderRadius: "10px",
    border: "1px solid #eee",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "10px",
    color: "#888",
    flexShrink: 0,
  },

  itemName: {
    margin: 0,
    fontWeight: "500",
  },

  itemMeta: {
    margin: "5px 0 0",
    fontSize: "12px",
    color: "#888",
  },

  itemRight: {
    textAlign: "right",
    whiteSpace: "nowrap",
  },

  itemPrice: {
    margin: "0 0 6px",
    fontSize: "13px",
    color: "#666",
  },

  totalRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginTop: "20px",
    paddingTop: "16px",
    borderTop: "2px solid #eee",
  },

  total: {
    fontSize: "22px",
  },
};
