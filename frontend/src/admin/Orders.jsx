import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

export default function Orders() {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchOrders() {
      try {
        const token = localStorage.getItem("adminToken");

        if (!token) {
          alert("Admin session expired. Please login again.");
          navigate("/admin/login");
          return;
        }

        const res = await fetch(`${import.meta.env.VITE_API_BASE}/api/orders`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.message || "Failed to load orders");
        }

        const data = await res.json();
        setOrders(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error("Orders fetch error:", err);
        alert("Unable to load orders. Please try again.");
      } finally {
        setLoading(false);
      }
    }

    fetchOrders();
  }, [navigate]);

  if (loading) {
    return <p style={{ padding: 40 }}>Loading orders…</p>;
  }

  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>Orders</h1>

      {orders.length === 0 && <p style={styles.empty}>No orders found</p>}

      {orders.map((order) => (
        <div
          key={order._id}
          onClick={() => navigate(`/admin/orders/${order._id}`)}
          style={styles.card}
        >
          <div>
            <strong style={styles.orderId}>
              Order #{order._id.slice(-6).toUpperCase()}
            </strong>
            <p style={styles.meta}>
              ₹{order.totalAmount} · {order.status}
            </p>
          </div>

          <span style={styles.arrow}>→</span>
        </div>
      ))}
    </div>
  );
}

/* ---------------- STYLES ---------------- */

const styles = {
  page: {
    padding: "48px",
    background: "#f7f7f7",
    minHeight: "100vh",
    fontFamily: "Inter, sans-serif",
  },

  heading: {
    fontSize: "28px",
    marginBottom: "32px",
    fontWeight: "500",
  },

  empty: {
    color: "#777",
    fontSize: "14px",
  },

  card: {
    background: "#fff",
    border: "1px solid #eee",
    borderRadius: "14px",
    padding: "20px 24px",
    marginBottom: "14px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    cursor: "none",
    transition: "all 0.2s ease",
  },

  orderId: {
    fontSize: "15px",
  },

  meta: {
    fontSize: "13px",
    color: "#666",
    marginTop: "6px",
  },

  arrow: {
    fontSize: "20px",
    color: "#999",
  },
};
