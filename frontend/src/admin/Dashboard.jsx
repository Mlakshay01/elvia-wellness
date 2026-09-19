import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import AdminLayout from "./AdminLayout";

export default function Dashboard() {
  const navigate = useNavigate();

  const [stats, setStats] = useState({
    totalOrders: 0,
    totalRevenue: 0,
    pending: 0,
    inTransit: 0,
    delivered: 0,
  });

  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
  }, []);

  async function loadStats() {
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
        throw new Error(err.message || "Admin only");
      }

      const data = await res.json();
      setOrders(data);

      let revenue = 0;
      let pending = 0;
      let delivered = 0;
      let inTransit = 0;

      data.forEach((order) => {
        revenue += order.totalAmount || 0;

        if (order.status === "Pending") pending++;
        if (order.status === "Delivered") delivered++;
        if (order.status === "Shipped" || order.status === "Out for Delivery") {
          inTransit++;
        }
      });

      setStats({
        totalOrders: data.length,
        totalRevenue: revenue,
        pending,
        delivered,
        inTransit,
      });
    } catch (err) {
      console.error("Dashboard error:", err);
      alert("Admin access denied or session expired");
      navigate("/admin/login");
    } finally {
      setLoading(false);
    }
  }

  // ✅ FIXED: single source of truth
  function getCustomerEmail(order) {
    return (
      order.customerEmail || order.address?.email || order.user?.email || "N/A"
    );
  }

  if (loading) {
    return (
      <AdminLayout>
        <p style={{ padding: 40 }}>Loading dashboard…</p>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout>
      <div style={styles.page}>
        {/* HEADER */}
        <div style={styles.headerRow}>
          <div>
            <h1 style={styles.heading}>Dashboard</h1>
            <p style={styles.subheading}>Business overview</p>
          </div>

          <button
            onClick={() => navigate("/admin/chats")}
            style={styles.chatBtn}
          >
            Support Chats
          </button>
        </div>

        {/* STATS */}
        <div style={styles.grid}>
          <Card title="Total Orders" value={stats.totalOrders} />
          <Card title="Revenue" value={`₹${stats.totalRevenue}`} />
          <Card title="Pending Orders" value={stats.pending} />
          <Card title="In Transit" value={stats.inTransit} />
          <Card title="Delivered" value={stats.delivered} />
        </div>

        {/* RECENT ORDERS */}
        <h3 style={styles.sectionTitle}>Recent Orders</h3>

        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th>Order ID</th>
                <th>Customer Email</th>
                <th>Amount</th>
                <th>Status</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {orders.slice(0, 10).map((order) => (
                <tr key={order._id}>
                  <td>{order._id.slice(-6)}</td>
                  <td>{getCustomerEmail(order)}</td>
                  <td>₹{order.totalAmount}</td>
                  <td>{order.status}</td>
                  <td>{new Date(order.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AdminLayout>
  );
}

/* ---------------- COMPONENTS ---------------- */

function Card({ title, value }) {
  return (
    <div style={styles.card}>
      <p style={styles.cardTitle}>{title}</p>
      <h2 style={styles.cardValue}>{value}</h2>
    </div>
  );
}

/* ---------------- STYLES ---------------- */

const styles = {
  page: {
    padding: "40px",
    fontFamily: "Inter, sans-serif",
  },

  headerRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 32,
    flexWrap: "wrap",
    gap: 16,
  },

  heading: {
    fontSize: "32px",
    marginBottom: "6px",
  },

  subheading: {
    fontSize: "14px",
    color: "#666",
  },

  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
    gap: "24px",
    marginBottom: 50,
  },

  card: {
    background: "#fff",
    borderRadius: "18px",
    padding: "26px",
    border: "1px solid #eee",
  },

  cardTitle: {
    fontSize: "13px",
    letterSpacing: "1px",
    color: "#777",
    marginBottom: "10px",
  },

  cardValue: {
    fontSize: "28px",
    fontWeight: "500",
    color: "#111",
  },

  chatBtn: {
    padding: "14px 22px",
    borderRadius: 14,
    border: "1px solid #111",
    background: "#111",
    color: "#fff",
    fontSize: 14,
    cursor: "none",
  },

  sectionTitle: {
    fontSize: 18,
    marginBottom: 16,
  },

  tableWrap: {
    overflowX: "auto",
    background: "#fff",
    borderRadius: 14,
    border: "1px solid #eee",
  },

  table: {
    width: "100%",
    borderCollapse: "collapse",
    fontSize: 14,
  },
};
