import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

export default function MyOrders({ type = "active" }) {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("kaeorn_token");

    // 🔐 No token → redirect
    if (!token) {
      navigate("/");
      return;
    }

    fetch(`${import.meta.env.VITE_API_BASE}/api/orders/my-orders`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then(async (res) => {
        if (!res.ok) {
          throw new Error("Unauthorized");
        }

        return res.json();
      })
      .then((data) => {
         console.log("MY ORDERS API RESPONSE:", data);
        if (!Array.isArray(data)) {
          setOrders([]);
          return;
        }

        if (type === "previous") {
          setOrders(data.filter((o) => o.status === "Delivered"));
        } else {
          setOrders(data);
        }
      })
      .catch((error) => {
        console.error("Failed to fetch orders:", error);
        setOrders([]);
      })
      .finally(() => setLoading(false));
  }, [type, navigate]);

  /* -------- LOADING -------- */
  if (loading) {
    return (
      <p style={{ textAlign: "center", marginTop: 60 }}>Loading your orders…</p>
    );
  }

  /* -------- EMPTY -------- */
  if (orders.length === 0) {
    return (
      <p style={{ textAlign: "center", marginTop: 60 }}>No orders found.</p>
    );
  }

  return (
    <div style={styles.page}>
      <h2 style={styles.heading}>
        {type === "previous" ? "Previous Orders" : "My Orders"}
      </h2>

      {orders.map((order) => (
        <div
          key={order._id}
          style={styles.orderCard}
          onClick={() => navigate(`/order/${order._id}`)}
        >
          {/* ---------- ORDER ITEMS ---------- */}
          <div style={styles.itemsSection}>
            {Array.isArray(order.items) && order.items.length > 0 ? (
              order.items.map((item, index) => (
                <div
                  key={`${order._id}-${item.productId}-${index}`}
                  style={styles.item}
                >
                  {/* PRODUCT IMAGE */}
                  {item.image ? (
                    <img
                      src={item.image}
                      alt={item.name || "Product"}
                      style={styles.productImage}
                    />
                  ) : (
                    <div style={styles.imagePlaceholder}>No Image</div>
                  )}

                  {/* PRODUCT DETAILS */}
                  <div style={styles.itemDetails}>
                    <p style={styles.productName}>{item.name || "Product"}</p>

                    <p style={styles.itemMeta}>
                      ₹{item.price} × {item.quantity}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <p style={styles.noItems}>No item details available</p>
            )}
          </div>

          {/* ---------- ORDER INFO ---------- */}
          <div style={styles.orderInfo}>
            <p style={styles.status}>{order.status}</p>

            <p style={styles.date}>
              {new Date(order.createdAt).toLocaleDateString()}
            </p>

            <p style={styles.amount}>₹{order.totalAmount}</p>

            <span style={styles.view}>View →</span>
          </div>
        </div>
      ))}
    </div>
  );
}

const styles = {
  page: {
    maxWidth: 720,
    margin: "40px auto",
    padding: 20,
  },

  heading: {
    marginBottom: 30,
  },

  orderCard: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 20,
    padding: "18px 20px",
    borderRadius: 16,
    border: "1px solid #eee",
    marginBottom: 16,
    cursor: "pointer",
    transition: "all 0.2s ease",
    backgroundColor: "#fff",
  },

  /* ---------- ITEMS ---------- */

  itemsSection: {
    flex: 1,
    minWidth: 0,
  },

  item: {
    display: "flex",
    alignItems: "center",
    gap: 14,
  },

  productImage: {
    width: 70,
    height: 70,
    objectFit: "cover",
    borderRadius: 10,
    border: "1px solid #eee",
    flexShrink: 0,
  },

  imagePlaceholder: {
    width: 70,
    height: 70,
    borderRadius: 10,
    border: "1px solid #eee",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 10,
    color: "#777",
    flexShrink: 0,
  },

  itemDetails: {
    minWidth: 0,
  },

  productName: {
    margin: "0 0 6px",
    fontSize: 15,
    fontWeight: 500,
  },

  itemMeta: {
    margin: 0,
    fontSize: 13,
    color: "#777",
  },

  noItems: {
    margin: 0,
    fontSize: 13,
    color: "#777",
  },

  /* ---------- ORDER INFO ---------- */

  orderInfo: {
    textAlign: "right",
    flexShrink: 0,
  },

  status: {
    margin: "0 0 4px",
    fontSize: 14,
    fontWeight: 500,
  },

  date: {
    margin: "0 0 8px",
    fontSize: 12,
    color: "#777",
  },

  amount: {
    margin: "0 0 6px",
    fontSize: 16,
    fontWeight: 500,
  },

  view: {
    fontSize: 12,
    color: "#555",
  },
};
