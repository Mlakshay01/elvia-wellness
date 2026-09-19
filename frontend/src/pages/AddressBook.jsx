import { useState, useEffect } from "react";

export default function AddressBook() {
  const [addresses, setAddresses] = useState([]);
  const [loading, setLoading] = useState(true);
  const token = localStorage.getItem("kaeorn_token");

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_BASE}/api/addresses`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => {
        setAddresses(data || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return <p style={styles.loading}>Loading addresses…</p>;
  }

  return (
    <div style={styles.page}>
      <h2 style={styles.heading}>Your Addresses</h2>

      {addresses.length === 0 && (
        <p style={styles.empty}>No saved addresses yet.</p>
      )}

      {addresses.map((a, i) => (
        <div
          key={i}
          style={{
            ...styles.card,
            border: a.isDefault ? "2px solid #111" : "1px solid #EAEAEA",
          }}
        >
          <div style={styles.cardTop}>
            {a.isDefault && <span style={styles.defaultBadge}>DEFAULT</span>}
            <div style={styles.actions}>
              <span
                style={styles.actionBtn}
                onClick={() => alert("Edit not implemented")}
              >
                Edit
              </span>
              <span
                style={styles.deleteBtn}
                onClick={() => alert("Delete not implemented")}
              >
                Delete
              </span>
            </div>
          </div>

          <p style={styles.name}>{a.fullName}</p>

          <p style={styles.text}>
            {a.street}, {a.city}, {a.state} – {a.postalCode}
          </p>
          <p style={styles.text}>{a.phone}</p>
        </div>
      ))}

      <button
        style={styles.addBtn}
        onClick={() => alert("Navigate to Add Address")}
      >
        + Add New Address
      </button>
    </div>
  );
}

const styles = {
  page: {
    maxWidth: "640px",
    margin: "60px auto",
    padding: "0 20px",
    fontFamily: "Inter, sans-serif",
  },
  heading: {
    fontSize: "28px",
    fontWeight: 500,
    marginBottom: "24px",
    color: "#111",
  },
  loading: {
    textAlign: "center",
    marginTop: "48px",
    color: "#666",
  },
  empty: {
    textAlign: "center",
    marginTop: "40px",
    fontSize: "16px",
    color: "#555",
  },
  card: {
    background: "#fff",
    borderRadius: "12px",
    padding: "20px",
    marginBottom: "20px",
    boxShadow: "0 2px 6px rgba(0,0,0,0.04)",
  },
  cardTop: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "10px",
  },
  defaultBadge: {
    background: "#111",
    color: "#fff",
    padding: "4px 10px",
    fontSize: "11px",
    borderRadius: "8px",
    letterSpacing: "1px",
  },
  actions: {
    display: "flex",
    gap: "12px",
  },
  actionBtn: {
    fontSize: "12px",
    color: "#111",
    cursor: "none",
  },
  deleteBtn: {
    fontSize: "12px",
    color: "#B00020",
    cursor: "none",
  },
  name: {
    fontSize: "16px",
    fontWeight: 500,
    marginBottom: "4px",
  },
  text: {
    fontSize: "14px",
    color: "#444",
    margin: 0,
  },
  addBtn: {
    marginTop: "32px",
    width: "100%",
    padding: "16px",
    borderRadius: "40px",
    border: "none",
    background: "#111",
    color: "#fff",
    fontSize: "15px",
    fontWeight: 500,
    cursor: "none",
  },
};
