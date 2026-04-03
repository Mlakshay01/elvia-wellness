import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useAuth } from "../context/AuthContext";

export default function Account() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  if (!user) {
    navigate("/");
    return null;
  }

  return (
    <>
      <Helmet>
        <title>Your Account | KAEORN</title>
        <meta
          name="description"
          content="Manage your KAEORN account, orders, and personal details."
        />
      </Helmet>
      <div style={styles.page}>
        <h2 style={styles.heading}>Account</h2>

        <div style={styles.card}>
          <p style={styles.label}>NAME</p>
          <p>{user.name || "—"}</p>

          <p style={styles.label}>EMAIL</p>
          <p>{user.email}</p>
        </div>

        <div style={styles.actions}>
          <button style={styles.linkBtn} onClick={() => navigate("/my-orders")}>
            My Orders →
          </button>

          <button
            style={styles.linkBtn}
            onClick={() => navigate("/previous-orders")}
          >
            Previous Orders →
          </button>
        </div>

        <button style={styles.logoutBtn} onClick={logout}>
          Logout
        </button>
      </div>
    </>
  );
}

const styles = {
  page: {
    maxWidth: 520,
    margin: "60px auto",
    padding: 20,
  },
  heading: {
    marginBottom: 30,
  },
  card: {
    background: "#fff",
    border: "1px solid #eee",
    borderRadius: 16,
    padding: 24,
    marginBottom: 32,
  },
  label: {
    fontSize: 11,
    letterSpacing: "2px",
    color: "#888",
    marginTop: 16,
  },
  actions: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
    marginBottom: 40,
  },
  linkBtn: {
    background: "transparent",
    border: "1px solid #111",
    padding: "14px 18px",
    borderRadius: 30,
    cursor: "pointer",
    textAlign: "left",
  },
  logoutBtn: {
    background: "none",
    border: "none",
    color: "#b00020",
    cursor: "pointer",
    fontSize: 14,
  },
};
