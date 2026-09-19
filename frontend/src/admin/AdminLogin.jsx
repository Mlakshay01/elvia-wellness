import { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function AdminLogin() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin(e) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch(
        `${import.meta.env.VITE_API_BASE}/api/admin/login`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        },
      );

      const data = await res.json(); // ✅ FIXED

      if (!res.ok) {
        setError(data.message || "Login failed");
        setLoading(false);
        return;
      }

      // 🔐 SAVE ADMIN TOKEN
      localStorage.setItem("adminToken", data.token);

      // ✅ REDIRECT
      navigate("/admin/dashboard", { replace: true });
    } catch (err) {
      console.error("Admin login error:", err);
      setError("Unable to connect to server");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.page}>
      <form onSubmit={handleLogin} style={styles.card}>
        <h2 style={styles.title}>Admin Login</h2>

        {error && <p style={styles.error}>{error}</p>}

        <input
          type="email"
          placeholder="Admin Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          style={styles.input}
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          style={styles.input}
        />

        <button
          type="submit"
          style={{
            ...styles.button,
            opacity: loading ? 0.7 : 1,
          }}
          disabled={loading}
        >
          {loading ? "Signing in…" : "Login"}
        </button>
      </form>
    </div>
  );
}

/* ---------------- STYLES ---------------- */

const styles = {
  page: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    background: "#f7f7f7",
    fontFamily: "Inter, sans-serif",
  },
  card: {
    background: "#fff",
    padding: "42px",
    borderRadius: "18px",
    width: "360px",
    boxShadow: "0 24px 70px rgba(0,0,0,0.08)",
  },
  title: {
    marginBottom: "26px",
    fontSize: "22px",
    fontWeight: "500",
    textAlign: "center",
  },
  input: {
    width: "100%",
    padding: "14px",
    marginBottom: "14px",
    borderRadius: "10px",
    border: "1px solid #ddd",
    fontSize: "14px",
  },
  button: {
    width: "100%",
    padding: "14px",
    borderRadius: "30px",
    border: "none",
    background: "#111",
    color: "#fff",
    cursor: "none",
    fontSize: "15px",
    marginTop: "10px",
  },
  error: {
    color: "#c62828",
    fontSize: "13px",
    marginBottom: "14px",
    textAlign: "center",
  },
};
