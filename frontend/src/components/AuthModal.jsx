import { useState } from "react";
import { useAuth } from "../context/AuthContext";

export default function AuthModal({ onClose }) {
  const { requestOTP, verifyOTP } = useAuth();

  const [step, setStep] = useState("email");
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [timer, setTimer] = useState(0);

  async function handleSendOTP(e) {
    e.preventDefault();
    setStep("otp");
    startTimer();
    setLoading(true);
    setError("");

    try {
      await requestOTP(email);
    } catch {
      setError("Unable to send code");
      setStep("email");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyOTP(e) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      await verifyOTP(email, otp);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function startTimer() {
    setTimer(30);
    const i = setInterval(() => {
      setTimer((t) => {
        if (t <= 1) {
          clearInterval(i);
          return 0;
        }
        return t - 1;
      });
    }, 1000);
  }

  return (
    <div style={styles.overlay}>
      <div style={styles.card}>
        <button onClick={onClose} style={styles.close}>
          ×
        </button>

        <h2 style={styles.title}>
          {step === "email" ? "Welcome to KAEORN" : "Enter verification code"}
        </h2>

        <p style={styles.subtitle}>
          {step === "email"
            ? "Sign in with your email. No password required."
            : `We sent a 6-digit code to ${email}`}
        </p>

        {step === "email" ? (
          <form onSubmit={handleSendOTP} style={styles.form}>
            <input
              type="email"
              placeholder="Email address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              style={styles.input}
            />
            {error && <p style={styles.error}>{error}</p>}
            <button style={styles.button} disabled={loading}>
              {loading ? "Sending… ✉️" : "Continue"}
            </button>
          </form>
        ) : (
          <form onSubmit={handleVerifyOTP} style={styles.form}>
            <input
              placeholder="6-digit code"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              maxLength={6}
              required
              style={styles.otp}
              autoFocus
            />
            {error && <p style={styles.error}>{error}</p>}
            <button style={styles.button} disabled={loading}>
              {loading ? "Verifying…" : "Verify & Login"}
            </button>

            <div style={styles.resend}>
              {timer > 0 ? (
                <span>Resend in {timer}s</span>
              ) : (
                <button
                  type="button"
                  onClick={handleSendOTP}
                  style={styles.resendBtn}
                >
                  Resend code
                </button>
              )}
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

/* ---- STYLES ---- */
const styles = {
  overlay: {
    position: "fixed",
    inset: 0,
    background: "rgba(0,0,0,0.45)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 1000,
  },
  card: {
    background: "#fff",
    padding: 36,
    borderRadius: 20,
    width: "100%",
    maxWidth: 380,
    textAlign: "center",
    position: "relative",
  },
  close: {
    position: "absolute",
    right: 16,
    top: 12,
    fontSize: 22,
    border: "none",
    background: "none",
    cursor: "none",
  },
  title: { fontSize: 22, marginBottom: 10 },
  subtitle: { fontSize: 14, color: "#666", marginBottom: 24 },
  form: { display: "flex", flexDirection: "column", gap: 14 },
  input: { padding: 14, borderRadius: 12, border: "1px solid #ddd" },
  otp: {
    padding: 16,
    fontSize: 18,
    letterSpacing: 6,
    textAlign: "center",
    borderRadius: 14,
    border: "1px solid #ddd",
  },
  button: {
    padding: 16,
    borderRadius: 40,
    border: "none",
    background: "#111",
    color: "#fff",
  },
  resend: { marginTop: 14, fontSize: 13 },
  resendBtn: {
    background: "none",
    border: "none",
    fontWeight: 500,
    cursor: "none",
  },
  error: { color: "#c62828", fontSize: 13 },
};
