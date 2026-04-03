import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";

export default function Success() {
  const navigate = useNavigate();

  return (
    <>
      <Helmet>
        <title>Order Confirmed | KAEORN</title>
        <meta
          name="description"
          content="Your KAEORN order has been placed successfully. Thank you for choosing luxury wellness."
        />
      </Helmet>
      <div style={styles.page}>
        <h1>Payment Successful 🤍</h1>
        <p>Your order has been placed successfully.</p>

        <button style={styles.button} onClick={() => navigate("/")}>
          Continue Shopping
        </button>
      </div>
    </>
  );
}

const styles = {
  page: {
    minHeight: "70vh",
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    alignItems: "center",
    gap: 20,
  },
  button: {
    padding: "14px 30px",
    borderRadius: 40,
    border: "none",
    background: "#111",
    color: "#fff",
    cursor: "pointer",
  },
};
