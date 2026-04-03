import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";

export default function Checkout() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    name: "",
    phone: "",
    email: "",
    address: "",
    city: "",
    state: "",
    pincode: "",
  });

  function handleContinue() {
    if (
      !form.name ||
      !form.phone ||
      !form.address ||
      !form.city ||
      !form.state ||
      !form.pincode
    ) {
      alert("Please fill all required fields");
      return;
    }

    // Save delivery address for Payment.jsx
    localStorage.setItem("deliveryAddress", JSON.stringify(form));

    navigate("/payment");
  }

  return (
    <>
      <Helmet>
        <title>Checkout | KAEORN</title>
        <meta
          name="description"
          content="Complete your purchase of KAEORN luxury fragrances with secure checkout and fast delivery."
        />
      </Helmet>

      <div style={styles.container}>
        <h2 style={styles.heading}>Delivery Details</h2>

        <input
          placeholder="Full Name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
        />

        <input
          placeholder="Phone Number"
          value={form.phone}
          onChange={(e) => setForm({ ...form, phone: e.target.value })}
        />

        <input
          placeholder="Email (for invoice)"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
        />

        <textarea
          placeholder="Full Address"
          value={form.address}
          onChange={(e) => setForm({ ...form, address: e.target.value })}
        />

        <input
          placeholder="City"
          value={form.city}
          onChange={(e) => setForm({ ...form, city: e.target.value })}
        />

        <input
          placeholder="State"
          value={form.state}
          onChange={(e) => setForm({ ...form, state: e.target.value })}
        />

        <input
          placeholder="Pincode"
          value={form.pincode}
          onChange={(e) => setForm({ ...form, pincode: e.target.value })}
        />

        <button onClick={handleContinue} style={styles.button}>
          Continue to Secure Payment
        </button>
      </div>
    </>
  );
}

/* ---------------- STYLES ---------------- */

const styles = {
  container: {
    padding: "40px",
    maxWidth: "420px",
    margin: "auto",
    display: "flex",
    flexDirection: "column",
    gap: "14px",
    fontFamily: "Inter, sans-serif",
  },
  heading: {
    marginBottom: "20px",
    fontSize: "26px",
  },
  button: {
    marginTop: "16px",
    padding: "16px",
    borderRadius: "40px",
    border: "none",
    background: "#111",
    color: "#fff",
    cursor: "pointer",
    fontSize: "15px",
  },
};
