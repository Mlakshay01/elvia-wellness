export default function Privacy() {
  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>Privacy Policy</h1>

      <p style={styles.text}>
        KAEORN Wellness respects your privacy and is committed to protecting
        your personal information. We collect customer data only when necessary
        to process orders, provide support, and improve our services.
      </p>

      <p style={styles.text}>
        Information collected may include name, email address, phone number,
        shipping address, and order details. This data is used strictly for
        fulfillment, communication, and customer service purposes.
      </p>

      <p style={styles.text}>
        All payments are securely processed through authorized third-party
        payment gateways. KAEORN Wellness does not store or have access to your
        card, UPI, or banking information.
      </p>

      <p style={styles.text}>
        We do not sell, rent, or share your personal information with third
        parties except where required to fulfill your order or comply with
        legal obligations.
      </p>
    </div>
  );
}

const styles = {
  page: {
    maxWidth: "880px",
    margin: "80px auto",
    padding: "0 24px",
    lineHeight: 1.9,
    fontFamily: "Inter, sans-serif",
  },
  heading: {
    fontSize: "34px",
    fontWeight: "500",
    marginBottom: "28px",
  },
  text: {
    fontSize: "16px",
    color: "#333",
    marginBottom: "22px",
  },
};
