export default function Refund() {
  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>Refund & Cancellation Policy</h1>

      <p style={styles.text}>
        At KAEORN Wellness, we take great care in packaging and quality checks.
        Refunds or replacements are applicable only in cases where products are
        damaged, defective, or incorrect upon delivery.
      </p>

      <p style={styles.text}>
        Any such issue must be reported within 48 hours of receiving the order,
        along with clear images and order details for verification.
      </p>

      <p style={styles.text}>
        Once approved, refunds will be processed to the original payment method
        within 7–10 business days. Shipping charges, if applicable, are
        non-refundable.
      </p>

      <p style={styles.text}>
        Orders once placed cannot be cancelled after they have been shipped.
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
