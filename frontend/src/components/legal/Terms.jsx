export default function Terms() {
  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>Terms & Conditions</h1>

      <p style={styles.text}>
        By accessing and using the KAEORN Wellness website, you agree to comply
        with and be bound by the terms and conditions outlined on this page.
      </p>

      <p style={styles.text}>
        All product descriptions, pricing, availability, and policies are
        subject to change at any time without prior notice.
      </p>

      <p style={styles.text}>
        KAEORN Wellness reserves the right to refuse service, cancel orders, or
        limit quantities at its discretion.
      </p>

      <p style={styles.text}>
        Continued use of the website constitutes acceptance of these terms.
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
