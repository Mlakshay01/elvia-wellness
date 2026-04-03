export default function Contact() {
  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>Contact Us</h1>

      <p style={styles.text}>
        For any questions related to orders, products, or general support, feel
        free to reach out to us. Our team aims to respond within 24–48 business
        hours.
      </p>

      <div style={styles.infoBlock}>
        <p><strong>Brand:</strong> KAEORN Wellness</p>
        <p><strong>Email:</strong> kaeornwellness@gmail.com</p>
        <p><strong>Phone:</strong> +91 9053140500</p>
        <p><strong>Operating Region:</strong> India</p>
      </div>
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
    marginBottom: "24px",
  },
  infoBlock: {
    marginTop: "24px",
    fontSize: "15px",
    color: "#444",
  },
};
