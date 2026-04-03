export default function About() {
  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>About KAEORN Wellness</h1>

      <p style={styles.text}>
        KAEORN Wellness is a premium skincare and wellness brand rooted in
        simplicity, precision, and long-term skin health. We believe luxury is
        not excess — it is intention, formulation integrity, and trust.
      </p>

      <p style={styles.text}>
        Our products are developed with a thoughtful balance of modern
        dermatological science and refined aesthetics. Each formulation is
        designed to be effective, gentle, and purposeful — avoiding unnecessary
        additives while focusing on results that respect the skin barrier.
      </p>

      <p style={styles.text}>
        At KAEORN, we value transparency, quality sourcing, and responsible
        production. Every product is created with careful attention to safety,
        performance, and user experience.
      </p>

      <p style={styles.text}>
        KAEORN Wellness is for those who prefer clarity over clutter, and care
        over claims.
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
    fontSize: "36px",
    fontWeight: "500",
    marginBottom: "32px",
  },
  text: {
    fontSize: "16px",
    color: "#333",
    marginBottom: "22px",
  },
};
