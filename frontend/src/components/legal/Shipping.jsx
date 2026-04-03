export default function Shipping() {
  return (
    <div style={styles.page}>
      <h1 style={styles.heading}>Shipping Policy</h1>

      <p style={styles.text}>
        Orders placed with KAEORN Wellness are processed within 1–3 business
        days, excluding weekends and public holidays.
      </p>

      <p style={styles.text}>
        Delivery timelines typically range between 5–10 business days,
        depending on the shipping location and courier partner.
      </p>

      <p style={styles.text}>
        Once shipped, tracking details will be shared via email or SMS. Delays
        caused by courier partners, weather conditions, or regional restrictions
        are beyond our control.
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
