import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";
import Footer from "../components/Footer";

/* ---------------- CLOUDINARY IMAGES ---------------- */
const img2 =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768910313/ChatGPT_Image_Jan_19_2026_10_47_40_PM_lrcqbq.png";
const img3 =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768910953/ChatGPT_Image_Jan_20_2026_05_37_32_PM_krakt8.png";
const img4 =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768910513/ChatGPT_Image_Jan_20_2026_05_30_21_PM_caczgp.png";
const img5 =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768911211/ChatGPT_Image_Jan_20_2026_05_40_17_PM_pnnszr.png";

const images = [img2, img3, img4, img5];

export default function ProductSpray() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();

  /* ---------------- STATE ---------------- */
  const [activeImage, setActiveImage] = useState(images[0]);
  const [authType, setAuthType] = useState(null);
  const [visible, setVisible] = useState(false);
  const [added, setAdded] = useState(false);
  const productRef = useRef(null);

  /* ---------------- PRODUCT DATA ---------------- */
  const product = {
    id: "haetsal-veil-spray-spf50", // ❗ DO NOT CHANGE
    name: "Haetsal Veil™ Spray SPF 50+ PA++++",
    price: 2699,
  };

  /* ---------------- SCROLL ANIMATION ---------------- */
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => entry.isIntersecting && setVisible(true),
      { threshold: 0.25 },
    );

    if (productRef.current) observer.observe(productRef.current);
    return () => observer.disconnect();
  }, []);

  /* ---------------- HANDLERS ---------------- */
  function handleOrderNow() {
    if (!user) {
      setAuthType("login");
      return;
    }

    addToCart({
      ...product,
      image: activeImage,
      quantity: 1,
    });

    navigate("/cart");
  }

  function handleAddToCartOnly() {
    if (!user) {
      setAuthType("login");
      return;
    }

    addToCart({
      ...product,
      image: activeImage,
      quantity: 1,
    });

    setAdded(true);
    setTimeout(() => setAdded(false), 2200);
  }

  return (
    <>
      {authType && (
        <AuthModal type={authType} onClose={() => setAuthType(null)} />
      )}

      {/* ---------------- PRODUCT SECTION ---------------- */}
      <section
        ref={productRef}
        style={{
          ...styles.productSection,
          ...(visible ? styles.show : styles.hide),
        }}
      >
        {/* LEFT COLUMN */}
        <div style={styles.imageColumn}>
          <img src={activeImage} alt={product.name} style={styles.mainImage} />

          <div style={styles.thumbnailRow}>
            {images.map((img, i) => (
              <img
                key={i}
                src={img}
                alt=""
                onClick={() => setActiveImage(img)}
                style={{
                  ...styles.thumbnail,
                  opacity: activeImage === img ? 1 : 0.45,
                }}
              />
            ))}
          </div>

          {/* LEFT INFO */}
          <div style={styles.leftNote}>
            <h4 style={styles.leftNoteTitle}>Designed for Reapplication</h4>
            <p style={styles.leftNoteText}>
              Protection fades with time, sweat, and movement. This ultra-fine
              mist allows effortless reapplication — even over makeup — without
              disrupting your routine.
            </p>
          </div>
        </div>

        {/* RIGHT COLUMN */}
        <div style={styles.detailsColumn}>
          <p style={styles.category}>SUN PROTECTION</p>

          <h1 style={styles.productTitle}>
            Haetsal Veil™ Spray SPF 50+ PA++++
          </h1>

          <p style={styles.koreanName}>햇살베일™ 선스프레이</p>

          <p style={styles.subtitle}>
            A fine, ultra-light sunscreen mist designed for effortless
            reapplication — anytime, anywhere.
          </p>

          <p style={styles.price}>₹2,699</p>

          {/* CTA */}
          <div style={styles.ctaRow}>
            <button style={styles.buyButton} onClick={handleOrderNow}>
              Order Now
            </button>

            <div style={{ position: "relative" }}>
              <button
                style={{
                  ...styles.addToCartBtn,
                  ...(added ? styles.addedBtn : {}),
                }}
                onClick={handleAddToCartOnly}
              >
                {added ? "Added ✓" : "Add to Cart"}
              </button>

              {added && (
                <div style={styles.toast}>
                  Added to cart · Open <strong>Profile → Cart</strong>
                </div>
              )}
            </div>
          </div>

          {/* BADGES */}
          <div style={styles.badges}>
            <span>No White Cast</span>
            <span>On-the-Go Friendly</span>
            <span>Daily Wear</span>
          </div>

          {/* HOW TO USE */}
          <div style={styles.quickUse}>
            <h4 style={styles.quickUseTitle}>How to Use</h4>
            <p>
              Hold the spray 10–15 cm away and mist evenly over face and neck as
              the final step of your routine.
            </p>
            <p>
              Reapply every 2–3 hours, especially after sweating or outdoor
              exposure.
            </p>
          </div>

          {/* BENEFITS */}
          <div style={styles.benefits}>
            <h4 style={styles.benefitsTitle}>Why You’ll Love It</h4>
            <ul style={styles.benefitsList}>
              <li>SPF 50+ PA++++ broad-spectrum protection</li>
              <li>Ultra-fine mist — no heavy or greasy feel</li>
              <li>Perfect for reapplication over makeup</li>
              <li>Zero white cast on all skin tones</li>
              <li>Ideal for humid and tropical climates</li>
              <li>Non-comedogenic and breathable</li>
            </ul>
          </div>

          {/* RECOMMENDED BASE */}
          <div style={styles.recommendBox}>
            <p style={styles.recommendText}>
              Designed for reapplication, this mist works best when layered over
              a strong base.
              <br />
              <strong>
                Start your day with Haetsal Veil™ Cream for even, long-lasting
                protection.
              </strong>
            </p>

            <button
              style={styles.recommendBtn}
              onClick={() => navigate("/product")}
            >
              View Base Protection Cream
            </button>
          </div>
        </div>
      </section>

      <Footer />
    </>
  );
}

/* ---------------- STYLES ---------------- */

const styles = {
  productSection: {
    display: "flex",
    flexWrap: "wrap",
    gap: 90,
    maxWidth: 1200,
    margin: "56px auto",
    padding: "0 24px",
  },

  hide: { opacity: 0, transform: "translateY(40px)" },
  show: { opacity: 1, transform: "translateY(0)", transition: "0.9s ease" },

  imageColumn: { flex: 1, minWidth: 320 },
  mainImage: { width: "100%", borderRadius: 24 },
  thumbnailRow: { display: "flex", gap: 14, marginTop: 20 },

  thumbnail: {
    width: 74,
    height: 74,
    borderRadius: 14,
    cursor: "none",
    objectFit: "cover",
  },

  leftNote: {
    marginTop: 34,
    padding: "22px 24px",
    borderRadius: 20,
    background: "rgba(0,0,0,0.035)",
    maxWidth: 420,
  },

  leftNoteTitle: {
    fontSize: 15,
    fontWeight: 500,
    marginBottom: 10,
  },

  leftNoteText: {
    fontSize: 14.5,
    lineHeight: 1.8,
    color: "#444",
  },

  detailsColumn: { flex: 1, minWidth: 320 },
  category: { fontSize: 12, letterSpacing: 2.5, color: "#888" },
  productTitle: { fontSize: 40, fontWeight: 500, marginTop: 6 },
  koreanName: { fontSize: 16, color: "#777", marginBottom: 18 },
  subtitle: { fontSize: 16, color: "#555", lineHeight: 1.8 },
  price: { fontSize: 24, margin: "26px 0" },

  ctaRow: { display: "flex", gap: 16, flexWrap: "wrap" },

  buyButton: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "#111",
    color: "#fff",
    border: "none",
    fontSize: 15,
    cursor: "none",
  },

  addToCartBtn: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "transparent",
    color: "#111",
    border: "1px solid #111",
    fontSize: 15,
    cursor: "none",
    transition: "all 0.25s ease",
  },

  addedBtn: {
    background: "#111",
    color: "#fff",
    transform: "scale(0.96)",
  },

  toast: {
    position: "absolute",
    top: "110%",
    left: 0,
    background: "#111",
    color: "#fff",
    padding: "10px 14px",
    borderRadius: 14,
    fontSize: 12.5,
    marginTop: 8,
    whiteSpace: "nowrap",
  },

  badges: {
    display: "flex",
    gap: 22,
    fontSize: 13,
    marginTop: 26,
    color: "#555",
    flexWrap: "wrap",
  },

  quickUse: {
    marginTop: 34,
    fontSize: 15.5,
    lineHeight: 1.9,
    color: "#333",
    maxWidth: 460,
  },

  quickUseTitle: {
    fontSize: 16.5,
    fontWeight: 500,
    marginBottom: 12,
  },

  benefits: {
    marginTop: 34,
    maxWidth: 460,
  },

  benefitsTitle: {
    fontSize: 16.5,
    fontWeight: 500,
    marginBottom: 14,
  },

  benefitsList: {
    fontSize: 14.5,
    lineHeight: 1.9,
    color: "#444",
    paddingLeft: 18,
  },

  recommendBox: {
    marginTop: 44,
    padding: "26px 28px",
    borderRadius: 22,
    background: "rgba(0,0,0,0.03)",
    maxWidth: 480,
  },

  recommendText: {
    fontSize: 15,
    lineHeight: 1.8,
    color: "#333",
    marginBottom: 18,
  },

  recommendBtn: {
    padding: "14px 30px",
    borderRadius: 40,
    background: "#111",
    color: "#fff",
    border: "none",
    fontSize: 14,
    cursor: "none",
  },
};
