import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";

/* ---------------- IMAGES ---------------- */
const images = [
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769083201/ChatGPT_Image_Jan_22_2026_05_29_15_PM_o5qpcx.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769082852/ChatGPT_Image_Jan_22_2026_05_22_45_PM_acztym.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769081520/ChatGPT_Image_Jan_22_2026_05_01_01_PM_nzxsqv.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769083325/ChatGPT_Image_Jan_22_2026_05_30_28_PM_marrlk.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769083469/ChatGPT_Image_Jan_22_2026_05_33_06_PM_ucfz1x.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769083604/ChatGPT_Image_Jan_22_2026_05_35_29_PM_sgvxbh.png",
];

/* 🌸 BACKGROUND IMAGE */
const bg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1770667104/763a2a0bb343a5b614a2f890d267a37c_sqezd5.jpg";

export default function PerfumeQuietWoods() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();

  const productRef = useRef(null);
  const [visible, setVisible] = useState(false);
  const [authType, setAuthType] = useState(null);
  const [added, setAdded] = useState(false);
  const [open, setOpen] = useState("description");

  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => e.isIntersecting && setVisible(true),
      { threshold: 0.25 }
    );
    productRef.current && obs.observe(productRef.current);
    return () => obs.disconnect();
  }, []);

  const product = {
    id: "perfume-soie-femme",
    name: "KAEORN — SOIE FEMME",
    price: 1199,
  };

  const originalPrice = 1499;
  const discountPercent = Math.round(
    ((originalPrice - product.price) / originalPrice) * 100
  );

  function handleOrderNow() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart({ ...product, image: images[0], quantity: 1 });
    navigate("/cart");
  }

  function handleAddToCartOnly() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart({ ...product, image: images[0], quantity: 1 });
    setAdded(true);
    setTimeout(() => setAdded(false), 2200);
  }

  function Accordion({ title, id, children }) {
    const isOpen = open === id;
    return (
      <div style={styles.accordionItem}>
        <div
          style={styles.accordionHeader}
          onClick={() => setOpen(isOpen ? null : id)}
        >
          {title}
          <span>{isOpen ? "−" : "+"}</span>
        </div>
        {isOpen && <div style={styles.accordionContent}>{children}</div>}
      </div>
    );
  }

  return (
    <>
      {authType && (
        <AuthModal type={authType} onClose={() => setAuthType(null)} />
      )}

      <section
        ref={productRef}
        style={{
          ...styles.productSection,
          ...(visible ? styles.show : styles.hide),
        }}
      >
        {/* 🖤 IMAGE SLIDER (SAME AS THÉ NOIR MEN) */}
        <div style={styles.gallery}>
          {images.map((img, i) => (
            <div key={i} style={styles.slide}>
              <img src={img} alt="" style={styles.mainImage} />
            </div>
          ))}
        </div>

        {/* DETAILS */}
        <div
          style={{
            ...styles.detailsColumn,
            backgroundImage: `url(${bg})`,
          }}
        >
          <div style={styles.overlay} />

          <div style={styles.inner}>
            <p style={styles.category}>WOMEN · EAU DE PARFUM</p>
            <h1 style={styles.productTitle}>SOIE FEMME</h1>

            <div style={styles.saleBadge}>RELEASE SALE</div>

            <div style={styles.priceWrap}>
              <span style={styles.price}>₹{product.price}</span>
              <span style={styles.originalPrice}>₹{originalPrice}</span>
              <span style={styles.discount}>{discountPercent}% OFF</span>
            </div>

            <p style={styles.subtitle}>
              A luminous feminine fragrance designed for elegance without effort.
              Smooth, soft and modern — crafted to feel intimate yet unforgettable.
            </p>

            <div style={styles.ctaRow}>
              <button style={styles.buyButton} onClick={handleOrderNow}>
                Buy Now
              </button>

              <button
                style={{
                  ...styles.addToCartBtn,
                  ...(added ? styles.addedBtn : {}),
                }}
                onClick={handleAddToCartOnly}
              >
                {added ? "Added ✓" : "Add to Cart"}
              </button>
            </div>

            <div style={styles.accordionWrap}>
              <Accordion title="DESCRIPTION" id="description">
                SOIE FEMME opens with a luminous softness that instantly feels elegant and modern.
                The scent stays close to the skin, creating a refined aura rather than loud projection.
                As it settles, gentle warmth and creamy femininity emerge — polished, graceful and deeply comforting.
              </Accordion>

              <Accordion title="HOW IT MAKES YOU FEEL" id="feel">
                Wearing SOIE FEMME feels calm, confident and emotionally grounding.
                It enhances femininity without exaggeration — soft confidence, quiet beauty and modern grace.
              </Accordion>

              <Accordion title="PERFORMANCE" id="performance">
                Longevity up to 24 hours with a smooth, evolving profile.
                Projection remains refined and elegant, designed for intimate luxury.
              </Accordion>

              <Accordion title="HOW TO APPLY" id="apply">
                Apply 2–4 sprays on pulse points such as neck, wrists and collarbone.
                Avoid rubbing to preserve the fragrance structure.
              </Accordion>

              <Accordion title="REVIEWS FROM INDIA" id="reviews">
                ★★★★★ Riya — Delhi: “Feels truly premium.”  
                ★★★★★ Aanya — Mumbai: “Soft, elegant and addictive.”  
                ★★★★☆ Kavya — Bangalore: “Perfect everyday luxury scent.”
              </Accordion>

              <Accordion title="KAEORN PHILOSOPHY" id="philosophy">
                KAEORN creates fragrances for quiet luxury — refined, intentional and intimate.
                Beauty that doesn’t shout, but stays remembered.
              </Accordion>
            </div>
          </div>
        </div>
      </section>
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
    margin: "75px auto",
    padding: "0 24px",
    fontFamily: "Inter, sans-serif",
  },

  hide: { opacity: 0, transform: "translateY(40px)" },
  show: { opacity: 1, transform: "translateY(0)", transition: "0.9s ease" },

  /* IMAGE SLIDER */
  gallery: {
    flex: 1,
    minWidth: 320,
    display: "flex",
    overflowX: "auto",
    gap: 24,
    scrollSnapType: "x mandatory",
  },

  slide: {
    minWidth: "100%",
    scrollSnapAlign: "center",
  },

  mainImage: {
    width: "100%",
    borderRadius: 24,
    boxShadow: "0 30px 60px rgba(0,0,0,0.12)",
    objectFit: "cover",
  },

  detailsColumn: {
    flex: 1,
    minWidth: 320,
    borderRadius: 28,
    backgroundSize: "cover",
    backgroundPosition: "center",
    position: "relative",
    overflow: "hidden",
  },

  overlay: {
    position: "absolute",
    inset: 0,
    background: "rgba(255,255,255,0.93)",
  },

  inner: { position: "relative", padding: "40px" },

  category: { fontSize: 12, letterSpacing: 2.5, color: "#888" },
  productTitle: { fontSize: 40, fontWeight: 500 },

  saleBadge: {
    marginTop: 10,
    display: "inline-block",
    padding: "6px 14px",
    borderRadius: 999,
    background: "#111",
    color: "#fff",
    fontSize: 11,
    letterSpacing: 2,
  },

  priceWrap: { display: "flex", gap: 12, alignItems: "center" },
  price: { fontSize: 28, fontWeight: 500 },
  originalPrice: { textDecoration: "line-through", color: "#888" },
  discount: { color: "#e91e63", fontSize: 13 },

  subtitle: { fontSize: 16, color: "#555", lineHeight: 1.8 },

  ctaRow: { display: "flex", gap: 16, marginTop: 20 },

  buyButton: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "#111",
    color: "#fff",
    border: "none",
  },

  addToCartBtn: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "transparent",
    border: "1px solid #111",
  },

  addedBtn: { background: "#111", color: "#fff" },

  accordionWrap: { marginTop: 30, borderTop: "1px solid #eee" },

  accordionItem: { borderBottom: "1px solid #eee", padding: "22px 0" },

  accordionHeader: {
    display: "flex",
    justifyContent: "space-between",
    cursor: "pointer",
    fontSize: 13,
    letterSpacing: 2,
    fontWeight: 500,
  },

  accordionContent: {
    marginTop: 16,
    fontSize: 15.5,
    lineHeight: 1.9,
    color: "#555",
  },
};
