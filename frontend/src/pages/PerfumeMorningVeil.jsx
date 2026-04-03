import { useState, useEffect, useRef } from "react";
import { Helmet } from "react-helmet-async";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";

/* ---------------- IMAGES ---------------- */
const images = [
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769084646/ChatGPT_Image_Jan_22_2026_05_53_40_PM_fxiq9d.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769084897/ChatGPT_Image_Jan_22_2026_05_57_33_PM_omnxe9.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769084884/ChatGPT_Image_Jan_22_2026_05_54_05_PM_hzov1u.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769085158/ChatGPT_Image_Jan_22_2026_06_01_54_PM_pz0txu.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769085354/ChatGPT_Image_Jan_22_2026_06_05_02_PM_hvhel5.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769085557/ChatGPT_Image_Jan_22_2026_06_08_42_PM_nlsn7w.png",
];

/* 🌫️ BACKGROUND */
const bg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1770669629/dc9fb4aaf164ae5f44160471f5eb9a7b_hmhsw6.jpg";

export default function PerfumeMorningVeil() {
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
    id: "perfume-veil-unisex",
    name: "KAEORN — VEIL",
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
    addToCart("/perfume/morning-veil");
    navigate("/cart");
  }

  function handleAddToCartOnly() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart("/perfume/morning-veil");
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
    <Helmet>
  <title>Morning Veil Perfume | KAEORN</title>
  <meta
    name="description"
    content="Discover Morning Veil by KAEORN — a clean, airy unisex fragrance designed for a soft and luminous everyday scent."
  />
</Helmet>
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
        {/* 🖤 IMAGE SLIDER (SAME SYSTEM) */}
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
            <p style={styles.category}>UNISEX · EAU DE PARFUM</p>
            <h1 style={styles.productTitle}>VEIL</h1>

            <div style={styles.priceWrap}>
              <span style={styles.price}>₹{product.price}</span>
              <span style={styles.originalPrice}>₹{originalPrice}</span>
              <span style={styles.discount}>{discountPercent}% OFF</span>
            </div>

            <p style={styles.monthOrders}>🔥 500+ ordered this month</p>

            <p style={styles.subtitle}>
              A fragrance designed to dissolve into skin — subtle, creamy and
              emotionally comforting. VEIL is not worn to be announced, but to
              be remembered.
            </p>

            <div style={styles.ctaRow}>
              <button style={styles.buyButton} onClick={handleOrderNow}>
                Order Now
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

            {/* DROPDOWNS */}
            <div style={styles.accordionWrap}>
              <Accordion title="DESCRIPTION" id="description">
                   VEIL opens with a clean, creamy softness that feels instantly
                refined and modern. Rather than projecting loudly, it stays
                close to the skin, creating an intimate aura that feels
                effortlessly luxurious. As it settles, the fragrance develops
                a smooth warmth — not sweet, not sharp — but balanced and calm.
                This is a scent designed for everyday elegance, for moments that
                don’t need drama to feel special. VEIL becomes part of you,
                adapting to your skin chemistry and mood, making it feel deeply
                personal and quietly addictive.
              </Accordion>

              <Accordion title="HOW IT MAKES YOU FEEL" id="feel">
                  Wearing VEIL feels like stepping into a composed, confident
                version of yourself. It creates a sense of calm luxury —
                comforting, grounding, and subtly empowering. The fragrance
                doesn’t demand attention, yet it leaves an impression of
                refinement and taste. Many describe the feeling as soothing,
                intimate, and emotionally warm — like clean skin, soft fabric,
                and quiet confidence combined. It’s ideal for those who value
                elegance without excess.
              </Accordion>

              <Accordion title="PERFORMANCE" id="performance">
                VEIL is crafted as an Eau de Parfum with a refined balance
                between longevity and softness. On skin, it lasts comfortably
                for 8–10 hours while maintaining a gentle projection. The
                sillage remains intimate and elegant, noticeable only when
                someone comes close. This controlled performance ensures the
                fragrance feels luxurious and appropriate across all settings —
                never overpowering, always polished.
              </Accordion>
              

              <Accordion title="HOW TO APPLY" id="apply">
                 Apply VEIL on clean, moisturized skin for best results. Two to
                four sprays are sufficient. Focus on pulse points such as the
                sides of the neck, wrists, behind the ears, and collarbone.
                Avoid rubbing the fragrance after application, as this disrupts
                its natural development. Allow it to settle and evolve
                naturally with your body heat for a smoother, longer-lasting
                effect.
              </Accordion>

              <Accordion title="REVIEWS FROM INDIA" id="reviews">
              ★★★★★ Riya, Delhi — “Feels like a niche European perfume.”  
                ★★★★★ Aarav, Mumbai — “Very calming and classy.”  
                ★★★★☆ Meera, Bangalore — “Perfect everyday luxury scent.”  
                ★★★★★ Nikhil, Pune — “Subtle, clean and addictive.”
              </Accordion>

              <Accordion title="KAEORN PHILOSOPHY" id="philosophy">
                KAEORN believes in quiet luxury — fragrance as a personal ritual
                rather than a statement. Each creation is designed to feel
                intentional, refined, and emotionally resonant. Instead of
                loud projection, KAEORN focuses on intimacy, balance, and modern
                elegance. VEIL represents this philosophy fully: a fragrance
                that enhances who you are, without ever overshadowing you.
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
    objectFit: "cover",
    boxShadow: "0 30px 60px rgba(0,0,0,0.12)",
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

  priceWrap: { display: "flex", gap: 12, alignItems: "center" },
  price: { fontSize: 28, fontWeight: 500 },
  originalPrice: { textDecoration: "line-through", color: "#888" },
  discount: { color: "#e91e63", fontSize: 13 },

  monthOrders: { marginTop: 6, fontSize: 13, fontWeight: 500 },

  subtitle: { fontSize: 16, color: "#555", lineHeight: 1.8 },

  ctaRow: { display: "flex", gap: 16, marginTop: 20 },

  buyButton: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "#111",
    color: "#fff",
    border: "none",
    cursor: "pointer",
  },

  addToCartBtn: {
    padding: "16px 34px",
    borderRadius: 50,
    border: "1px solid #111",
    background: "transparent",
    cursor: "pointer",
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
