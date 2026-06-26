import { useState, useEffect, useRef } from "react";
import { Helmet } from "react-helmet-async";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";

/* ── IMAGES ── */
const images = [
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1777636662/velion_home_xpbqlc.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1777638826/velion_2_2_bdkhld.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1777639156/velion_3_2_q6y0dw.png",
  "https://res.cloudinary.com/dhh2i1soo/image/upload/v1777625790/velion_how_to_use_x1mhqs.png",
];

const bg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1770669629/dc9fb4aaf164ae5f44160471f5eb9a7b_hmhsw6.jpg";

const NOTES = [
  {
    src: "https://res.cloudinary.com/dhh2i1soo/image/upload/v1777627256/saffron_ey2cwd.png",
    name: "Exotic Saffron",
    desc: "Rich & Aromatic",
  },
  {
    src: "https://res.cloudinary.com/dhh2i1soo/image/upload/v1777627475/cedar_xlwjs8.png",
    name: "Radiant Cedar",
    desc: "Enduring Elegance",
  },
  {
    src: "https://res.cloudinary.com/dhh2i1soo/image/upload/v1777627602/amber_cf7vrv.png",
    name: "Golden Amber",
    desc: "Warm & Lingering",
  },
];

const REVIEWS = [
  {
    stars: 5,
    name: "Priya, Delhi",
    text: "Like wearing liquid crystal — warm and impossibly clean.",
  },
  {
    stars: 5,
    name: "Aisha, Mumbai",
    text: "Reminds me of BR540 but more intimate, skin-close.",
  },
  {
    stars: 5,
    name: "Kavya, Bangalore",
    text: "The saffron note is stunning. Lasts all day on my wrists.",
  },
  {
    stars: 4,
    name: "Rohan, Pune",
    text: "Unisex done right. Floral but never sweet or heavy.",
  },
];

/* ── ACCORDION ── */
function Accordion({ title, id, open, setOpen, children }) {
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

export default function PerfumeVelion() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();

  const productRef = useRef(null);
  const [visible, setVisible] = useState(false);
  const [authType, setAuthType] = useState(null);
  const [added, setAdded] = useState(false);
  const [open, setOpen] = useState("description");

  const galleryRef = useRef(null);
  const [currentImage, setCurrentImage] = useState(0);

  function goTo(n) {
    const idx = (n + images.length) % images.length;
    setCurrentImage(idx);
    galleryRef.current?.scrollTo({
      left: idx * galleryRef.current.offsetWidth,
      behavior: "smooth",
    });
  }

  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => e.isIntersecting && setVisible(true),
      { threshold: 0.25 },
    );
    productRef.current && obs.observe(productRef.current);
    return () => obs.disconnect();
  }, []);

  const price = 599;
  const originalPrice = 1199;

  function handleOrderNow() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart("/perfume/velion");
    navigate("/cart");
  }

  function handleAddToCartOnly() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart("/perfume/velion");
    setAdded(true);
    setTimeout(() => setAdded(false), 2200);
  }

  return (
    <>
      <Helmet>
        <title>VELION — Unisex Solid Perfume Balm | KAEORN</title>
        <meta
          name="description"
          content="VELION is a radiant solid perfume — a crystalline fusion of exotic saffron and radiant cedar grounded by golden amber. A skin-close luxury. 10g balm, ₹599. Made in India."
        />
        <link rel="canonical" href="https://kaeorn.com/perfume/velion" />
        <meta
          property="og:title"
          content="VELION — Unisex Solid Perfume Balm | KAEORN"
        />
        <meta
          property="og:description"
          content="Fresh · Floral · Luminous. Notes of Cedar, Amberwood & Saffron. ₹599 — Made in India."
        />
        <meta property="og:image" content={images[0]} />
        <meta property="og:url" content="https://kaeorn.com/perfume/velion" />
        <meta property="og:type" content="product" />
      </Helmet>

      {authType && (
        <AuthModal type={authType} onClose={() => setAuthType(null)} />
      )}

      <style>{css}</style>

      <section
        ref={productRef}
        style={{
          ...styles.productSection,
          ...(visible ? styles.show : styles.hide),
        }}
      >
        {/* ── GALLERY ── */}
        <div style={styles.galleryWrap}>
          <div
            ref={galleryRef}
            className="gallery-scroll"
            style={styles.gallery}
            onScroll={(e) => {
              const idx = Math.round(
                e.target.scrollLeft / e.target.offsetWidth,
              );
              setCurrentImage(idx);
            }}
          >
            {images.map((img, i) => (
              <div key={i} style={styles.slide}>
                <img
                  src={img}
                  alt={`VELION Solid Perfume Balm by KAEORN — view ${i + 1}`}
                  style={styles.mainImage}
                />
              </div>
            ))}
          </div>

          <button style={styles.navBtn} onClick={() => goTo(currentImage - 1)}>
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M9 2L4 7L9 12"
                stroke="#111"
                strokeWidth="1.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>

          <button
            style={{ ...styles.navBtn, left: "auto", right: 16 }}
            onClick={() => goTo(currentImage + 1)}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M5 2L10 7L5 12"
                stroke="#111"
                strokeWidth="1.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>

          <div style={styles.dots}>
            {images.map((_, i) => (
              <div
                key={i}
                onClick={() => goTo(i)}
                style={{
                  ...styles.dot,
                  width: i === currentImage ? 20 : 6,
                  background: i === currentImage ? "#111" : "rgba(0,0,0,0.25)",
                }}
              />
            ))}
          </div>
        </div>

        {/* ── DETAILS ── */}
        <div
          style={{
            ...styles.detailsColumn,
            backgroundImage: `url(${bg})`,
          }}
        >
          <div style={styles.overlay} />
          <div style={styles.inner}>
            <p style={styles.category}>Unisex Perfume Balm</p>
            <h1 style={styles.productTitle}>VELION</h1>
            <span style={styles.volume}>10 g</span>

            {/* ── SALE BANNER ── */}
            <div style={styles.saleBanner}>
              <span style={styles.saleBannerDot} />
              <span style={styles.saleBannerText}>
                New Arrival Sale · Limited Period
              </span>
              <span style={styles.saleBannerDot} />
            </div>

            {/* ── PRICE BLOCK ── */}
            <div style={styles.priceWrap}>
              <span style={styles.price}>₹{price}</span>
              <span style={styles.originalPrice}>₹{originalPrice}</span>
              <span style={styles.saveBadge}>50% OFF</span>
            </div>

            <p style={styles.subtitle}>
              A radiant, woody solid perfume — exotic saffron and airy cedar
              lifted by warm, golden amber. Inspired by the world's most coveted
              crystalline fragrance, made for those who leave a sophisticated,
              lingering impression.
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

            {/* ── ACCORDIONS ── */}
            <div style={styles.accordionWrap}>
              <Accordion
                title="DESCRIPTION"
                id="description"
                open={open}
                setOpen={setOpen}
              >
                VELION opens with the intense, aromatic spice of Exotic Saffron
                — rich and immediately captivating. As it warms on the skin, it
                reveals a heart of Radiant Cedar, providing a mineral-faceted
                core that adds depth and enduring elegance. The fragrance is
                anchored by Golden Amber, creating a warm, resinous trail that
                feels both powerful and magnetic. The overall effect is
                sophisticated and transparent — a personal luxury that stays
                intimate to the skin.
              </Accordion>

              <Accordion
                title="HOW IT MAKES YOU FEEL"
                id="feel"
                open={open}
                setOpen={setOpen}
              >
                Like light through crystal. VELION is clean luxury — fresh and
                floral up top, warm and lingering underneath. The kind of scent
                that makes people lean in without knowing why.
              </Accordion>

              <Accordion title="NOTES" id="notes" open={open} setOpen={setOpen}>
                <div style={styles.notesWrap}>
                  {NOTES.map((n) => (
                    <div key={n.name} style={styles.noteItem}>
                      <img src={n.src} alt={n.name} style={styles.noteImage} />
                      <div style={styles.noteTitle}>{n.name}</div>
                      <div style={styles.noteDesc}>{n.desc}</div>
                    </div>
                  ))}
                </div>
              </Accordion>

              <Accordion
                title="PERFORMANCE"
                id="performance"
                open={open}
                setOpen={setOpen}
              >
                VELION is a solid perfume with strong skin-adhesion and
                surprising longevity. The amberwood base anchors the floral top
                notes for 8 to 10 hours of quiet, consistent presence. It
                evolves beautifully — brighter in the first hour, warmer and
                more resinous as the day goes on.
              </Accordion>

              <Accordion
                title="HOW TO APPLY"
                id="apply"
                open={open}
                setOpen={setOpen}
              >
                Apply a small amount of VELION onto clean, moisturized skin. Use
                your fingertip to warm the balm before gently pressing onto
                skin. Focus on pulse points — neck, wrists, inside of elbows,
                behind ears. Let it settle naturally without rubbing for the
                cleanest finish. Reapply lightly mid-day whenever you want to
                refresh the radiance.
              </Accordion>

              <Accordion
                title="REVIEWS"
                id="reviews"
                open={open}
                setOpen={setOpen}
              >
                <div style={styles.reviewsWrap}>
                  {REVIEWS.map((r, i) => (
                    <div key={i} style={styles.reviewItem}>
                      <div style={styles.reviewStars}>
                        {"★".repeat(r.stars)}
                        {"☆".repeat(5 - r.stars)}
                      </div>
                      <p style={styles.reviewText}>"{r.text}"</p>
                      <span style={styles.reviewName}>— {r.name}</span>
                    </div>
                  ))}
                </div>
              </Accordion>

              <Accordion
                title="KAEORN PHILOSOPHY"
                id="philosophy"
                open={open}
                setOpen={setOpen}
              >
                Kaeorn was built on the belief that luxury should feel
                effortless, not loud. Every fragrance is designed to enhance who
                you already are — not to make a statement, but to leave an
                impression. Quiet. Intentional. Made in India, for the world.
              </Accordion>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

/* ── SCOPED CSS ── */
const css = `
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-6px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .nox-sale-banner { animation: slideIn 0.5s ease forwards; }
  .gallery-scroll::-webkit-scrollbar { display: none; }
`;

/* ── STYLES ── */
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
  // REPLACE gallery with:
  gallery: {
    display: "flex",
    overflowX: "auto",
    scrollSnapType: "x mandatory",
    scrollbarWidth: "none",
  },

  // ADD these four new ones anywhere in the styles object:
  galleryWrap: {
    flex: 1,
    minWidth: 320,
    position: "relative",
    borderRadius: 24,
    overflow: "hidden",
  },
  navBtn: {
    position: "absolute",
    left: 16,
    top: "50%",
    transform: "translateY(-50%)",
    width: 40,
    height: 40,
    borderRadius: "50%",
    background: "rgba(255,255,255,0.85)",
    border: "0.5px solid rgba(0,0,0,0.1)",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 2,
  },
  dots: {
    position: "absolute",
    bottom: 18,
    left: "50%",
    transform: "translateX(-50%)",
    display: "flex",
    gap: 6,
  },
  dot: {
    height: 6,
    borderRadius: 3,
    cursor: "pointer",
    transition: "all 0.3s ease",
  },
  slide: { minWidth: "100%", scrollSnapAlign: "center" },
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
  productTitle: { fontSize: 40, fontWeight: 500, margin: "8px 0 4px" },
  volume: {
    fontSize: 11,
    color: "#9a9089",
    letterSpacing: "0.1em",
    fontFamily: "'DM Mono', monospace",
    display: "block",
    marginBottom: "16px",
  },

  /* ── SALE BANNER ── */
  saleBanner: {
    display: "inline-flex",
    alignItems: "center",
    gap: "10px",
    background: "#b91c1c",
    padding: "8px 16px",
    marginBottom: "18px",
    fontFamily: "'DM Mono', monospace",
  },
  saleBannerText: {
    fontSize: "0.58rem",
    letterSpacing: "0.2em",
    textTransform: "uppercase",
    color: "#fff",
  },
  saleBannerDot: {
    display: "inline-block",
    width: "4px",
    height: "4px",
    borderRadius: "50%",
    background: "rgba(255,255,255,0.5)",
    flexShrink: 0,
  },

  /* ── PRICE ── */
  priceWrap: {
    display: "flex",
    gap: 12,
    alignItems: "baseline",
    marginBottom: 16,
    flexWrap: "wrap",
  },
  price: {
    fontSize: 28,
    fontWeight: 500,
    color: "#b91c1c",
    fontFamily: "'Cormorant Garamond', serif",
  },
  originalPrice: {
    fontSize: 18,
    fontWeight: 400,
    color: "#aaa",
    textDecoration: "line-through",
    fontFamily: "'Cormorant Garamond', serif",
  },
  saveBadge: {
    fontFamily: "'DM Mono', monospace",
    fontSize: "8px",
    letterSpacing: "0.18em",
    textTransform: "uppercase",
    background: "#b91c1c",
    color: "#fff",
    padding: "4px 10px",
    alignSelf: "center",
  },

  subtitle: { fontSize: 15.5, color: "#555", lineHeight: 1.85 },
  ctaRow: { display: "flex", gap: 16, marginTop: 20 },
  buyButton: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "#111",
    color: "#fff",
    border: "none",
    cursor: "pointer",
    fontSize: 14,
  },
  addToCartBtn: {
    padding: "16px 34px",
    borderRadius: 50,
    border: "1px solid #111",
    background: "transparent",
    cursor: "pointer",
    fontSize: 14,
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
    fontSize: 15,
    lineHeight: 1.9,
    color: "#555",
  },
  notesWrap: {
    display: "flex",
    justifyContent: "space-between",
    gap: 30,
    marginTop: 10,
    flexWrap: "wrap",
  },
  noteItem: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: 6,
    minWidth: 90,
  },
  noteImage: {
    width: 42,
    height: 42,
    objectFit: "cover",
    borderRadius: "50%",
    marginBottom: 6,
  },
  noteTitle: { fontSize: 14, letterSpacing: 1.2, fontWeight: 500 },
  noteDesc: {
    fontSize: 12.5,
    color: "#777",
    fontStyle: "italic",
    textAlign: "center",
  },
  reviewsWrap: {
    display: "flex",
    flexDirection: "column",
    gap: 20,
    marginTop: 4,
  },
  reviewItem: { borderLeft: "2px solid #eee", paddingLeft: 14 },
  reviewStars: {
    color: "#c9a96e",
    fontSize: 13,
    letterSpacing: 2,
    marginBottom: 4,
  },
  reviewText: {
    fontSize: 14.5,
    color: "#444",
    lineHeight: 1.7,
    margin: "0 0 4px",
    fontStyle: "italic",
  },
  reviewName: { fontSize: 12, color: "#999", letterSpacing: 1 },
};
