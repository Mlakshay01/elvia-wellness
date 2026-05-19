import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";

/* ── IMAGES ── */
const images = [
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775490008/ChatGPT_Image_Apr_6_2026_09_02_53_PM_vcfbtm.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775489995/ChatGPT_Image_Apr_6_2026_09_04_33_PM_zdnnfz.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775490008/ChatGPT_Image_Apr_6_2026_09_04_41_PM_pahxmb.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775489989/ChatGPT_Image_Apr_6_2026_09_07_27_PM_qkmvdz.png",
];

const bg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1770667104/763a2a0bb343a5b614a2f890d267a37c_sqezd5.jpg";

const NOTES = [
  {
    src: "https://res.cloudinary.com/dvmntn6vf/image/upload/v1776065610/81af0db4-d647-416d-9862-480f7f001535.png",
    name: "Coffee",
    desc: "Addictive depth",
  },
  {
    src: "https://res.cloudinary.com/dvmntn6vf/image/upload/v1776065678/0109617c-4707-40ae-b364-a05abb8a7f6b.png",
    name: "Jasmine",
    desc: "Floral elegance",
  },
  {
    src: "https://res.cloudinary.com/dvmntn6vf/image/upload/v1776065745/23e6e349-01f2-4d3b-89ad-37ba7375f429.png",
    name: "Vanilla",
    desc: "Soft sensuality",
  },
];

const REVIEWS = [
  { stars: 5, name: "Riya, Delhi", text: "Feels truly premium." },
  { stars: 5, name: "Aanya, Mumbai", text: "Soft, elegant and addictive." },
  {
    stars: 4,
    name: "Kavya, Bangalore",
    text: "Perfect everyday luxury scent.",
  },
];

/* ── ACCORDION — outside component to avoid recreation on every render ── */
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

export default function PerfumeQuietWoods() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();
  const descRef = useRef(null);

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

  const originalPrice = 1499;
  const price = 1399;
  const discountPercent = Math.round(
    ((originalPrice - price) / originalPrice) * 100,
  );

  function handleOrderNow() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart("/perfume/soie-femme-floral-perfume");
    navigate("/cart");
  }

  function handleAddToCartOnly() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart("/perfume/soie-femme-floral-perfume");
    setAdded(true);
    setTimeout(() => setAdded(false), 2200);
  }

  function scrollToDesc() {
    descRef.current?.scrollIntoView({ behavior: "smooth" });
    setOpen("description");
  }

  return (
    <>
      <Helmet>
        <title>Soie Femme — Women's Eau de Parfum | KAEORN</title>
        <meta
          name="description"
          content="Soie Femme by Kaeorn — a luminous feminine Eau de Parfum with notes of Coffee, Jasmine, and Vanilla. Quiet luxury, made in India. ₹1,399."
        />
        <link
          rel="canonical"
          href="https://kaeorn.com/perfume/soie-femme-floral-perfume"
        />
        <meta
          property="og:title"
          content="Soie Femme — Women's Eau de Parfum | KAEORN"
        />
        <meta
          property="og:description"
          content="A luminous feminine fragrance with Coffee, Jasmine & Vanilla. Soft, intimate, unforgettable. ₹1,399 — Made in India."
        />
        <meta
          property="og:image"
          content="https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775490008/ChatGPT_Image_Apr_6_2026_09_02_53_PM_vcfbtm.png"
        />
        <meta
          property="og:url"
          content="https://kaeorn.com/perfume/soie-femme-floral-perfume"
        />
        <meta property="og:type" content="product" />
      </Helmet>

      {authType && (
        <AuthModal type={authType} onClose={() => setAuthType(null)} />
      )}

      <style>{`
  .gallery-scroll::-webkit-scrollbar { display: none; }
`}</style>

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
              <div key={i} style={styles.imageSlide}>
                <img
                  src={img}
                  alt={`SOIE FEMME Eau de Parfum by KAEORN — view ${i + 1}`}
                  style={styles.galleryImage}
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
            <p style={styles.category}>WOMEN · EAU DE PARFUM</p>
            <h1 style={styles.productTitle}>SOIE FEMME</h1>
            <span style={styles.volume}>100 ml</span>
            <span style={styles.volume}>Longevity: 8-10hrs</span>
            <span>30% Natural Oils Concentration</span>
            <br />
            <button style={styles.readMore} onClick={scrollToDesc}>Read more about this fragrance</button>

            {/* <div style={styles.saleBadge}>RELEASE SALE</div> */}

            <div style={styles.priceWrap}>
              <span style={styles.price}>₹{price}</span>
              {/* <span style={styles.originalPrice}>₹{originalPrice}</span>
              <span style={styles.discount}>{discountPercent}% OFF</span> */}
            </div>

            <p style={styles.subtitle}>
              Femininity without force. Soie Femme is a luminous, skin-close
              scent — smooth and soft, with a warmth that lingers long after
              you've left.
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
            <div ref={descRef} style={styles.accordionWrap}>
              <Accordion
                title="DESCRIPTION"
                id="description"
                open={open}
                setOpen={setOpen}
              >
                Soie Femme opens with a luminous, quietly radiant softness. It
                doesn't project — it draws people in. Coffee adds an unexpected
                depth, Jasmine brings a refined floral elegance, and Vanilla
                settles everything into a warm, creamy finish that feels like a
                second skin. This is a fragrance for women who carry themselves
                with ease. Not loud. Not trying. Just present.
              </Accordion>

              <Accordion
                title="HOW IT MAKES YOU FEEL"
                id="feel"
                open={open}
                setOpen={setOpen}
              >
                Calm, feminine, and quietly powerful. Soie Femme doesn't demand
                to be noticed — it earns it. The feeling is soft confidence:
                like wearing something beautiful that no one else can quite
                place. Comforting, grounding, and deeply personal.
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
                Soie Femme is an Eau de Parfum built for intimate presence. On
                skin, it lasts 8–10 hours with a gentle, evolving sillage. Close
                enough to be noticed by those near you — never overpowering a
                room.
              </Accordion>

              <Accordion
                title="HOW TO APPLY"
                id="apply"
                open={open}
                setOpen={setOpen}
              >
                Apply 2–4 sprays on clean, moisturized skin. Focus on pulse
                points — sides of the neck, wrists, behind the ears, and
                collarbone. Don't rub after spraying. Let it breathe and settle
                naturally with your body heat.
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

  // ADD these four:
  galleryWrap: {
    flex: 1,
    minWidth: 320,
    position: "relative",
    borderRadius: 26,
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
  detailsColumn: {
    flex: 1,
    minWidth: 320,
    borderRadius: 28,
    backgroundSize: "cover",
    backgroundPosition: "center",
    position: "relative",
    overflow: "hidden",
  },
  // ADD these two to your styles object:
imageSlide: {
  minWidth: "100%",
  scrollSnapAlign: "center",
},
galleryImage: {
  width: "100%",
  height: "100%",
  objectFit: "cover",
  borderRadius: 26,
  display: "block",
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
    readMore: {
    border: "none",
    background: "transparent",
    fontSize: 13,
    cursor: "pointer",
    textDecoration: "underline",
    marginBottom: 12,
    padding: 0,
    color: "#555",
  },
  saleBadge: {
    display: "inline-block",
    padding: "6px 14px",
    borderRadius: 999,
    background: "#111",
    color: "#fff",
    fontSize: 11,
    letterSpacing: 2,
    marginBottom: 14,
  },
  priceWrap: {
    display: "flex",
    gap: 12,
    alignItems: "center",
    marginBottom: 16,
  },
  price: { fontSize: 28, fontWeight: 500 },
  originalPrice: { textDecoration: "line-through", color: "#888" },
  discount: { color: "#e91e63", fontSize: 13 },
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
    background: "transparent",
    border: "1px solid #111",
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
    gap: 28,
    marginTop: 8,
    flexWrap: "wrap",
  },
  noteItem: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    minWidth: 90,
    gap: 6,
  },
  noteImage: {
    width: 42,
    height: 42,
    objectFit: "contain",
    marginBottom: 6,
  },
  noteTitle: {
    fontSize: 14,
    letterSpacing: 1.2,
    fontWeight: 500,
    textAlign: "center",
  },
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
  reviewItem: {
    borderLeft: "2px solid #eee",
    paddingLeft: 14,
  },
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
  reviewName: {
    fontSize: 12,
    color: "#999",
    letterSpacing: 1,
  },
};
