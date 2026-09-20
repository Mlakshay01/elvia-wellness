import { useState, useEffect, useRef } from "react";
import { Helmet } from "react-helmet-async";
import { ld, productJsonLd, breadcrumbJsonLd } from "../seo/schema";
import ProductReviews from "../components/ProductReviews";
import useProductReviews from "../hooks/useProductReviews";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";
import { PRODUCTS } from "../data/products";

/* ── PRODUCT (price/id live in data/products.js) ── */
const ROUTE = "/perfume/discovery-set";
const SET = PRODUCTS[ROUTE];

/* Cloudinary: web-sized, auto-format copy of an image */
const web = (url) => url.replace("/upload/", "/upload/f_auto,q_auto,w_900/");

/* ── WHAT'S INSIDE — one 30 ml bottle of each ── */
const INSIDE = [
  {
    name: "THÉ NOIR",
    route: "/perfume/noir-party-perfume",
    gender: "MEN",
    mood: "Fruity · Aromatic · Gourmand",
    notes: "Apple, Lavender, Tonka Bean",
  },
  {
    name: "VEIL",
    route: "/perfume/veil-fresh-perfume",
    gender: "UNISEX",
    mood: "Citrus · Spicy · Woody",
    notes: "Bergamot, Pink Pepper, Sandalwood",
  },
  {
    name: "SOIE FEMME",
    route: "/perfume/soie-femme-floral-perfume",
    gender: "WOMEN",
    mood: "Floral · Roasted · Gourmand",
    notes: "Coffee, Jasmine, Vanilla",
  },
];

/* ── IMAGES — the three bottles ── */
const images = INSIDE.map((item) => web(PRODUCTS[item.route].image));

const bg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1770669629/dc9fb4aaf164ae5f44160471f5eb9a7b_hmhsw6.jpg";

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

export default function PerfumeDiscoverySet() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();
  const descRef = useRef(null);

  const productRef = useRef(null);
  const [visible, setVisible] = useState(false);
  const [authType, setAuthType] = useState(null);
  const [added, setAdded] = useState(false);
  const [open, setOpen] = useState("inside");
  const reviewsData = useProductReviews("discovery-set");

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

  const price = SET.price;
  const priceLabel = `₹${price.toLocaleString("en-IN")}`;

  function handleOrderNow() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart(ROUTE);
    navigate("/cart");
  }

  function handleAddToCartOnly() {
    if (!user) {
      setAuthType("login");
      return;
    }
    addToCart(ROUTE);
    setAdded(true);
    setTimeout(() => setAdded(false), 2200);
  }

  function scrollToDesc() {
    descRef.current?.scrollIntoView({ behavior: "smooth" });
    setOpen("inside");
  }

  return (
    <>
      <Helmet>
        <title>Discovery Set — 3 × 30 ml Eau de Parfum | KAEORN</title>
        <meta
          name="description"
          content={`The KAEORN Discovery Set — three 30 ml Eau de Parfum bottles: THÉ NOIR, VEIL and SOIE FEMME. Find your signature scent or gift the complete collection. ${priceLabel} — Made in India.`}
        />
        <link rel="canonical" href="https://kaeorn.com/perfume/discovery-set" />
        <meta
          property="og:title"
          content="Discovery Set — 3 × 30 ml Eau de Parfum | KAEORN"
        />
        <meta
          property="og:description"
          content={`Three 30 ml bottles — THÉ NOIR, VEIL & SOIE FEMME. ${priceLabel} — Made in India.`}
        />
        <meta property="og:image" content={images[0]} />
        <meta
          property="og:url"
          content="https://kaeorn.com/perfume/discovery-set"
        />
        <meta property="og:type" content="product" />
        <script type="application/ld+json">
          {ld(productJsonLd("/perfume/discovery-set", { description: "The KAEORN Discovery Set — three 30 ml Eau de Parfum bottles: THÉ NOIR, VEIL and SOIE FEMME.", category: "Collection · Eau de Parfum", availability: "InStock", images: images.slice(0, 3), rating: reviewsData.summary, reviews: reviewsData.reviews }))}
        </script>
        <script type="application/ld+json">
          {ld(
            breadcrumbJsonLd([
              { name: "Home", path: "/" },
              { name: "DISCOVERY SET", path: "/perfume/discovery-set" },
            ]),
          )}
        </script>
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
                  alt={`KAEORN Discovery Set — ${INSIDE[i].name} 30 ml Eau de Parfum`}
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
            <p style={styles.category}>COLLECTION · EAU DE PARFUM</p>
            <h1 style={styles.productTitle}>DISCOVERY SET</h1>
            <span style={styles.volume}>3 × 30 ml</span>
            <span style={styles.volume}>Longevity: 8-10hrs</span>
            <span>25–30% Natural Oils Concentration</span>
            <br />
            <button style={styles.readMore} onClick={scrollToDesc}>
              See what's inside
            </button>

            <div style={styles.priceWrap}>
              <span style={styles.price}>{priceLabel}</span>
            </div>

            <p style={styles.subtitle}>
              Three signatures, three moods. One 30 ml bottle each of THÉ NOIR,
              VEIL and SOIE FEMME — spend time with every one, then keep the
              scent that feels like you. Or give the whole collection as a gift.
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
                title="WHAT'S INSIDE"
                id="inside"
                open={open}
                setOpen={setOpen}
              >
                <div style={styles.insideList}>
                  {INSIDE.map((item) => (
                    <div key={item.name} style={styles.insideItem}>
                      <div style={styles.insideHead}>
                        <span style={styles.insideName}>{item.name}</span>
                        <span style={styles.insideTag}>
                          {item.gender} · 30 ml
                        </span>
                      </div>
                      <p style={styles.insideMood}>{item.mood}</p>
                      <p style={styles.insideNotes}>{item.notes}</p>
                      <button
                        style={styles.insideLink}
                        onClick={() => navigate(item.route)}
                      >
                        View this fragrance →
                      </button>
                    </div>
                  ))}
                </div>
              </Accordion>

              <Accordion
                title="DESCRIPTION"
                id="description"
                open={open}
                setOpen={setOpen}
              >
                The Discovery Set brings all three KAEORN Eau de Parfum
                signatures together in 30 ml bottles — the woody, aromatic THÉ
                NOIR, the clean, airy VEIL and the luminous, gourmand SOIE
                FEMME. It's the easiest way to find the scent that suits your
                skin, your mood and your day, before choosing a full 100 ml
                bottle.
              </Accordion>

              <Accordion
                title="HOW TO APPLY"
                id="apply"
                open={open}
                setOpen={setOpen}
              >
                Apply to clean, moisturized skin — 2 to 4 sprays is enough.
                Pulse points work best: sides of the neck, wrists, behind the
                ears, collarbone. Don't rub after spraying. Let it settle and
                develop with your body heat for the smoothest, longest-lasting
                result.
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

      <ProductReviews
        productId="discovery-set"
        productName="the Discovery Set"
        data={reviewsData}
      />
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
  // UPDATE galleryWrap:
  galleryWrap: {
    flex: 1,
    minWidth: 320,
    position: "relative",
    borderRadius: 26,
    overflow: "hidden",
    aspectRatio: "3 / 4", // ← add this
  },

  // ADD these two:
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
    cursor: "none",
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
    cursor: "none",
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
    cursor: "none",
    textDecoration: "underline",
    marginBottom: 12,
    padding: 0,
    color: "#555",
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
    cursor: "none",
    fontSize: 14,
  },
  addToCartBtn: {
    padding: "16px 34px",
    borderRadius: 50,
    border: "1px solid #111",
    background: "transparent",
    cursor: "none",
    fontSize: 14,
  },
  addedBtn: { background: "#111", color: "#fff" },
  accordionWrap: { marginTop: 30, borderTop: "1px solid #eee" },
  accordionItem: { borderBottom: "1px solid #eee", padding: "22px 0" },
  accordionHeader: {
    display: "flex",
    justifyContent: "space-between",
    cursor: "none",
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
  noteImage: { width: 42, height: 42, objectFit: "contain", marginBottom: 6 },
  noteTitle: { fontSize: 14, letterSpacing: 1.2, fontWeight: 500 },
  noteDesc: {
    fontSize: 12.5,
    color: "#777",
    fontStyle: "italic",
    textAlign: "center",
  },
  insideList: { display: "flex", flexDirection: "column", gap: 22 },
  insideItem: {
    borderLeft: "2px solid #eee",
    paddingLeft: 14,
  },
  insideHead: {
    display: "flex",
    alignItems: "baseline",
    gap: 12,
    flexWrap: "wrap",
    marginBottom: 4,
  },
  insideName: {
    fontSize: 15,
    letterSpacing: 1.6,
    fontWeight: 500,
    color: "#111",
  },
  insideTag: { fontSize: 11, letterSpacing: 2, color: "#9a9089" },
  insideMood: { fontSize: 14, color: "#555", margin: "0 0 2px" },
  insideNotes: {
    fontSize: 13.5,
    color: "#777",
    fontStyle: "italic",
    margin: "0 0 6px",
  },
  insideLink: {
    border: "none",
    background: "transparent",
    padding: 0,
    fontSize: 13,
    color: "#555",
    textDecoration: "underline",
    cursor: "none",
  },
};
