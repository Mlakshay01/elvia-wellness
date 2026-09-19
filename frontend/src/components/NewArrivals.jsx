/*
  NewArrivals.jsx
  ───────────────
  Homepage "New Arrivals" section.

  • DISCOVERY SET is the main feature (3 × 30 ml: THÉ NOIR, VEIL, SOIE FEMME).
  • NOX + VELION are sold out, so they sit in a small "Currently sold out"
    list underneath instead of taking up full-size cards.

  Usage in Home.jsx (unchanged):
    import NewArrivals from "../components/NewArrivals";
    ...
    <NewArrivals navigate={navigate} addReveal={addReveal} user={user} addToCart={addToCart} setShowAuth={setShowAuth} />
*/

import { useState, useRef, useEffect } from "react";
import { PRODUCTS as CATALOG } from "../data/products";

/* Cloudinary: web-sized, auto-format copy of an image */
const web = (url, width = 700) =>
  url.replace("/upload/", `/upload/f_auto,q_auto,w_${width}/`);

/* ── IMAGES ── */
/*
  Have one photo of the whole set? Paste its Cloudinary URL here and it
  replaces the 3-bottle collage. Leave "" to keep the collage.
*/
const DISCOVERY_IMG = "";

const NOX_IMG =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1777184309/ChatGPT_Image_Apr_26_2026_11_47_58_AM_dycgoa.png";
const VELION_IMG =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1777636662/velion_home_xpbqlc.png";

/* ── FEATURED: DISCOVERY SET ──
   Price comes from data/products.js so it can never drift from the cart.
   Looked up by id (not by route key) so the homepage can't crash if the
   route key in products.js is spelled differently. */
const SET_ROUTE = "/perfume/discovery-set";
const SET = Object.values(CATALOG).find((p) => p.id === "discovery-set");

if (!SET) {
  console.warn(
    'NewArrivals: no product with id "discovery-set" in data/products.js',
  );
}

const FEATURED = {
  id: "discovery-set",
  route: SET_ROUTE,
  name: "DISCOVERY SET",
  eyebrow: "New Arrival",
  subtitle: "3 × 30 ml Eau de Parfum Collection",
  character: "Discover Every Signature",
  notes: ["THÉ NOIR", "VEIL", "SOIE FEMME"],
  desc: "Not sure which KAEORN is yours? Start with all three — a 30 ml bottle each of THÉ NOIR (men), VEIL (unisex) and SOIE FEMME (women). Wear them, then choose your signature scent. Or give the complete collection as a gift.",
  price: SET ? `₹${SET.price.toLocaleString("en-IN")}` : "",
  originalPrice: "",
  size: "3 × 30 ml",
  gender: "Men • Women • Unisex",
  img: DISCOVERY_IMG,
  accent: "#c9a96e",
  tag: "New",
  priceLabel: "Collection · 3 × 30 ml",
};

/* Three-bottle collage (used while there is no single set photo).
   Positions are % of the image frame; tiles are 58% wide, 3:4. */
const COLLAGE = [
  {
    route: "/perfume/noir-party-perfume",
    alt: "THÉ NOIR Eau de Parfum by KAEORN — 30 ml",
    style: { left: "5%", top: "6%", "--rot": "-6deg", zIndex: 1 },
  },
  {
    route: "/perfume/soie-femme-floral-perfume",
    alt: "SOIE FEMME Eau de Parfum by KAEORN — 30 ml",
    style: { right: "5%", bottom: "6%", "--rot": "6deg", zIndex: 1 },
  },
  {
    route: "/perfume/veil-fresh-perfume",
    alt: "VEIL Eau de Parfum by KAEORN — 30 ml",
    style: { left: "21%", top: "21%", "--rot": "0deg", zIndex: 2 },
  },
];

/* ── SOLD OUT (shown small) ── */
const SOLD_OUT = [
  {
    id: "nox",
    route: "/perfume/nox",
    name: "NOX",
    subtitle: "Solid Perfume Balm · 10 g",
    img: NOX_IMG,
  },
  {
    id: "velion",
    route: "/perfume/velion",
    name: "VELION",
    subtitle: "Solid Perfume Balm · 10 g",
    img: VELION_IMG,
  },
];

/* ─────────────────────────────────────────────
   FEATURED CARD
───────────────────────────────────────────── */
function FeaturedCard({
  product,
  navigate,
  addToCart,
  user,
  setShowAuth,
  addReveal,
}) {
  const [added, setAdded] = useState(false);
  const cardRef = useRef(null);

  useEffect(() => {
    if (cardRef.current) addReveal(cardRef.current);
  }, []);

  function handleAdd(e) {
    e.stopPropagation();
    if (!user) {
      setShowAuth(true);
      return;
    }
    // addToCart accepts a product id; returns false if it can't resolve it
    if (addToCart(product.id) === false) return;
    setAdded(true);
    setTimeout(() => setAdded(false), 2200);
  }

  return (
    <article
      ref={cardRef}
      style={cardStyles.wrap}
      className="na-card reveal"
    >
      {/* ── IMAGE ── */}
      <div style={cardStyles.imageCol}>
        <div
          style={cardStyles.imageFrame}
          className="na-img-frame"
          onClick={() => navigate(product.route)}
        >
          {product.img ? (
            <img
              src={product.img}
              alt={`${product.name} ${product.subtitle} by KAEORN`}
              style={cardStyles.img}
              className="na-img"
            />
          ) : (
            COLLAGE.filter((tile) => CATALOG[tile.route]).map((tile) => (
              <img
                key={tile.route}
                src={web(CATALOG[tile.route].image)}
                alt={tile.alt}
                className="na-tile"
                style={{ ...cardStyles.tile, ...tile.style }}
              />
            ))
          )}
          <div style={cardStyles.imgOverlay} className="na-img-overlay" />

          {/* floating info chip */}
          <div
            style={{ ...cardStyles.chip, borderColor: product.accent + "55" }}
          >
            <span style={cardStyles.chipLabel}>{product.gender}</span>
            <span
              style={{ ...cardStyles.chipDot, background: product.accent }}
            />
            <span style={cardStyles.chipLabel}>{product.size}</span>
          </div>

          <div style={cardStyles.newBadge}>{product.tag}</div>
        </div>
      </div>

      {/* ── COPY ── */}
      <div style={cardStyles.copyCol}>
        <p style={cardStyles.eyebrow}>{product.eyebrow}</p>

        <h2 style={cardStyles.name}>{product.name}</h2>

        <p style={{ ...cardStyles.character, color: product.accent }}>
          {product.character}
        </p>

        <p style={cardStyles.desc}>{product.desc}</p>

        <div style={cardStyles.notes}>
          {product.notes.map((n) => (
            <span key={n} style={cardStyles.notePill}>
              {n}
            </span>
          ))}
        </div>

        {/* price + cta */}
        <div style={cardStyles.footer}>
          <div>
            <p style={cardStyles.priceLabel}>{product.priceLabel}</p>
            <p style={cardStyles.price}>{product.price}</p>
          </div>
          <div style={cardStyles.ctaRow}>
            <button
              type="button"
              className="na-btn"
              style={cardStyles.btnGhost}
              onClick={() => navigate(product.route)}
            >
              See what's inside
            </button>
            <button
              type="button"
              className="na-btn"
              style={{
                ...cardStyles.btnFill,
                background: added ? "#2a2520" : "#0d0c0b",
              }}
              onClick={handleAdd}
              disabled={!SET}
            >
              {added ? "Added ✓" : "Add to Cart"}
            </button>
          </div>
        </div>
      </div>
    </article>
  );
}

/* ─────────────────────────────────────────────
   SOLD-OUT ROW (small, muted)
───────────────────────────────────────────── */
function SoldOutRow({ item, navigate }) {
  return (
    <button
      type="button"
      className="na-btn"
      style={soldOutStyles.row}
      onClick={() => navigate(item.route)}
      aria-label={`${item.name} — sold out. View product page`}
    >
      <img
        src={web(item.img, 160)}
        alt=""
        style={soldOutStyles.thumb}
        loading="lazy"
      />
      <span style={soldOutStyles.text}>
        <span style={soldOutStyles.name}>{item.name}</span>
        <span style={soldOutStyles.sub}>{item.subtitle}</span>
      </span>
      <span style={soldOutStyles.status}>Sold out</span>
    </button>
  );
}

/* ─────────────────────────────────────────────
   SECTION
───────────────────────────────────────────── */
export default function NewArrivals({
  navigate,
  addReveal,
  user,
  addToCart,
  setShowAuth,
}) {
  const sectionRef = useRef(null);

  return (
    <>
      <style>{css}</style>
      <section style={sectionStyles.section} ref={sectionRef} id="new-arrivals">
        {/* ── HEADER ── */}
        <div style={sectionStyles.header}>
          <div style={sectionStyles.headerLeft}>
            <p style={sectionStyles.eyebrow}>
              <span style={sectionStyles.eyebrowLine} />
              New Arrivals
            </p>
            <h2 style={sectionStyles.title}>
              Start with
              <br />
              all three.
            </h2>
          </div>
          <div style={sectionStyles.headerRight}>
            <p style={sectionStyles.intro}>
              The Discovery Set puts our three Eau de Parfum signatures in your
              hands — one 30 ml bottle each — so you can find the one that
              feels like you.
            </p>
            <div style={sectionStyles.headerRule} />
            <p style={sectionStyles.headerMeta}>
              THÉ NOIR · VEIL · SOIE FEMME · 3 × 30 ml
            </p>
          </div>
        </div>

        {/* ── FEATURED ── */}
        <FeaturedCard
          product={FEATURED}
          navigate={navigate}
          addToCart={addToCart}
          user={user}
          setShowAuth={setShowAuth}
          addReveal={addReveal}
        />

        {/* ── SOLD OUT ── */}
        <div style={soldOutStyles.wrap}>
          <p style={soldOutStyles.label}>Currently sold out</p>
          <div style={soldOutStyles.list}>
            {SOLD_OUT.map((item) => (
              <SoldOutRow key={item.id} item={item} navigate={navigate} />
            ))}
          </div>
        </div>
      </section>
    </>
  );
}

/* ── SECTION STYLES ── */
const sectionStyles = {
  section: {
    padding: "clamp(5rem, 10vw, 9rem) clamp(1.5rem, 5vw, 4rem)",
    maxWidth: 1200,
    margin: "0 auto",
    fontFamily: "'DM Mono', monospace",
  },
  header: {
    display: "flex",
    gap: "clamp(2rem, 6vw, 6rem)",
    alignItems: "flex-end",
    marginBottom: "clamp(3rem, 6vw, 5rem)",
    flexWrap: "wrap",
  },
  headerLeft: { flex: "0 0 auto" },
  eyebrow: {
    fontSize: "0.6rem",
    letterSpacing: "0.26em",
    textTransform: "uppercase",
    color: "var(--muted, #888)",
    marginBottom: "1.2rem",
    display: "flex",
    alignItems: "center",
    gap: "12px",
  },
  eyebrowLine: {
    display: "inline-block",
    width: "28px",
    height: "1px",
    background: "var(--muted, #888)",
  },
  title: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "clamp(3.5rem, 7vw, 6rem)",
    fontWeight: 300,
    lineHeight: 0.92,
    letterSpacing: "-0.01em",
    color: "var(--ink, #0d0c0b)",
  },
  headerRight: {
    flex: 1,
    minWidth: 240,
    paddingBottom: "0.5rem",
  },
  intro: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "clamp(1rem, 1.8vw, 1.2rem)",
    lineHeight: 1.85,
    color: "var(--muted, #777)",
    marginBottom: "2rem",
    maxWidth: 440,
  },
  headerRule: {
    width: "100%",
    height: "1px",
    background: "var(--border, #eee)",
    marginBottom: "1.2rem",
  },
  headerMeta: {
    fontSize: "0.58rem",
    letterSpacing: "0.2em",
    textTransform: "uppercase",
    color: "var(--muted, #aaa)",
  },
};

/* ── FEATURED CARD STYLES ── */
const cardStyles = {
  wrap: {
    display: "flex",
    gap: "clamp(2rem, 5vw, 5rem)",
    alignItems: "center",
    flexWrap: "wrap",
  },
  imageCol: {
    flex: "0 0 auto",
    width: "clamp(260px, 40vw, 460px)",
  },
  imageFrame: {
    position: "relative",
    width: "100%",
    paddingBottom: "133.33%",
    overflow: "hidden",
    cursor: "pointer",
    backgroundColor: "#f5f0eb",
  },
  /* single set photo */
  img: {
    position: "absolute",
    top: 0,
    left: 0,
    width: "100%",
    height: "100%",
    objectFit: "cover",
    display: "block",
    transition:
      "transform 1.1s cubic-bezier(0.25,0.46,0.45,0.94), filter 0.5s ease",
    filter: "saturate(0.9) contrast(1.03)",
  },
  /* collage tile */
  tile: {
    position: "absolute",
    width: "58%",
    aspectRatio: "3 / 4",
    objectFit: "cover",
    display: "block",
    boxSizing: "border-box",
    border: "5px solid #fff",
    boxShadow: "0 14px 30px rgba(13,12,11,0.18)",
    transform: "rotate(var(--rot, 0deg))",
    transition: "transform 0.6s cubic-bezier(0.25,0.46,0.45,0.94)",
  },
  imgOverlay: {
    position: "absolute",
    inset: 0,
    background:
      "linear-gradient(to top, rgba(13,12,11,0.35) 0%, transparent 50%)",
    opacity: 0,
    transition: "opacity 0.4s",
    zIndex: 3,
    pointerEvents: "none",
  },
  chip: {
    position: "absolute",
    bottom: "20px",
    left: "20px",
    display: "flex",
    alignItems: "center",
    gap: "8px",
    background: "rgba(255,255,255,0.88)",
    backdropFilter: "blur(10px)",
    border: "1px solid",
    padding: "8px 14px",
    zIndex: 4,
  },
  chipLabel: {
    fontFamily: "'DM Mono', monospace",
    fontSize: "9px",
    letterSpacing: "0.18em",
    textTransform: "uppercase",
    color: "#444",
  },
  chipDot: {
    width: "5px",
    height: "5px",
    borderRadius: "50%",
    flexShrink: 0,
  },
  newBadge: {
    position: "absolute",
    top: "20px",
    right: "20px",
    fontFamily: "'DM Mono', monospace",
    fontSize: "8px",
    letterSpacing: "0.22em",
    textTransform: "uppercase",
    padding: "6px 12px",
    zIndex: 4,
    background: "#0d0c0b",
    color: "#f0ece4",
  },
  copyCol: {
    flex: 1,
    minWidth: 260,
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    gap: "0",
  },
  eyebrow: {
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.58rem",
    letterSpacing: "0.22em",
    textTransform: "uppercase",
    color: "var(--muted, #888)",
    marginBottom: "1.4rem",
  },
  name: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "clamp(3.4rem, 7.2vw, 6.4rem)",
    fontWeight: 300,
    lineHeight: 0.9,
    letterSpacing: "-0.02em",
    color: "var(--ink, #0d0c0b)",
    marginBottom: "1.2rem",
  },
  character: {
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.62rem",
    letterSpacing: "0.16em",
    textTransform: "uppercase",
    marginBottom: "1.8rem",
  },
  desc: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "clamp(1rem, 1.6vw, 1.15rem)",
    lineHeight: 1.85,
    color: "var(--muted, #666)",
    marginBottom: "2rem",
    maxWidth: 420,
  },
  notes: {
    display: "flex",
    flexWrap: "wrap",
    gap: "8px",
    marginBottom: "2rem",
  },
  notePill: {
    fontFamily: "'DM Mono', monospace",
    fontSize: "8.5px",
    letterSpacing: "0.16em",
    textTransform: "uppercase",
    padding: "6px 14px",
    border: "1px solid var(--border, #ddd)",
    color: "var(--ink, #333)",
  },
  footer: {
    display: "flex",
    alignItems: "flex-end",
    justifyContent: "space-between",
    gap: "1.5rem",
    paddingTop: "1.8rem",
    borderTop: "1px solid var(--border, #eee)",
    flexWrap: "wrap",
    alignSelf: "stretch",
  },
  priceLabel: {
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.55rem",
    letterSpacing: "0.2em",
    textTransform: "uppercase",
    color: "var(--muted, #aaa)",
    marginBottom: "5px",
  },
  price: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "2.2rem",
    fontWeight: 300,
    color: "var(--ink, #0d0c0b)",
    lineHeight: 1,
  },
  ctaRow: {
    display: "flex",
    gap: "10px",
    flexWrap: "wrap",
  },
  btnGhost: {
    padding: "12px 22px",
    background: "transparent",
    color: "var(--ink, #0d0c0b)",
    border: "1px solid var(--border, #ccc)",
    fontFamily: "'DM Mono', monospace",
    fontSize: "9px",
    letterSpacing: "0.18em",
    textTransform: "uppercase",
    cursor: "pointer",
    transition: "border-color 0.2s",
  },
  btnFill: {
    padding: "12px 22px",
    color: "#f0ece4",
    border: "none",
    fontFamily: "'DM Mono', monospace",
    fontSize: "9px",
    letterSpacing: "0.18em",
    textTransform: "uppercase",
    cursor: "pointer",
    transition: "background 0.2s",
  },
};

/* ── SOLD-OUT STYLES (deliberately small + muted) ── */
const soldOutStyles = {
  wrap: {
    marginTop: "clamp(3.5rem, 7vw, 6rem)",
    paddingTop: "1.6rem",
    borderTop: "1px solid var(--border, #eee)",
  },
  label: {
    fontFamily: "'DM Mono', monospace",
    fontSize: "0.55rem",
    letterSpacing: "0.2em",
    textTransform: "uppercase",
    color: "var(--muted, #aaa)",
    marginBottom: "1rem",
  },
  list: {
    display: "flex",
    flexWrap: "wrap",
    gap: "12px",
  },
  row: {
    display: "flex",
    alignItems: "center",
    gap: "14px",
    padding: "8px 16px 8px 8px",
    minWidth: 240,
    background: "transparent",
    border: "1px solid var(--border, #eee)",
    cursor: "pointer",
    textAlign: "left",
    fontFamily: "'DM Mono', monospace",
    opacity: 0.7,
  },
  thumb: {
    width: 44,
    height: 44,
    objectFit: "cover",
    display: "block",
    filter: "grayscale(1)",
    flexShrink: 0,
  },
  text: {
    display: "flex",
    flexDirection: "column",
    gap: "3px",
    flex: 1,
  },
  name: {
    fontSize: "0.7rem",
    letterSpacing: "0.16em",
    color: "var(--ink, #333)",
  },
  sub: {
    fontSize: "0.55rem",
    letterSpacing: "0.12em",
    color: "var(--muted, #999)",
  },
  status: {
    fontSize: "0.52rem",
    letterSpacing: "0.18em",
    textTransform: "uppercase",
    color: "var(--muted, #888)",
    whiteSpace: "nowrap",
  },
};

/* ── SCOPED CSS ── */
const css = `
  .na-img-frame:hover .na-img {
    transform: scale(1.05);
    filter: saturate(1.06) contrast(1.04);
  }
  .na-img-frame:hover .na-tile {
    transform: rotate(var(--rot, 0deg)) scale(1.03);
  }
  .na-img-frame:hover .na-img-overlay {
    opacity: 1;
  }
  .na-btn:focus-visible {
    outline: 1px solid #c9a96e;
    outline-offset: 3px;
  }

  @media (max-width: 680px) {
    .na-card { flex-direction: column !important; align-items: stretch !important; }
    .na-card > div:first-child { width: 100% !important; }
  }

  @media (prefers-reduced-motion: reduce) {
    .na-img, .na-tile, .na-img-overlay { transition: none !important; }
  }
`;