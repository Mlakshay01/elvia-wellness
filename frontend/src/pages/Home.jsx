import { useNavigate } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import { Helmet } from "react-helmet-async";
import "../styles/Home/Hero.css";
import "../styles/Global/Utils.css";
import "../styles/Home/About.css";
import "../styles/Home/ComingSoon.css";
import "../styles/Home/PerfumeSection.css";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";
import { useCallback } from "react";
import NewArrivals from "../components/NewArrivals";
import AmbassadorSection from "../components/AmbassadorSection";

/* ── PRODUCT IMAGES ── */
const softSkinImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1775275614/ChatGPT_Image_Apr_4_2026_09_35_50_AM_pkb6za.png";
const morningVeilImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1775280305/ChatGPT_Image_Apr_4_2026_10_54_03_AM_fjvuq2.png";
const quietWoodsImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1775490015/ChatGPT_Image_Apr_6_2026_09_09_54_PM_olzzof.png";

/* ── MARQUEE ITEMS ── */
const MARQUEE_ITEMS = [
  "KAEORN",
  "·",
  "QUIET LUXURY",
  "·",
  "THÉ NOIR",
  "·",
  "SOIE FEMME",
  "·",
  "VEIL",
  "·",
  "EAU DE PARFUM",
  "·",
  "MADE IN INDIA",
  "·",
  "BECAUSE CARE DESERVES LUXURY",
  "·",
];

/* ── SCHEMA ── */
const ORGANIZATION_SCHEMA = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "Kaeorn",
  url: "https://kaeorn.com",
  description:
    "Kaeorn is a luxury perfume brand offering premium Eau de Parfum for men, women, and unisex wear. Made in India.",
  foundingLocation: {
    "@type": "Country",
    name: "India",
  },
  sameAs: ["https://instagram.com/kaeorn.co", "https://facebook.com/kaeorn"],
};

function PerfumeCard({
  to,
  img,
  gender,
  name,
  mood,
  concentration,
  price,
  mrp,
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
    const success = addToCart(to);
    setAdded(success ? "success" : "error");
    setTimeout(() => setAdded(null), 2000);
  }

  return (
    <div
      ref={cardRef}
      className="reveal"
      style={styles.perfumeCard}
      onClick={() => navigate(to)}
    >
      <div style={styles.perfumeImageWrap}> 
        <img
          src={img}
          alt={`${name} – ${gender} Eau de Parfum by Kaeorn`}
          style={styles.perfumeImage}
        />
        <div style={styles.perfumeOverlay}>
          <span style={styles.overlayText}>Discover →</span>
        </div>
      </div>
      <div style={styles.cardInfo}>
        <span style={styles.gender}>{gender} · EAU DE PARFUM</span>
        <h4 style={styles.name}>{name}</h4>
        <p style={styles.mood}>{mood}</p>
        <span style={styles.volume}>100 ml</span>
        <span style={styles.volume}>Longevity: 8-10hrs</span>
        <span>{concentration} Natural Oils</span>
        <div style={styles.priceRow}>
          <span style={styles.price}>{price}</span>
          <span style={styles.mrp}>{mrp}</span>
        </div>
        <div className="prod-actions">
          <button
            className="prod-explore"
            onClick={(e) => {
              e.stopPropagation();
              navigate(to);
            }}
          >
            Explore
          </button>
          <button
            className="prod-add"
            onClick={handleAdd}
            style={
              added ? { background: "var(--ink)", color: "var(--paper)" } : {}
            }
          >
            {added === "success"
              ? "Added ✓"
              : added === "error"
                ? "Couldn't add"
                : "+ Cart"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [visible, setVisible] = useState(false);
  const { addToCart } = useCart();
  const [showAuth, setShowAuth] = useState(false);

  /* ── PAGE ENTER ── */
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 120);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const coupon = params.get("coupon");
    if (coupon) {
      // save to localStorage so cart picks it up automatically
      localStorage.setItem("pendingCoupon", coupon.toUpperCase());
    }
  }, []);

  /* ── NOTIFY ME ── */
  function notifyMe(product) {
    const id = product === "cream" ? "emailCream" : "emailSpray";
    const input = document.getElementById(id);
    const email = input?.value?.trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      alert("Please enter a valid email address.");
      return;
    }
    // TODO: connect to your backend or email service (e.g. Mailchimp, Resend)
    alert(
      `Thank you. We'll reach you at ${email} when ${
        product === "cream" ? "Haetsal Veil™ Cream" : "Haetsal Veil™ Spray"
      } arrives.`,
    );
    if (input) input.value = "";
  }

  /* ── SCROLL REVEAL ── */
  const observerRef = useRef(null);

  useEffect(() => {
    observerRef.current = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            observerRef.current.unobserve(e.target);
          }
        });
      },
      { threshold: 0.1 },
    );

    document.querySelectorAll(".reveal").forEach((el) => {
      const rect = el.getBoundingClientRect();
      if (rect.top < window.innerHeight) {
        el.classList.add("visible");
      } else {
        observerRef.current.observe(el);
      }
    });
  }, []);

  const addReveal = useCallback((el) => {
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight) {
      el.classList.add("visible");
    } else if (observerRef.current) {
      observerRef.current.observe(el);
    }
  }, []);

  return (
    <>
      <Helmet>
        <title>KAEORN | Luxury Perfumes</title>
        <meta
          name="description"
          content="Kaeorn is a luxury perfume brand offering premium Eau de Parfum for men, women, and unisex wear. Discover THÉ NOIR, VEIL & SOIE FEMME. Made in India."
        />
        <meta name="msvalidate.01" content="67F58E3194DD09F40FDEBEC5C0E2A230" />
        <meta name="robots" content="index, follow" />
        <link rel="canonical" href="https://kaeorn.com/" />

        <meta property="og:title" content="KAEORN | Luxury Perfumes" />
        <meta
          property="og:description"
          content="Premium Eau de Parfum crafted for everyday elegance. Discover the world of Kaeorn."
        />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://kaeorn.com/" />
        <meta
          property="og:image"
          content="https://res.cloudinary.com/dvmntn6vf/image/upload/v1775275614/ChatGPT_Image_Apr_4_2026_09_35_50_AM_pkb6za.png"
        />
        <meta property="og:site_name" content="Kaeorn" />

        <script type="application/ld+json">
          {JSON.stringify(ORGANIZATION_SCHEMA)}
        </script>
      </Helmet>

      {showAuth && <AuthModal onClose={() => setShowAuth(false)} />}

      <main
        style={{
          opacity: visible ? 1 : 0,
          transform: visible ? "translateY(0)" : "translateY(12px)",
          transition: "all 0.9s cubic-bezier(0.22,1,0.36,1)",
        }}
      >
        {/* ── HERO ── */}
        <section className="hero" id="hero">
          <div className="hero-ambient" />
          <div className="hero-content">
            {/* eyebrow: brand · product type */}
            <p className="hero-eyebrow">KAEORN · EAU DE PARFUM</p>
            <h1 className="hero-title">
              Scent that
              <br />
              <em>stays with</em>
              <br />
              you.
            </h1>
            <p className="hero-sub">
              Not a statement. Not a performance.
              <br />A quiet presence — intimate, lasting, entirely your own.
            </p>
            <div className="hero-actions">
              <button
                onClick={() => {
                  document
                    .getElementById("collection")
                    ?.scrollIntoView({ behavior: "smooth" });
                }}
                className="btn-primary"
              >
                Explore Collection
              </button>
              <button
                onClick={() => {
                  document
                    .getElementById("about")
                    ?.scrollIntoView({ behavior: "smooth" });
                }}
                className="btn-outline"
              >
                Our Story
              </button>
            </div>
          </div>
          <div className="hero-scroll">
            <span>Scroll</span>
            <div className="scroll-track">
              <div className="scroll-thumb" />
            </div>
          </div>
        </section>

        {/* ── MARQUEE ── */}
        <div className="marquee-wrap">
          <div className="marquee-track">
            {[...MARQUEE_ITEMS, ...MARQUEE_ITEMS].map((item, i) => (
              <span
                key={i}
                className={`marquee-item${item === "·" ? " marquee-sep" : ""}`}
              >
                {item}
              </span>
            ))}
          </div>
        </div>

        {/*-- NEW COLLECTION --*/}
        <NewArrivals
          navigate={navigate}
          addReveal={addReveal}
          user={user}
          addToCart={addToCart}
          setShowAuth={setShowAuth}
        />

        {/* ── COLLECTION ── */}
        <section style={styles.perfumeSection} id="collection">
          <div ref={addReveal} className="reveal">
            <div className="collection-header">
              <div>
                <p className="section-eyebrow">THE COLLECTION</p>
                <h2 className="section-title">
                  Three moods.
                  <br />
                  <em>One skin.</em>
                </h2>
              </div>
              <div>
                <p className="collection-intro">
                  Each Kaeorn scent is built around a feeling — not a trend.
                  Wear the one that finds you.
                </p>
              </div>
            </div>
          </div>

          <div style={styles.perfumeRow}>
            {[
              {
                to: "/perfume/noir-party-perfume",
                img: softSkinImg,
                gender: "MEN",
                name: "THÉ NOIR",
                mood: "Fruity · Aromatic · Gourmand",
                concentration: "25%",
                price: "₹1,799",
                mrp: "₹3,599",
              },
              {
                to: "/perfume/veil-fresh-perfume",
                img: morningVeilImg,
                gender: "UNISEX",
                name: "VEIL",
                mood: "Citrus · Spicy · Woody",
                concentration: "25%",
                price: "₹1,799",
                mrp: "₹3,599",
              },
              {
                to: "/perfume/soie-femme-floral-perfume",
                img: quietWoodsImg,
                gender: "WOMEN",
                name: "SOIE FEMME",
                mood: "Floral · Roasted · Gourmand",
                concentration: "50%",
                price: "₹1,799",
                mrp: "₹3,599",
              },
            ].map((p) => (
              <PerfumeCard
                key={p.name}
                {...p}
                navigate={navigate}
                addToCart={addToCart}
                user={user}
                setShowAuth={setShowAuth}
                addReveal={addReveal}
              />
            ))}
          </div>
        </section>

        {/* ── ABOUT ── */}
        <section className="about" id="about">
          <div className="about-inner">
            <div className="about-top">
              <div>
                <p
                  ref={addReveal}
                  className="section-eyebrow about-eyebrow reveal"
                >
                  THE PHILOSOPHY
                </p>
                <h2
                  ref={addReveal}
                  className="about-title reveal reveal-delay-1"
                >
                  Luxury that
                  <br />
                  lives close
                  <br />
                  to <em>skin.</em>
                </h2>
              </div>
              <div ref={addReveal} className="about-body reveal reveal-delay-2">
                <p>
                  Kaeorn was built on one belief — that luxury should feel
                  effortless, not loud. We make perfumes for people who don't
                  need to announce themselves. Scents that settle into your skin
                  and become indistinguishable from you.
                </p>
                <p>
                  Every bottle is the result of careful work — layered notes,
                  considered compositions, and ingredients chosen for how they
                  feel on real skin. Not just how they smell in the air.
                </p>
                <p>
                  KAEORN means to endure and to radiate. That's the standard we
                  hold every fragrance to. Made in India, for the world.
                </p>
                <div className="about-quote">
                  <blockquote>"Because care deserves luxury."</blockquote>
                  <cite>— KAEORN</cite>
                </div>
              </div>
            </div>
            <div className="about-stats">
              <div ref={addReveal} className="stat reveal">
                <div className="stat-n">5</div>
                <div className="stat-l">Fragrances Crafted</div>
              </div>
              <div ref={addReveal} className="stat reveal reveal-delay-1">
                <div className="stat-n">30</div>
                <div className="stat-l">Happy Wearers</div>
              </div>
              <div ref={addReveal} className="stat reveal reveal-delay-2">
                <div className="stat-n">100%</div>
                <div className="stat-l">Cruelty Free</div>
              </div>
            </div>
          </div>
        </section>

        {/*-- Ambassador Program --*/}
        <AmbassadorSection addReveal={addReveal} navigate={navigate} />

        {/* ── COMING SOON ── */}
        <section className="coming" id="coming">
          <div className="coming-inner">
            <div className="coming-header">
              <p ref={addReveal} className="section-eyebrow reveal">
                WHAT'S NEXT
              </p>
              <h2
                ref={addReveal}
                className="section-title reveal reveal-delay-1"
              >
                Kaeorn
                <br />
                <em>beyond scent.</em>
              </h2>
            </div>
            <div className="coming-grid">
              <div ref={addReveal} className="coming-card coming-cream reveal">
                <div className="coming-soon-badge">Coming Soon</div>
                <div className="coming-icon">☀</div>
                <h3 className="coming-name">Haetsal Veil™ Cream</h3>
                <p className="coming-sub">Sunscream · Face</p>
                <p className="coming-desc">
                  Daily sun protection with a lightweight, skin-friendly finish.
                  Designed to shield against UV damage while keeping your skin
                  hydrated, smooth, and comfortable throughout the day.
                </p>
                <div className="coming-notify">
                  <input
                    type="email"
                    className="coming-email"
                    placeholder="Your email"
                    id="emailCream"
                  />
                  <button
                    className="coming-submit"
                    onClick={() => notifyMe("cream")}
                  >
                    Notify Me
                  </button>
                </div>
              </div>
              <div
                ref={addReveal}
                className="coming-card coming-spray reveal reveal-delay-1"
              >
                <div className="coming-soon-badge">Coming Soon</div>
                <div className="coming-icon">◈</div>
                <h3 className="coming-name">Haetsal Veil™ Spray</h3>
                <p className="coming-sub">Sunscreen · Body</p>
                <p className="coming-desc">
                  Easy, even sun protection for everyday use. A quick-apply body
                  spray that protects against UV exposure without heaviness,
                  leaving the skin feeling light and non-sticky.
                </p>
                <div className="coming-notify">
                  <input
                    type="email"
                    className="coming-email"
                    placeholder="Your email"
                    id="emailSpray"
                  />
                  <button
                    className="coming-submit"
                    onClick={() => notifyMe("spray")}
                  >
                    Notify Me
                  </button>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </>
  );
}

/* ── STYLES ── */
const styles = {
  perfumeSection: {
    padding: "clamp(5rem, 10vw, 9rem) clamp(1.5rem, 5vw, 4rem)",
    maxWidth: 1400,
    margin: "0 auto",
  },
  perfumeIntro: {
    maxWidth: 620,
    margin: "0 auto 5rem",
    textAlign: "center",
  },
  perfumeSubtitle: {
    fontSize: "clamp(.85rem, 1.8vw, 1rem)",
    lineHeight: 1.9,
    color: "var(--muted)",
    marginTop: "1.25rem",
  },
  perfumeRow: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
    gap: "1.5px",
    background: "var(--border)",
    marginBottom: "4rem",
  },
  perfumeCard: {
    background: "var(--paper)",
    cursor: "pointer",
    position: "relative",
    overflow: "hidden",
  },
  offset: {
    transform: "translateY(32px)",
  },
  perfumeImageWrap: {
    position: "relative",
    overflow: "hidden",
    aspectRatio: "3 / 4",
  },
  perfumeImage: {
    width: "100%",
    height: "100%",
    objectFit: "cover",
    display: "block",
    transition: "transform .9s cubic-bezier(0.25,0.46,0.45,0.94)",
  },
  perfumeOverlay: {
    position: "absolute",
    inset: 0,
    background:
      "linear-gradient(to top, rgba(13,12,11,.6) 0%, transparent 50%)",
    opacity: 0,
    transition: "opacity .4s",
    display: "flex",
    alignItems: "flex-end",
    padding: "1.5rem",
  },
  overlayText: {
    fontFamily: "'DM Mono', monospace",
    fontSize: ".65rem",
    letterSpacing: ".15em",
    textTransform: "uppercase",
    color: "var(--paper)",
  },
  cardInfo: {
    padding: "1.75rem 1.75rem 2rem",
    borderTop: "1px solid var(--border)",
  },
  gender: {
    fontFamily: "'DM Mono', monospace",
    fontSize: ".6rem",
    letterSpacing: ".2em",
    color: "var(--muted)",
    textTransform: "uppercase",
    display: "block",
    marginBottom: ".6rem",
  },
  name: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "1.65rem",
    fontWeight: 400,
    letterSpacing: ".02em",
    lineHeight: 1.1,
    marginBottom: ".5rem",
  },
  mood: {
    fontFamily: "'DM Mono', monospace",
    fontSize: ".62rem",
    letterSpacing: ".1em",
    color: "var(--muted)",
    marginBottom: "1rem",
  },
  volume: {
    fontFamily: "'DM Mono', monospace",
    fontSize: ".6rem",
    letterSpacing: ".15em",
    color: "var(--muted)",
    textTransform: "uppercase",
    display: "block",
    marginBottom: "1rem",
  },
  priceRow: {
    display: "flex",
    alignItems: "baseline",
    gap: ".75rem",
  },
  price: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "1.5rem",
    fontWeight: 400,
  },
  mrp: {
    fontSize: ".8rem",
    color: "var(--muted)",
    textDecoration: "line-through",
  },
  viewAll: {
    margin: "0 auto",
    display: "block",
    padding: ".85rem 2.25rem",
    background: "var(--ink)",
    color: "var(--paper)",
    border: "none",
    fontFamily: "'DM Mono', monospace",
    fontSize: ".7rem",
    letterSpacing: ".15em",
    textTransform: "uppercase",
    cursor: "pointer",
    transition: "background .2s",
  },
};
