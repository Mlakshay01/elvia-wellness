import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { ld, productJsonLd, breadcrumbJsonLd, SITE_URL } from "../seo/schema";
import ProductReviews from "../components/ProductReviews";
import useProductReviews from "../hooks/useProductReviews";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";
import SizeSelector from "../components/SizeSelector";
import { getSizeOptions } from "../data/products";
import { HALLOWEEN_PRODUCTS } from "../config/halloween";
import ParticleCanvas from "./ParticleCanvas";
import { playBell } from "./audioEngine";
import PriceBlock, { OfferTag } from "./PriceBlock";
import { useBodyClass, useHalloweenActive, useParallax, useReducedMotion } from "./hooks";

/* ===========================================================================
   SHARED TEMPLATE for NOCTURNE and AZUR.
   Reuses the existing product-page logic (Helmet SEO + Product/Breadcrumb
   JSON-LD, reviews hook + component, cart, size selector, auth modal) with a
   new look driven by the per-product theme in src/config/halloween.js.

   Server render = full real content (no effect-only content). Everything
   decorative (particles, mist, parallax, pinned scroll, audio) is client-side.
   When the Halloween theme has ended the page stays a normal product page:
   same layout and colourway, but no particles, mist, sound or seasonal copy.
=========================================================================== */

const useIsoLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect;
const NOTE_KEYS = ["top", "heart", "base"];
const NOTE_LABEL = { top: "Top note", heart: "Heart note", base: "Base note" };
const abs = (u) => (u && u.startsWith("/") ? `${SITE_URL}${u}` : u);

function Details({ title, children, open }) {
  return (
    <details className="hw-acc" open={open}>
      <summary>{title}<span aria-hidden="true" /></summary>
      <div className="hw-acc-body">{children}</div>
    </details>
  );
}

export default function HalloweenProduct({ productKey }) {
  const p = HALLOWEEN_PRODUCTS[productKey];
  const other = HALLOWEEN_PRODUCTS[p.other];

  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();
  const themed = useHalloweenActive(); // false after the end date → Halloween extras hidden
  const reduced = useReducedMotion();
  const reviewsData = useProductReviews(p.id);

  useBodyClass("hw-dark");

  const rootRef = useRef(null);
  const heroRef = useRef(null);
  const pinRef = useRef(null);
  useParallax(heroRef, { enabled: !reduced });

  const [authType, setAuthType] = useState(null);
  const [added, setAdded] = useState(false);
  const [sizeId, setSizeId] = useState("30ml");
  const SIZE_OPTIONS = getSizeOptions(p.route);
  const selected = SIZE_OPTIONS.find((o) => o.id === sizeId) || SIZE_OPTIONS[SIZE_OPTIONS.length - 1];
  const price = selected?.price ?? p.price;
  const mrp = p.mrp; // struck-through MRP (display only)
  const sizeLabel = p.size; // real bottle size from config (getSizeOptions only knows "100 ml")

  /* ── scroll-reveal for everything below the fold (armed client-side only) ── */
  useIsoLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    root.classList.add("hw-armed");
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add("is-in"); io.unobserve(e.target); }
      }),
      { threshold: 0.12 },
    );
    root.querySelectorAll(".hw-io").forEach((el) => io.observe(el));
    return () => { io.disconnect(); root.classList.remove("hw-armed"); };
  }, [productKey]);

  /* ── scroll-pinned notes: the bottle stays fixed while top / heart / base fade in ── */
  const [scrollActive, setActive] = useState(NOTE_KEYS.length); // server: all visible
  const active = reduced ? NOTE_KEYS.length : scrollActive; // reduced motion: static, all visible
  useEffect(() => {
    const el = pinRef.current;
    if (!el || reduced) return;
    let raf = 0, last = -1;
    const update = () => {
      raf = 0;
      const r = el.getBoundingClientRect();
      const total = Math.max(1, r.height - window.innerHeight);
      const prog = Math.max(0, Math.min(1, -r.top / total));
      el.style.setProperty("--p", prog.toFixed(3));
      const a = prog < 0.1 ? 0 : prog < 0.38 ? 1 : prog < 0.66 ? 2 : 3;
      if (a !== last) { last = a; setActive(a); }
    };
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(update); };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, [reduced, productKey]);

  /* ── cart (same flow as the other perfume pages) ── */
  function handleOrderNow() {
    if (!user) return setAuthType("login");
    if (addToCart(selected.route)) playBell();
    navigate("/cart");
  }
  function handleAddToCart() {
    if (!user) return setAuthType("login");
    if (addToCart(selected.route)) playBell();
    setAdded(true);
    setTimeout(() => setAdded(false), 2000);
  }

  const goBuy = () =>
    document.getElementById("buy")?.scrollIntoView({ behavior: reduced ? "auto" : "smooth" });

  /* ── SEO ── */
  const title = themed
    ? `${p.name} — ${p.tagline} | Halloween Edition Eau de Parfum | KAEORN`
    : `${p.name} — Eau de Parfum | KAEORN`;
  const description = `${p.seoDescription} ${sizeLabel} bottle. Limited launch offer: ₹${price}${mrp > price ? ` (MRP ₹${mrp})` : ""}.`;
  const jsonImages = [p.images.front, p.images.threeQuarter, p.images.lifestyle].map(abs);
  const theme = p.theme;
  const cssVars = {
    "--t-from": theme.bgFrom, "--t-mid": theme.bgMid, "--t-to": theme.bgTo,
    "--t-glow": theme.glow, "--t-accent": theme.accent, "--t-soft": theme.accentSoft, "--t-text": theme.text,
  };
  const eyebrow = themed ? "THE HALLOWEEN EDITION" : "EAU DE PARFUM";

  return (
    <div ref={rootRef} className={`hw-product hw-product--${p.key}${themed ? " is-themed" : ""}`} style={cssVars}>
      <Helmet>
        <title>{title}</title>
        <meta name="description" content={description} />
        <link rel="canonical" href={`${SITE_URL}${p.route}`} />
        <meta property="og:title" content={title} />
        <meta property="og:description" content={`${p.tagline}. ${p.mood}. ${sizeLabel} · ₹${price}${mrp > price ? ` (MRP ₹${mrp})` : ""} — Made in India.`} />
        <meta property="og:image" content={abs(p.images.front)} />
        <meta property="og:url" content={`${SITE_URL}${p.route}`} />
        <meta property="og:type" content="product" />
        <script type="application/ld+json">
          {ld(productJsonLd(p.route, {
            description: `${p.name} by KAEORN — ${p.tagline}. ${p.mood} Eau de Parfum, ${sizeLabel}. Made in India.`,
            category: "Eau de Parfum",
            availability: "InStock",
            images: jsonImages,
            rating: reviewsData.summary,
            reviews: reviewsData.reviews,
          }))}
        </script>
        <script type="application/ld+json">
          {ld(breadcrumbJsonLd([{ name: "Home", path: "/" }, { name: p.name, path: p.route }]))}
        </script>
      </Helmet>

      {authType && <AuthModal type={authType} onClose={() => setAuthType(null)} />}

      {/* ───────────── 1. FULL-SCREEN HERO ───────────── */}
      <section className="hw-p-hero" ref={heroRef}>
        <div className="hw-p-bg" aria-hidden="true">
          {themed && <div className={`hw-mist hw-mist--p1 hw-mist--${theme.particle}`} />}
          {themed && <div className={`hw-mist hw-mist--p2 hw-mist--${theme.particle}`} />}
        </div>
        {themed && <ParticleCanvas type={theme.particle} desktop={52} mobile={18} className="hw-p-particles" />}

        <div className="hw-pname-bg" aria-hidden="true">{p.name}</div>

        <div className="hw-p-stage">
          {theme.light === "moon" && <span className="hw-moon" aria-hidden="true" />}
          {theme.light === "spot" && <span className="hw-spot" aria-hidden="true" />}
          <span className="hw-p-tilt">
            <span className="hw-p-float">
              <img
                className="hw-p-bottle"
                data-boot-wait=""
                src={p.images.front}
                width="400"
                height="700"
                alt={`${p.name} Eau de Parfum by KAEORN — ${p.tagline}`}
                decoding="async"
                fetchPriority="high"
                draggable="false"
              />
              {theme.floor && <img className="hw-reflect" src={p.images.front} alt="" aria-hidden="true" width="400" height="700" />}
            </span>
          </span>
        </div>

        <div className="hw-p-info">
          <p className="hw-eyebrow">{eyebrow}</p>
          <h1 className="hw-p-title">{p.name}</h1>
          <p className="hw-p-tagline">{p.tagline}</p>
          <OfferTag className="hw-offer-tag--hero" />
          <button type="button" className="hw-btn" onClick={goBuy}>
            Shop · ₹{price}{mrp > price && <del className="hw-btn-mrp">₹{mrp}</del>}
          </button>
        </div>
      </section>

      {/* ───────────── 2. SCROLL-PINNED NOTES ───────────── */}
      <section className={`hw-pin${reduced ? " hw-pin--static" : ""}`} ref={pinRef} aria-label={`${p.name} fragrance notes`}>
        <div className="hw-pin-sticky">
          <p className="hw-eyebrow hw-pin-eyebrow">The composition</p>
          <div className="hw-pin-grid">
            <ol className="hw-pin-notes" role="list">
              {NOTE_KEYS.map((k, i) => (
                <li key={k} className={`hw-note hw-note--${k}${active > i ? " is-on" : ""}`}>
                  <span className="hw-note-label">{NOTE_LABEL[k]}</span>
                  <span className="hw-note-name">{p.notes[k].name}</span>
                  <span className="hw-note-desc">{p.notes[k].desc}</span>
                </li>
              ))}
            </ol>
            <div className="hw-pin-bottle">
              <span className="hw-pin-halo" aria-hidden="true" />
              <img src={p.images.threeQuarter} width="400" height="700" loading="lazy" decoding="async" alt={`${p.name} bottle`} />
            </div>
          </div>
        </div>
      </section>

      {/* ───────────── 3. MACRO MOOD STRIP ───────────── */}
      <section className="hw-strip hw-io" aria-label={`${p.name} in detail`}>
        <p className="hw-eyebrow">{themed ? "Seen after dark" : "In detail"}</p>
        <div className="hw-strip-row">
          {[
            ["detail", "Cap and label, close up"],
            ["lifestyle", p.key === "nocturne" ? "With dark rose and smoke" : "With frosted glass and ice"],
            ["flatlay", "Flat-lay"],
          ].map(([k, cap]) => (
            <figure key={k} className={`hw-strip-item hw-strip-item--${k}`}>
              <img src={p.images[k]} loading="lazy" decoding="async" width={k === "flatlay" ? 1000 : 800} height={k === "flatlay" ? 800 : 1000} alt={`${p.name} — ${cap}`} />
              <figcaption>{cap}</figcaption>
            </figure>
          ))}
        </div>
      </section>

      {/* ───────────── 4. BUY ───────────── */}
      <section className="hw-buy hw-io" id="buy">
        <div className="hw-buy-art">
          <span className="hw-buy-glow" aria-hidden="true" />
          <img src={p.images.front} width="400" height="700" loading="lazy" decoding="async" alt={`${p.name} ${sizeLabel} bottle`} />
        </div>
        <div className="hw-buy-body">
          <p className="hw-eyebrow">{p.category} · {sizeLabel}</p>
          <h2 className="hw-h2">{p.name}</h2>
          <p className="hw-p-tagline">{p.tagline}</p>
          <p className="hw-buy-story">{p.story}</p>

          {SIZE_OPTIONS.length > 1 ? (
            <div className="hw-size-invert">
              <SizeSelector options={SIZE_OPTIONS} value={sizeId} onChange={setSizeId} />
            </div>
          ) : (
            <div className="hw-size">
              <span className="hw-size-label">Size</span>
              <span className="hw-size-pill">{sizeLabel}</span>
            </div>
          )}

          <OfferTag className="hw-offer-tag--buy" />
          <PriceBlock price={price} mrp={mrp} size="lg" />

          <div className="hw-buy-cta">
            <button type="button" className="hw-btn" onClick={handleOrderNow}>Order Now</button>
            <button type="button" className={`hw-btn hw-btn--ghost${added ? " is-added" : ""}`} onClick={handleAddToCart}>
              {added ? "Added ✓" : "Add to Cart"}
            </button>
          </div>

          <div className="hw-acc-wrap">
            <Details title="DESCRIPTION" open>{p.story}</Details>
            <Details title="HOW IT MAKES YOU FEEL">{p.feel}</Details>
            <Details title="KAEORN PHILOSOPHY">
              Kaeorn was built on the belief that luxury should feel effortless, not loud. Every fragrance is designed
              to enhance who you already are — not to make a statement, but to leave an impression. Quiet. Intentional.
              Made in India, for the world.
            </Details>
          </div>
        </div>
      </section>

      {/* ───────────── 5. REVIEWS (shared component, dark-inverted via CSS vars) ───────────── */}
      <div className="hw-reviews">
        <ProductReviews productId={p.id} productName={p.name} data={reviewsData} />
      </div>

      {/* ───────────── 6. COMPLETE THE SET ───────────── */}
      <section className="hw-set hw-io" style={{ "--o-from": other.theme.bgFrom, "--o-to": other.theme.bgTo, "--o-glow": other.theme.glow, "--o-accent": other.theme.accent }}>
        <Link to={other.route} className="hw-set-card">
          <img src={other.images.front} width="400" height="700" loading="lazy" decoding="async" alt={`${other.name} Eau de Parfum by KAEORN`} />
          <span className="hw-set-text">
            <span className="hw-eyebrow">Complete the set</span>
            <span className="hw-set-name">{other.name}</span>
            <span className="hw-set-tag">{other.tagline}</span>
            <span className="hw-set-cta">Discover →</span>
          </span>
        </Link>
      </section>
    </div>
  );
}
