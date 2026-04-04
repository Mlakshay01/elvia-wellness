import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";

/* ---------------- GALLERY IMAGES ---------------- */
const galleryImages = [
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775277347/ChatGPT_Image_Apr_4_2026_10_05_23_AM_heqntp.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775277087/ChatGPT_Image_Apr_4_2026_10_00_20_AM_di0hwz.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775276759/ChatGPT_Image_Apr_4_2026_09_46_24_AM_sps175.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769079569/ChatGPT_Image_Jan_22_2026_04_28_32_PM_fxa20n.png",
];

/* ---------------- BACKGROUND IMAGE ---------------- */
const backgroundImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1770656016/be80b78fdc3c377d99bfa27e2cb6713f_oae83q.jpg";

export default function PerfumeSoftSkin() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();

  const sectionRef = useRef(null);
  const descRef = useRef(null);

  const [visible, setVisible] = useState(false);
  const [authType, setAuthType] = useState(null);
  const [added, setAdded] = useState(false);
  const [open, setOpen] = useState("description");

  const product = {
    id: "the-noir-men",
    name: "KAEORN — THÉ NOIR MEN",
    price: 1199,
    originalPrice: 1499,
  };

  const discount = Math.round(
    ((product.originalPrice - product.price) / product.originalPrice) * 100,
  );

  useEffect(() => {
    const io = new IntersectionObserver(
      ([e]) => e.isIntersecting && setVisible(true),
      { threshold: 0.25 },
    );
    if (sectionRef.current) io.observe(sectionRef.current);
    return () => io.disconnect();
  }, []);

  function handleBuy() {
    if (!user) return setAuthType("login");
    addToCart("/perfume/soft-skin");
    navigate("/cart");
  }

  function handleAdd() {
    if (!user) return setAuthType("login");
    addToCart("/perfume/soft-skin");
    setAdded(true);
    setTimeout(() => setAdded(false), 2000);
  }

  function scrollToDesc() {
    descRef.current?.scrollIntoView({ behavior: "smooth" });
    setOpen("description");
  }

  return (
    <>
      <Helmet>
        <title>THÉ NOIR Perfume | KAEORN</title>
        <meta
          name="description"
          content="Shop THÉ NOIR by KAEORN — a woody, aromatic fragrance for men. Long-lasting, refined, and crafted for everyday luxury."
        />
      </Helmet>
      {authType && (
        <AuthModal type={authType} onClose={() => setAuthType(null)} />
      )}

      <section
        ref={sectionRef}
        style={{
          ...styles.page,
          opacity: visible ? 1 : 0,
          transform: visible ? "translateY(0)" : "translateY(40px)",
        }}
      >
        {/* ---------------- IMAGE GALLERY ---------------- */}
        <div style={styles.gallery}>
          {galleryImages.map((img, i) => (
            <div key={i} style={styles.imageSlide}>
              <img src={img} alt="" style={styles.galleryImage} />
            </div>
          ))}
        </div>

        {/* ---------------- TEXT SECTION ---------------- */}
        <div
          style={{
            ...styles.details,
            backgroundImage: `url(${backgroundImg})`,
          }}
        >
          <div style={styles.overlay} />

          <div style={styles.content}>
            <p style={styles.category}>MEN · EAU DE PARFUM</p>

            <h1 style={styles.title}>THÉ NOIR MEN</h1>

            <button style={styles.readMore} onClick={scrollToDesc}>
              Read more about this fragrance
            </button>

            <div style={styles.sale}>LAUNCH SALE</div>

            <div style={styles.priceRow}>
              <span style={styles.price}>₹{product.price}</span>
              <span style={styles.strike}>₹{product.originalPrice}</span>
              <span style={styles.off}>{discount}% OFF</span>
            </div>

            <p style={styles.shortDesc}>
              A refined masculine fragrance crafted for presence without excess.
              Smooth, modern and quietly addictive — designed to feel intimate
              yet unforgettable.
            </p>

            <div style={styles.cta}>
              <button style={styles.buy} onClick={handleBuy}>
                Buy Now
              </button>

              <button
                style={{
                  ...styles.cart,
                  ...(added ? styles.added : {}),
                }}
                onClick={handleAdd}
              >
                {added ? "Added ✓" : "Add to Cart"}
              </button>
            </div>

            {/* ---------------- ACCORDIONS ---------------- */}
            <div ref={descRef} style={styles.accordions}>
              <Accordion
                title="DESCRIPTION"
                open={open === "description"}
                onClick={() => setOpen("description")}
              >
                THÉ NOIR MEN opens with a refined clean aura that immediately
                signals understated luxury. As the fragrance settles, a warm,
                softly sweet depth emerges — smooth, composed, and undeniably
                masculine. It feels polished rather than loud, intimate rather
                than overpowering. This is a scent designed to be discovered up
                close, leaving a quiet impression that lingers long after the
                moment has passed.
              </Accordion>

              <Accordion
                title="HOW IT MAKES YOU FEEL"
                open={open === "feel"}
                onClick={() => setOpen("feel")}
              >
                Wearing THÉ NOIR MEN evokes calm confidence and quiet control.
                It enhances your presence without announcing itself. You feel
                grounded, refined, and effortlessly put together — the kind of
                confidence that doesn’t need validation. Ideal for moments where
                subtle impact matters more than attention.
              </Accordion>

              <Accordion
                title="PERFORMANCE"
                open={open === "performance"}
                onClick={() => setOpen("performance")}
              >
                Designed for endurance, THÉ NOIR MEN lasts up to 24 hours on
                skin. Its projection remains refined and close, creating a
                premium aura rather than an overpowering trail. The scent
                evolves slowly throughout the day, maintaining elegance from
                first spray to final note.
              </Accordion>

              <Accordion
                title="HOW TO APPLY"
                open={open === "apply"}
                onClick={() => setOpen("apply")}
              >
                Apply 2–4 sprays to pulse points such as the neck, wrists, and
                collarbone. Avoid rubbing after application to allow the
                fragrance to develop naturally. Best applied on moisturized skin
                for smoother diffusion and longer wear.
              </Accordion>

              <Accordion
                title="REVIEWS FROM INDIA"
                open={open === "reviews"}
                onClick={() => setOpen("reviews")}
              >
                ★★★★★ Arjun, Delhi — “Feels expensive and composed.” ★★★★★
                Karan, Mumbai — “People asked what I was wearing.” ★★★★☆ Raghav,
                Bangalore — “Perfect for office and evenings.”
              </Accordion>

              <Accordion
                title="KAEORN PHILOSOPHY"
                open={open === "brand"}
                onClick={() => setOpen("brand")}
              >
                KAEORN is built on the belief that true luxury is quiet. Our
                fragrances are designed to complement individuality, not
                overpower it. Every creation is intentional — refined, intimate,
                and crafted for modern rituals where subtlety defines
                sophistication.
              </Accordion>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

/* ---------------- ACCORDION ---------------- */
function Accordion({ title, open, onClick, children }) {
  return (
    <div style={styles.accItem}>
      <div style={styles.accHead} onClick={onClick}>
        {title}
        <span>{open ? "−" : "+"}</span>
      </div>
      {open && <div style={styles.accBody}>{children}</div>}
    </div>
  );
}

/* ---------------- STYLES ---------------- */
const styles = {
  page: {
    maxWidth: 1280,
    margin: "75px auto",
    padding: "0 24px",
    display: "flex",
    flexWrap: "wrap",
    gap: 80,
    fontFamily: "Inter, sans-serif",
    transition: "all .8s ease",
  },

  gallery: {
    flex: 1,
    minWidth: 320,
    display: "flex",
    overflowX: "auto",
    gap: 20,
    scrollSnapType: "x mandatory",
  },

  imageSlide: {
    minWidth: "100%",
    scrollSnapAlign: "center",
  },

  galleryImage: {
    width: "100%",
    borderRadius: 26,
    objectFit: "cover",
    boxShadow: "0 30px 60px rgba(0,0,0,0.08)",
  },

  details: {
    flex: 1,
    minWidth: 320,
    position: "relative",
    backgroundSize: "cover",
    backgroundPosition: "center",
    borderRadius: 26,
    overflow: "hidden",
  },

  overlay: {
    position: "absolute",
    inset: 0,
    background: "rgba(255,255,255,0.82)",
  },

  content: {
    position: "relative",
    padding: "42px",
  },

  category: { fontSize: 12, letterSpacing: 2.5, color: "#888" },
  title: { fontSize: 42, fontWeight: 500 },

  readMore: {
    border: "none",
    background: "transparent",
    fontSize: 13,
    cursor: "pointer",
    textDecoration: "underline",
    marginBottom: 12,
  },

  sale: {
    display: "inline-block",
    padding: "6px 14px",
    background: "#111",
    color: "#fff",
    borderRadius: 999,
    fontSize: 11,
    letterSpacing: 2,
  },

  priceRow: { display: "flex", gap: 14, margin: "16px 0" },
  price: { fontSize: 28, fontWeight: 500 },
  strike: { textDecoration: "line-through", color: "#888" },
  off: { color: "#c62828", fontSize: 13 },

  shortDesc: {
    fontSize: 16,
    lineHeight: 1.8,
    color: "#555",
  },

  cta: { display: "flex", gap: 16, marginTop: 20 },

  buy: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "#111",
    color: "#fff",
    border: "none",
  },

  cart: {
    padding: "16px 34px",
    borderRadius: 50,
    border: "1px solid #111",
    background: "transparent",
  },

  added: { background: "#111", color: "#fff" },

  accordions: {
    marginTop: 30,
    borderTop: "1px solid #eee",
  },

  accItem: { borderBottom: "1px solid #eee", padding: "20px 0" },

  accHead: {
    display: "flex",
    justifyContent: "space-between",
    cursor: "pointer",
    fontSize: 13,
    letterSpacing: 2,
    fontWeight: 500,
  },

  accBody: {
    marginTop: 14,
    fontSize: 15,
    lineHeight: 1.9,
    color: "#555",
  },
};
