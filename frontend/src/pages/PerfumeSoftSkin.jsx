import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useAuth } from "../context/AuthContext";
import { useCart } from "../context/CartContext";
import AuthModal from "../components/AuthModal";

/* ── IMAGES ── */
const galleryImages = [
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775277347/ChatGPT_Image_Apr_4_2026_10_05_23_AM_heqntp.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775277087/ChatGPT_Image_Apr_4_2026_10_00_20_AM_di0hwz.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775276759/ChatGPT_Image_Apr_4_2026_09_46_24_AM_sps175.png",
  "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775279065/ChatGPT_Image_Apr_4_2026_10_33_48_AM_rgmzrl.png",
];

const backgroundImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1770656016/be80b78fdc3c377d99bfa27e2cb6713f_oae83q.jpg";

const NOTES = [
  {
    src: "https://res.cloudinary.com/dvmntn6vf/image/upload/v1776063550/33f1fa71-31da-480d-b0fb-a7873bba7a42.png",
    name: "Apple",
    desc: "Crisp allure",
  },
  {
    src: "https://res.cloudinary.com/dvmntn6vf/image/upload/v1776063583/28d899ef-0fa4-4253-8b93-c9574c3b570a.png",
    name: "Lavender",
    desc: "Refined calm",
  },
  {
    src: "https://res.cloudinary.com/dvmntn6vf/image/upload/v1776063501/b97dc82a-ac51-42e7-81e6-44c504e1ad6f.png",
    name: "Tonka Bean",
    desc: "Warm sensuality",
  },
];

const REVIEWS = [
  { stars: 5, name: "Arjun, Delhi", text: "Feels expensive and composed." },
  { stars: 5, name: "Karan, Mumbai", text: "People asked what I was wearing." },
  {
    stars: 4,
    name: "Raghav, Bangalore",
    text: "Perfect for office and evenings.",
  },
];

/* ── ACCORDION — unified API: id / open / setOpen ── */
function Accordion({ title, id, open, setOpen, children }) {
  const isOpen = open === id;
  return (
    <div style={styles.accItem}>
      <div style={styles.accHead} onClick={() => setOpen(isOpen ? null : id)}>
        {title}
        <span>{isOpen ? "−" : "+"}</span>
      </div>
      {isOpen && <div style={styles.accBody}>{children}</div>}
    </div>
  );
}

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

  const galleryRef = useRef(null);
  const [currentImage, setCurrentImage] = useState(0);

  function goTo(n) {
    const idx = (n + galleryImages.length) % galleryImages.length;
    setCurrentImage(idx);
    galleryRef.current?.scrollTo({
      left: idx * galleryRef.current.offsetWidth,
      behavior: "smooth",
    });
  }

  const originalPrice = 1499;
  const price = 1399;
  const discount = Math.round(((originalPrice - price) / originalPrice) * 100);

  useEffect(() => {
    const io = new IntersectionObserver(
      ([e]) => e.isIntersecting && setVisible(true),
      { threshold: 0.25 },
    );
    if (sectionRef.current) io.observe(sectionRef.current);
    return () => io.disconnect();
  }, []);

  function handleOrderNow() {
    if (!user) return setAuthType("login");
    addToCart("/perfume/noir-party-perfume");
    navigate("/cart");
  }

  function handleAddToCart() {
    if (!user) return setAuthType("login");
    addToCart("/perfume/noir-party-perfume");
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
        <title>THÉ NOIR — Men's Eau de Parfum | KAEORN</title>
        <meta
          name="description"
          content="THÉ NOIR by Kaeorn — a woody, aromatic men's Eau de Parfum with notes of Apple, Lavender, and Tonka Bean. Quiet luxury, made in India. ₹1,399."
        />
        <link rel="canonical" href="https://kaeorn.com/perfume/noir-party-perfume" />
        <meta
          property="og:title"
          content="THÉ NOIR — Men's Eau de Parfum | KAEORN"
        />
        <meta
          property="og:description"
          content="A woody, aromatic fragrance with Apple, Lavender & Tonka Bean. Refined, intimate, made in India. ₹1,399."
        />
        <meta
          property="og:image"
          content="https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1775277347/ChatGPT_Image_Apr_4_2026_10_05_23_AM_heqntp.png"
        />
        <meta
          property="og:url"
          content="https://kaeorn.com/perfume/noir-party-perfume"
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
        ref={sectionRef}
        style={{
          ...styles.page,
          opacity: visible ? 1 : 0,
          transform: visible ? "translateY(0)" : "translateY(40px)",
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
            {galleryImages.map((img, i) => (
              <div key={i} style={styles.imageSlide}>
                <img
                  src={img}
                  alt={`THÉ NOIR Men Eau de Parfum by KAEORN — view ${i + 1}`}
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
            {galleryImages.map((_, i) => (
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
            ...styles.details,
            backgroundImage: `url(${backgroundImg})`,
          }}
        >
          <div style={styles.overlay} />
          <div style={styles.content}>
            <p style={styles.category}>MEN · EAU DE PARFUM</p>
            <h1 style={styles.title}>THÉ NOIR</h1>
            <span style={styles.volume}>100 ml</span>
            <span style={styles.volume}>Longevity: 8-10hrs</span>
            <span>25% Natural Oils Concentration</span>
            <br />

            <button style={styles.readMore} onClick={scrollToDesc}>
              Read more about this fragrance
            </button>
            {/* 
            <div style={styles.sale}>LAUNCH SALE</div> */}

            <div style={styles.priceRow}>
              <span style={styles.price}>₹{price}</span>
              {/* <span style={styles.strike}>₹{originalPrice}</span>
              <span style={styles.off}>{discount}% OFF</span> */}
            </div>

            <p style={styles.shortDesc}>
              Presence without announcement. THÉ NOIR is a woody, aromatic men's
              scent built to stay close to skin — composed, modern, and quietly
              unforgettable.
            </p>

            <div style={styles.cta}>
              <button style={styles.buy} onClick={handleOrderNow}>
                Order Now
              </button>
              <button
                style={{ ...styles.cart, ...(added ? styles.added : {}) }}
                onClick={handleAddToCart}
              >
                {added ? "Added ✓" : "Add to Cart"}
              </button>
            </div>

            {/* ── ACCORDIONS ── */}
            <div ref={descRef} style={styles.accordions}>
              <Accordion
                title="DESCRIPTION"
                id="description"
                open={open}
                setOpen={setOpen}
              >
                THÉ NOIR opens with a crisp, clean clarity — Apple cutting
                through with a freshness that's refined, not playful. Lavender
                brings a composed, almost architectural calm to the heart. Then
                Tonka Bean settles everything into a smooth, warm finish that
                sits close to the skin. This is a scent discovered up close. It
                doesn't project — it lingers. Masculine without trying, modern
                without effort.
              </Accordion>

              <Accordion
                title="HOW IT MAKES YOU FEEL"
                id="feel"
                open={open}
                setOpen={setOpen}
              >
                Calm confidence. The kind that doesn't need a room to notice.
                THÉ NOIR makes you feel grounded and put together — not because
                of what it says, but because of what it doesn't. Quiet control.
                Effortless presence.
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
                THÉ NOIR is an Eau de Parfum built for intimacy, not projection.
                On skin, it lasts 8–10 hours with a refined, skin-close sillage.
                The kind of scent that makes people lean in, not step back. It
                evolves slowly through the day — fresh at first, warm by
                evening.
              </Accordion>

              <Accordion
                title="HOW TO APPLY"
                id="apply"
                open={open}
                setOpen={setOpen}
              >
                Apply 2–4 sprays to clean, moisturized skin. Focus on pulse
                points — neck, wrists, collarbone. Don't rub after spraying. Let
                it settle and develop with your body heat for the smoothest,
                longest-lasting result.
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
                id="brand"
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
  imageSlide: { minWidth: "100%", scrollSnapAlign: "center" },
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
  content: { position: "relative", padding: "42px" },
  category: { fontSize: 12, letterSpacing: 2.5, color: "#888" },
  title: { fontSize: 42, fontWeight: 500, margin: "8px 0 4px" },
  volume: {
    fontSize: 11,
    color: "#9a9089",
    letterSpacing: "0.1em",
    fontFamily: "'DM Mono', monospace",
    display: "block",
    marginBottom: "12px",
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
  sale: {
    display: "inline-block",
    padding: "6px 14px",
    background: "#111",
    color: "#fff",
    borderRadius: 999,
    fontSize: 11,
    letterSpacing: 2,
    marginBottom: 14,
  },
  priceRow: {
    display: "flex",
    gap: 14,
    margin: "0 0 16px",
    alignItems: "center",
  },
  price: { fontSize: 28, fontWeight: 500 },
  strike: { textDecoration: "line-through", color: "#888" },
  off: { color: "#c62828", fontSize: 13 },
  shortDesc: { fontSize: 15.5, lineHeight: 1.85, color: "#555" },
  cta: { display: "flex", gap: 16, marginTop: 20 },
  buy: {
    padding: "16px 34px",
    borderRadius: 50,
    background: "#111",
    color: "#fff",
    border: "none",
    cursor: "pointer",
    fontSize: 14,
  },
  cart: {
    padding: "16px 34px",
    borderRadius: 50,
    border: "1px solid #111",
    background: "transparent",
    cursor: "pointer",
    fontSize: 14,
  },
  added: { background: "#111", color: "#fff" },
  accordions: { marginTop: 30, borderTop: "1px solid #eee" },
  accItem: { borderBottom: "1px solid #eee", padding: "20px 0" },
  accHead: {
    display: "flex",
    justifyContent: "space-between",
    cursor: "pointer",
    fontSize: 13,
    letterSpacing: 2,
    fontWeight: 500,
  },
  accBody: { marginTop: 14, fontSize: 15, lineHeight: 1.9, color: "#555" },
  notesWrap: {
    display: "flex",
    justifyContent: "space-between",
    gap: 24,
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
