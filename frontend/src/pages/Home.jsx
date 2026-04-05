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





/* ── PRODUCT IMAGES ── */
const softSkinImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1775275614/ChatGPT_Image_Apr_4_2026_09_35_50_AM_pkb6za.png";
const morningVeilImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1775280305/ChatGPT_Image_Apr_4_2026_10_54_03_AM_fjvuq2.png";
const quietWoodsImg =
  "https://res.cloudinary.com/dvmntn6vf/image/upload/v1769081520/ChatGPT_Image_Jan_22_2026_05_01_01_PM_nzxsqv.png";


/* ── MARQUEE ITEMS ── */
const MARQUEE_ITEMS = [
  "KAEORN", "·", "QUIET LUXURY", "·", "THÉ NOIR MEN", "·",
  "SOIÉ FEMME", "·", "VEIL", "·", "EAU DE PARFUM", "·",
  "MADE IN INDIA", "·", "BECAUSE CARE DESERVES LUXURY", "·",
];

export default function Home() {
  const navigate = useNavigate();
  const { user } = useAuth();  
  const [visible, setVisible] = useState(false);
  const revealRefs = useRef([]);
  const { addToCart } = useCart();
  const [added, setAdded] = useState(false);
   const [showAuth, setShowAuth] = useState(false);

  /* ── CURSOR ── */
 useEffect(() => {
  const cr   = document.getElementById('cr');
  const cdot = document.getElementById('cd');
  if (!cr || !cdot) return;

  let mx = 0, my = 0, cx = 0, cy = 0;

  const onMove = e => {
    mx = e.clientX; my = e.clientY;
    cdot.style.left = mx + 'px';
    cdot.style.top  = my + 'px';
    cr.classList.add('visible');
    cdot.classList.add('visible');
  };

  let raf;
  const animCursor = () => {
    cx += (mx - cx) * .12;
    cy += (my - cy) * .12;
    // position the RING itself, not its parent wrapper
    cr.style.left = cx + 'px';
    cr.style.top  = cy + 'px';
    raf = requestAnimationFrame(animCursor);
  };
  raf = requestAnimationFrame(animCursor);

  document.addEventListener('mousemove', onMove);

  const hoverEls = document.querySelectorAll('a, button, .prod-card');
  hoverEls.forEach(el => {
    el.addEventListener('mouseenter', () => cr.classList.add('grow'));
    el.addEventListener('mouseleave', () => cr.classList.remove('grow'));
  });

  return () => {
    document.removeEventListener('mousemove', onMove);
    cancelAnimationFrame(raf);
  };
 }, []);


  /* ── PAGE ENTER ── */
  useEffect(() => {
    document.title = "KAEORN | Luxury Wellness Perfumes in India";
    let meta = document.querySelector("meta[name='description']");
    if (!meta) {
      meta = document.createElement("meta");
      meta.name = "description";
      document.head.appendChild(meta);
    }
    meta.content =
      "Kaeorn Wellness is a luxury fragrance brand offering premium perfumes for men, women, and unisex wear. Discover refined scents crafted for everyday elegance.";
    const t = setTimeout(() => setVisible(true), 120);
    return () => clearTimeout(t);
  }, []);

  /* ── SCROLL REVEAL ── */
 const observerRef = useRef(null);

 useEffect(() => {
  observerRef.current = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add("visible");
        observerRef.current.unobserve(e.target);
      }
    });
  });
 }, []);

const addReveal = (el) => {
  if (el && observerRef.current) {
    observerRef.current.observe(el);

    // fallback if already visible
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight) {
      el.classList.add("visible");
    }
  }
};

 function PerfumeCard({ to, img, gender, name, mood, price, mrp, navigate, addToCart, user, setShowAuth, addReveal }) {
  const [added, setAdded] = useState(false);


  function handleAdd(e) {
    e.stopPropagation(); // prevent card navigate
    if (!user) 
      { setShowAuth(true);
         return; 
        }
        const success = addToCart(to);

        if(success){
          setAdded("success");
        }else{
          setAdded("error");
        }

        setTimeout(() => setAdded(null), 2000);
  }

  return (
    <div ref={addReveal} className="reveal" style={styles.perfumeCard} onClick={() => navigate(to)}>
      <div style={styles.perfumeImageWrap}>
        <img src={img} alt={name} style={styles.perfumeImage} />
        <div style={styles.perfumeOverlay}>
          <span style={styles.overlayText}>Discover →</span>
        </div>
      </div>
      <div style={styles.cardInfo}>
        <span style={styles.gender}>{gender} · EAU DE PARFUM</span>
        <h4 style={styles.name}>{name}</h4>
        <p style={styles.mood}>{mood}</p>
        <div style={styles.priceRow}>
          <span style={styles.price}>{price}</span>
          <span style={styles.mrp}>{mrp}</span>
        </div>
        <div className="prod-actions">
          <button className="prod-explore" onClick={(e) => { e.stopPropagation(); navigate(to); }}>
            Explore
          </button>
          <button
            className="prod-add"
            onClick={handleAdd}
            style={added ? { background: "var(--ink)", color: "var(--paper)" } : {}}
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



  return (
    <>
     <Helmet>
  <title>KAEORN | Luxury Wellness Perfumes in India</title>
  <meta
    name="description"
    content="Kaeorn Wellness is a luxury fragrance brand offering premium perfumes for men, women, and unisex wear. Discover refined scents crafted for everyday elegance."
  />
</Helmet>
     {showAuth && <AuthModal onClose={() => setShowAuth(false)} />}
    
    {/* -- CURSOR ------ */}
      <div className="cursor" id="cursorRing">
        <div className="cursor-ring" id="cr"></div>
      </div>
      
      <div className="cursor-dot" id="cd"></div>

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
          <p className="hero-eyebrow">KAEORN FRAGRANCE</p>
          <h1 className="hero-title">
            A quiet<br /><em>expression</em><br />of scent
          </h1>
          <p className="hero-sub">
            Crafted to sit close to skin — intimate, understated, and deeply personal.
          </p>
          <div className="hero-actions">
            <a href="#collection" className="btn-primary">Explore Collection</a>
            <a href="#about" className="btn-outline">Our Story</a>
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
          {/* Duplicated for seamless loop */}
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

      {/* ── PERFUME SECTION ── */}
      <section style={styles.perfumeSection} id="collection">
        <div ref={addReveal} className="reveal">
          <div className="collection-header">
            <div>
              <p className="section-eyebrow">THE COLLECTION</p>
              <h2 className="section-title" ref={addReveal}>
                Three moods.<br /><em>One world.</em>
              </h2>
            </div>
            <div>
              <p className="collection-intro">
                Where skincare meets the art of perfume. Crafted for modern skin,
                softly perfumed — each scent a quiet statement.
              </p>
            </div>
          </div>
        </div>


        <div style={styles.perfumeRow}>
          {[
            {
              to: "/perfume/soft-skin",
              img: softSkinImg,
              gender: "MEN",
              name: "THÉ NOIR",
              mood: "Woody · Aromatic · Musky",
              price: "₹1,199",
              mrp: "₹1,499",
            },
            {
              to: "/perfume/morning-veil",
              img: morningVeilImg,
              gender: "UNISEX",
              name: "MORNING VEIL",
              mood: "Clean · Airy · Luminous",
              price: "₹1,199",
              mrp: "₹1,499",
            },
            {
              to: "/perfume/quiet-woods",
              img: quietWoodsImg,
              gender: "WOMEN",
              name: "SOIE FEMME",
              mood: "Luxury · Feminine",
              price: "₹1,199",
              mrp: "₹1,499",
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
          
        {/* <button style={styles.viewAll} onClick={() => navigate("/perfume")}>
          Explore Full Collection
        </button> */}
      </section>


      
      {/*-- ABOUT --*/}
      <section className="about" id="about">
        <div className="about-inner">
        <div className="about-top">
        <div>
        <p ref={addReveal} className="section-eyebrow about-eyebrow reveal">THE PHILOSOPHY</p>
        <h2 ref={addReveal} className="about-title reveal reveal-delay-1">
          Where skincare<br/>meets the art<br/>of <em>perfume.</em>
        </h2>
      </div>
      <div ref={addReveal} className="about-body reveal reveal-delay-2">
        <p>
          KAEORN was born from a single conviction: that fragrance should feel like a second skin, not a statement. We craft scents designed to linger softly and elevate your daily ritual.
        </p>
        <p>
          Each KAEORN fragrance is built around a human truth — a feeling worth preserving. Our perfumers work with the finest raw materials to create olfactory signatures that are intimate, understated, and deeply personal.
        </p>
        <p>
          The name KAEORN brings together two ideas — to endure, and to radiate. We make things that stay with you.
        </p>
        <div className="about-quote">
          <blockquote>"Because care deserves luxury."</blockquote>
          <cite>— KAEORN Brand Philosophy</cite>
        </div>
      </div>
    </div>
    <div className="about-stats">
      <div ref={addReveal} className="stat reveal">
        <div className="stat-n">3</div>
        <div className="stat-l">Fragrances Crafted</div>
      </div>
      <div ref={addReveal} className="stat reveal reveal-delay-1">
        <div className="stat-n">500+</div>
        <div className="stat-l">Happy Wearers</div>
      </div>
      <div ref={addReveal} className="stat reveal reveal-delay-2">
        <div className="stat-n">100%</div>
        <div className="stat-l">Cruelty Free</div>
      </div>
    </div>
    </div>
    </section>

      {/*-- COMING SOON --*/}
      <section className="coming" id="coming">
      <div className="coming-inner">
    <div className="coming-header">
      <p ref={addReveal} className="section-eyebrow reveal">WHAT'S NEXT</p>
      <h2 ref={addReveal} className="section-title reveal reveal-delay-1">The world of<br/>KAEORN <em>expands.</em></h2>
    </div>
    <div className="coming-grid">
      <div ref={addReveal} className="coming-card coming-cream reveal">
        <div className="coming-soon-badge">Coming Soon</div>
        <div className="coming-icon">☀</div>
        <h3 className="coming-name">Haetsal Veil™ Cream</h3>
        <p className="coming-sub">Skincare Line</p>
        <p className="coming-desc">
          Protection that feels like skin, not armor. Luxurious, softly scented skincare crafted for faces that refuse to hide. The first intersection of KAEORN fragrance and skincare.
        </p>
        <div className="coming-notify">
          <input type="email" className="coming-email" placeholder="Enter your email" id="emailCream"/>
          <button className="coming-submit" onClick={()=>"notifyMe('cream')"}>Notify Me</button>
        </div>
      </div>
      <div ref={addReveal} className="coming-card coming-spray reveal reveal-delay-1">
        <div className="coming-soon-badge">Coming Soon</div>
        <div className="coming-icon">◈</div>
        <h3 className="coming-name">Haetsal Veil™ Spray</h3>
        <p className="coming-sub">Body Spray Line</p>
        <p className="coming-desc">
          The scent that moves with you. Everyday body sprays with the same depth as our perfumes — lighter, breezier, and built for every moment of your day.
        </p>
        <div className="coming-notify">
          <input type="email" className="coming-email" placeholder="Enter your email" id="emailSpray"/>
          <button className="coming-submit" onClick={()=>"notifyMe('spray')"}>Notify Me</button>
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
    background: "linear-gradient(to top, rgba(13,12,11,.6) 0%, transparent 50%)",
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
