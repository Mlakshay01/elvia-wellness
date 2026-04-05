// import { useNavigate } from "react-router-dom";
// import { useEffect, useRef, useState } from "react";
// import { Helmet } from "react-helmet-async";
// import Footer from "../components/Footer";

// /* IMAGES */
// const softSkinImg =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_900/v1769074475/ChatGPT_Image_Jan_22_2026_03_03_50_PM_kct4ad.png";

// const morningVeilImg =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/v1769083998/ChatGPT_Image_Jan_22_2026_05_41_58_PM_ainmkh.png";

// const quietWoodsImg =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/v1769081520/ChatGPT_Image_Jan_22_2026_05_01_01_PM_nzxsqv.png";

// export default function Perfume() {
//   const navigate = useNavigate();
//   const sectionRef = useRef(null);
//   const [visible, setVisible] = useState(false);
//   const [hovered, setHovered] = useState(null);

//   const isMobile =
//     typeof window !== "undefined" && window.innerWidth < 768;

//   useEffect(() => {
//     const obs = new IntersectionObserver(
//       ([e]) => e.isIntersecting && setVisible(true),
//       { threshold: 0.25 }
//     );
//     sectionRef.current && obs.observe(sectionRef.current);
//     return () => obs.disconnect();
//   }, []);

//   function imageStyle(index) {
//     if (isMobile) {
//       return {
//         ...styles.image,
//         filter: "none",
//         transform: "scale(1)",
//       };
//     }

//     return {
//       ...styles.image,
//       filter: hovered === index ? "grayscale(0%)" : "grayscale(100%)",
//       transform: hovered === index ? "scale(1.03)" : "scale(1)",
//     };
//   }

//   return (
//     <>
//     <Helmet>
//   <title>Perfume Collection | KAEORN</title>
//   <meta
//     name="description"
//     content="Explore KAEORN's luxury perfume collection including woody, fresh, and feminine fragrances designed for modern lifestyles."
//   />
// </Helmet>
//     <main style={styles.page}>
//       {/* ---------- HERO ---------- */}
//       <section style={styles.hero}>
//         <p style={styles.label}>KAEORN FRAGRANCE</p>
//         <h1 style={styles.title}>A quiet expression of scent</h1>
//         <p style={styles.subtitle}>
//           Crafted to sit close to skin — intimate, understated,
//           and deeply personal.
//         </p>
//       </section>

//       {/* ---------- COLLECTION ---------- */}
//       <section ref={sectionRef} style={styles.collection}>
//         {/* THÉ NOIR MEN */}
//         <Card
//           index={0}
//           image={softSkinImg}
//           title="THÉ NOIR"
//           type="MEN"
//           mood="Woody · Aromatic · Musky"
//           onClick={() => navigate("/perfume/soft-skin")}
//           hovered={hovered}
//           setHovered={setHovered}
//           visible={visible}
//           isMobile={isMobile}
//           imageStyle={imageStyle}
//         />

//         {/* MORNING VEIL */}
//         <Card
//           index={1}
//           image={morningVeilImg}
//           title="MORNING VEIL"
//           type="UNISEX"
//           mood="Clean · Airy · Luminous"
//           onClick={() => navigate("/perfume/morning-veil")}
//           hovered={hovered}
//           setHovered={setHovered}
//           visible={visible}
//           isMobile={isMobile}
//           imageStyle={imageStyle}
//           offset={!isMobile}
//         />

//         {/* SOIE FEMME */}
//         <Card
//           index={2}
//           image={quietWoodsImg}
//           title="SOIE FEMME"
//           type="WOMEN"
//           mood="Soft · Elegant · Feminine"
//           onClick={() => navigate("/perfume/quiet-woods")}
//           hovered={hovered}
//           setHovered={setHovered}
//           visible={visible}
//           isMobile={isMobile}
//           imageStyle={imageStyle}
//         />
//       </section>
//     </main>
//     </>
    
    
//   );
// }

// /* ---------- CARD COMPONENT ---------- */

// function Card({
//   index,
//   image,
//   title,
//   type,
//   mood,
//   onClick,
//   hovered,
//   setHovered,
//   visible,
//   isMobile,
//   imageStyle,
//   offset,
// }) {
//   return (
//     <div
//       style={{
//         ...styles.card,
//         ...(visible ? styles.show(index) : styles.hide),
//         ...(offset ? styles.offset : {}),
//       }}
//       onMouseEnter={() => !isMobile && setHovered(index)}
//       onMouseLeave={() => !isMobile && setHovered(null)}
//       onClick={onClick}
//     >
//       <div style={styles.imageWrap}>
//         <img src={image} alt={title} style={imageStyle(index)} />
//         <div style={styles.vignette} />

//         {/* Desktop hover */}
//         {!isMobile && hovered === index && (
//           <div style={styles.view}>View</div>
//         )}

//         {/* Mobile CTA */}
//         {isMobile && <div style={styles.mobileView}>Tap to view</div>}
//       </div>

//       <div style={styles.cardText}>
//         <span style={styles.index}>{type}</span>
//         <h3 style={styles.name}>{title}</h3>
//         <p style={styles.mood}>{mood}</p>
//         <p style={styles.concentration}>Eau de Parfum</p>
//       </div>
//     </div>
//   );
// }

// /* ---------------- STYLES ---------------- */

// const styles = {
//   page: {
//     fontFamily: "Inter, sans-serif",
//     paddingBottom: 140,
//     background:
//       "radial-gradient(1200px 600px at 50% -10%, #f4f1ed 0%, #ffffff 60%)",
//     paddingTop: 10,
//   },

//   hero: {
//     maxWidth: 700,
//     margin: "48px auto 96px", // ✅ FIXED TOP SPACE
//     padding: "0 24px",
//     textAlign: "center",
//   },

//   label: {
//     fontSize: 12,
//     letterSpacing: 3,
//     color: "#8a7f72",
//     marginBottom: 14,
//   },

//   title: {
//     fontSize: "clamp(32px,5vw,42px)",
//     fontWeight: 400,
//     marginBottom: 18,
//   },

//   subtitle: {
//     fontSize: 16,
//     lineHeight: 1.8,
//     color: "#666",
//   },

//   collection: {
//     maxWidth: 1200,
//     margin: "0 auto",
//     padding: "0 24px",
//     display: "grid",
//     gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
//     gap: 80,
//   },

//   hide: {
//     opacity: 0,
//     transform: "translateY(40px)",
//   },

//   show: (i) => ({
//     opacity: 1,
//     transform: "translateY(0)",
//     transition: `all 0.9s cubic-bezier(0.22,1,0.36,1) ${i * 0.18}s`,
//   }),

//   card: {
//     cursor: "pointer",
//     textAlign: "center",
//   },

//   offset: {
//     transform: "translateY(32px)",
//   },

//   imageWrap: {
//     position: "relative",
//     borderRadius: 28,
//     overflow: "hidden",
//     marginBottom: 22,
//   },

//   image: {
//     width: "100%",
//     height: 460,
//     objectFit: "cover",
//     transition: "all 0.8s ease",
//   },

//   vignette: {
//     position: "absolute",
//     inset: 0,
//     background:
//       "linear-gradient(to top, rgba(0,0,0,0.25), rgba(0,0,0,0) 60%)",
//     pointerEvents: "none",
//   },

//   view: {
//     position: "absolute",
//     bottom: 18,
//     right: 18,
//     background: "rgba(0,0,0,0.7)",
//     color: "#fff",
//     fontSize: 12,
//     padding: "8px 14px",
//     borderRadius: 20,
//   },

//   mobileView: {
//     position: "absolute",
//     bottom: 16,
//     left: "50%",
//     transform: "translateX(-50%)",
//     background: "rgba(0,0,0,0.75)",
//     color: "#fff",
//     fontSize: 12,
//     padding: "8px 16px",
//     borderRadius: 20,
//     letterSpacing: 0.8,
//   },

//   cardText: {
//     textAlign: "center",
//   },

//   index: {
//     fontSize: 12,
//     letterSpacing: 2.5,
//     color: "#888",
//     marginBottom: 6,
//     display: "block",
//   },

//   name: {
//     fontSize: 20,
//     fontWeight: 400,
//     marginBottom: 6,
//   },

//   mood: {
//     fontSize: 14,
//     color: "#777",
//     marginBottom: 6,
//   },

//   concentration: {
//     fontSize: 12,
//     letterSpacing: 1.4,
//     color: "#999",
//   },
// };
