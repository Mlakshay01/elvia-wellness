// import { useState, useEffect, useRef } from "react";
// import { useNavigate } from "react-router-dom";
// import { useAuth } from "./context/AuthContext";
// import { useCart } from "./context/CartContext";
// import AuthModal from "./components/AuthModal";
// import Footer from "./components/Footer";


// /* ---------------- CLOUDINARY IMAGES ---------------- */
// const img2 =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768897906/ChatGPT_Image_Jan_20_2026_01_53_50_PM_ekdg0l.png";
// const img3 =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768897413/ChatGPT_Image_Jan_20_2026_01_53_06_PM_p5fr81.png";
// const img4 =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768897641/ChatGPT_Image_Jan_20_2026_01_54_12_PM_nkfbak.png";
// const img5 =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768899353/ChatGPT_Image_Jan_20_2026_02_25_23_PM_no7tvv.png";
// const img6 =
//   "https://res.cloudinary.com/dvmntn6vf/image/upload/f_auto,q_auto,w_800/v1768900206/ChatGPT_Image_Jan_20_2026_02_39_22_PM_y2argn.png";

// const images = [img2, img3, img4, img5, img6];

// export default function App() {
//   const navigate = useNavigate();
//   const { user } = useAuth();
//   const { addToCart } = useCart();

//   const productRef = useRef(null);
//   const [visible, setVisible] = useState(false);
//   const [activeImage, setActiveImage] = useState(images[0]);
//   const [authType, setAuthType] = useState(null);

//   // NEW: add-to-cart feedback
//   const [added, setAdded] = useState(false);

//   useEffect(() => {
//     const obs = new IntersectionObserver(
//       ([e]) => e.isIntersecting && setVisible(true),
//       { threshold: 0.25 }
//     );
//     productRef.current && obs.observe(productRef.current);
//     return () => obs.disconnect();
//   }, []);

//   const product = {
//     id: "haetsal-veil-spf50", // ❗ DO NOT CHANGE
//     name: "Haetsal Veil™ SPF 50+ PA++++",
//     price: 2499,
//   };

//   function handleOrderNow() {
//     if (!user) {
//       setAuthType("login");
//       return;
//     }

//     addToCart({
//       ...product,
//       image: activeImage,
//       quantity: 1,
//     });

//     navigate("/cart");
//   }

//   function handleAddToCartOnly() {
//     if (!user) {
//       setAuthType("login");
//       return;
//     }

//     addToCart({
//       ...product,
//       image: activeImage,
//       quantity: 1,
//     });

//     setAdded(true);
//     setTimeout(() => setAdded(false), 2200);
//   }

//   return (
//     <>
//       {authType && (
//         <AuthModal type={authType} onClose={() => setAuthType(null)} />
//       )}

//       {/* ---------------- PRODUCT SECTION ---------------- */}
//       <section
//         ref={productRef}
//         style={{
//           ...styles.productSection,
//           ...(visible ? styles.show : styles.hide),
//         }}
//       >
//         {/* IMAGES */}
//         <div style={styles.imageColumn}>
//           <img
//             src={activeImage}
//             alt={product.name}
//             style={styles.mainImage}
//           />

//           <div style={styles.thumbnailRow}>
//             {images.map((img, i) => (
//               <img
//                 key={i}
//                 src={img}
//                 alt=""
//                 onClick={() => setActiveImage(img)}
//                 style={{
//                   ...styles.thumbnail,
//                   opacity: activeImage === img ? 1 : 0.45,
//                 }}
//               />
//             ))}
//           </div>
//         </div>

//         {/* DETAILS */}
//         <div style={styles.detailsColumn}>
//           <p style={styles.category}>SUN PROTECTION</p>

//           <h1 style={styles.productTitle}>
//             Haetsal Veil™ SPF 50+ PA++++
//           </h1>

//           <p style={styles.koreanName}>햇살베일™ 선크림</p>

//           <p style={styles.subtitle}>
//             A weightless, skin-perfecting sunscreen designed for daily wear
//             with invisible protection and lasting comfort.
//           </p>

//           <p style={styles.price}>₹2,499</p>

//           {/* CTA */}
//           <div style={styles.ctaRow}>
//             <button style={styles.buyButton} onClick={handleOrderNow}>
//               Order Now
//             </button>

//             <div style={{ position: "relative" }}>
//               <button
//                 style={{
//                   ...styles.addToCartBtn,
//                   ...(added ? styles.addedBtn : {}),
//                 }}
//                 onClick={handleAddToCartOnly}
//               >
//                 {added ? "Added ✓" : "Add to Cart"}
//               </button>

//               {added && (
//                 <div style={styles.toast}>
//                   Added to cart · Open <strong>Profile → Cart</strong>
//                 </div>
//               )}
//             </div>
//           </div>

//           {/* BADGES */}
//           <div style={styles.badges}>
//             <span>No White Cast</span>
//             <span>Daily Wear</span>
//             <span>Lightweight</span>
//           </div>

//           {/* HOW TO USE */}
//           <div style={styles.quickUse}>
//             <h4 style={styles.quickUseTitle}>How to Use</h4>
//             <p>
//               Apply evenly as the final step of your morning skincare routine.
//             </p>
//             <p>
//               Reapply every 2–3 hours when exposed to sunlight.
//             </p>
//           </div>

//           {/* BENEFITS */}
//           <div style={styles.benefits}>
//             <h4 style={styles.benefitsTitle}>Why You’ll Love It</h4>
//             <ul style={styles.benefitsList}>
//               <li>SPF 50+ PA++++ broad-spectrum protection</li>
//               <li>Invisible finish on all skin tones</li>
//               <li>Comfortable, non-greasy texture</li>
//               <li>Perfect under makeup</li>
//               <li>Ideal for Indian climate</li>
//             </ul>
//           </div>

//           {/* RECOMMENDED SPRAY */}
//           <div style={styles.recommendBox}>
//             <p style={styles.recommendText}>
//               Need effortless reapplication when you’re outdoors?
//               <br />
//               <strong>
//                 Haetsal Veil™ Spray is designed for quick, mess-free
//                 touch-ups — anytime, anywhere.
//               </strong>
//             </p>

//             <button
//               style={styles.recommendBtn}
//               onClick={() => navigate("/product/spray")}
//             >
//               View Reapplication Spray
//             </button>
//           </div>
//         </div>
//       </section>

//       <Footer />
//     </>
//   );
// }

// /* ---------------- STYLES ---------------- */

// const styles = {
//   productSection: {
//     display: "flex",
//     flexWrap: "wrap",
//     gap: 90,
//     maxWidth: 1200,
//     margin: "56px auto",
//     padding: "0 24px",
//   },

//   hide: { opacity: 0, transform: "translateY(40px)" },
//   show: { opacity: 1, transform: "translateY(0)", transition: "0.9s ease" },

//   imageColumn: { flex: 1, minWidth: 320 },
//   mainImage: { width: "100%", borderRadius: 24 },
//   thumbnailRow: { display: "flex", gap: 14, marginTop: 20 },

//   thumbnail: {
//     width: 74,
//     height: 74,
//     borderRadius: 14,
//     cursor: "pointer",
//     objectFit: "cover",
//   },

//   detailsColumn: { flex: 1, minWidth: 320 },
//   category: { fontSize: 12, letterSpacing: 2.5, color: "#888" },
//   productTitle: { fontSize: 40, fontWeight: 500, marginTop: 6 },
//   koreanName: { fontSize: 16, color: "#777", marginBottom: 18 },
//   subtitle: { fontSize: 16, color: "#555", lineHeight: 1.8 },
//   price: { fontSize: 24, margin: "26px 0" },

//   ctaRow: { display: "flex", gap: 16, flexWrap: "wrap" },

//   buyButton: {
//     padding: "16px 34px",
//     borderRadius: 50,
//     background: "#111",
//     color: "#fff",
//     border: "none",
//     fontSize: 15,
//     cursor: "pointer",
//   },

//   addToCartBtn: {
//     padding: "16px 34px",
//     borderRadius: 50,
//     background: "transparent",
//     color: "#111",
//     border: "1px solid #111",
//     fontSize: 15,
//     cursor: "pointer",
//     transition: "all 0.25s ease",
//   },

//   addedBtn: {
//     background: "#111",
//     color: "#fff",
//     transform: "scale(0.96)",
//   },

//   toast: {
//     position: "absolute",
//     top: "110%",
//     left: 0,
//     background: "#111",
//     color: "#fff",
//     padding: "10px 14px",
//     borderRadius: 14,
//     fontSize: 12.5,
//     marginTop: 8,
//     whiteSpace: "nowrap",
//   },

//   badges: {
//     display: "flex",
//     gap: 22,
//     fontSize: 13,
//     marginTop: 26,
//     color: "#555",
//     flexWrap: "wrap",
//   },

//   quickUse: {
//     marginTop: 34,
//     fontSize: 15.5,
//     lineHeight: 1.9,
//     color: "#333",
//     maxWidth: 460,
//   },

//   quickUseTitle: {
//     fontSize: 16.5,
//     fontWeight: 500,
//     marginBottom: 12,
//   },

//   benefits: {
//     marginTop: 34,
//     maxWidth: 460,
//   },

//   benefitsTitle: {
//     fontSize: 16.5,
//     fontWeight: 500,
//     marginBottom: 14,
//   },

//   benefitsList: {
//     fontSize: 14.5,
//     lineHeight: 1.9,
//     color: "#444",
//     paddingLeft: 18,
//   },

//   recommendBox: {
//     marginTop: 44,
//     padding: "26px 28px",
//     borderRadius: 22,
//     background: "rgba(0,0,0,0.03)",
//     maxWidth: 480,
//   },

//   recommendText: {
//     fontSize: 15,
//     lineHeight: 1.8,
//     color: "#333",
//     marginBottom: 18,
//   },

//   recommendBtn: {
//     padding: "14px 30px",
//     borderRadius: 40,
//     background: "#111",
//     color: "#fff",
//     border: "none",
//     fontSize: 14,
//     cursor: "pointer",
//   },
// };
