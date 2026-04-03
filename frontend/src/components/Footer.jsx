import { useEffect, useRef, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import "../styles/Footer/Footer.css";

export default function Footer() {
  const navigate = useNavigate();
  const [visible, setVisible] = useState(false);
  const [hovered, setHovered] = useState(null);
  

  /* ── SCROLL REVEAL ── */
 const observerRef = useRef(null);

 useEffect(() => {
  observerRef.current = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
          observerRef.current.unobserve(entry.target);
        }
      });
    },
    {
      threshold: 0.1,
    }
  );

  // 🔥 FIX: check all reveal elements after mount
  const elements = document.querySelectorAll(".reveal");

  elements.forEach((el) => {
    observerRef.current.observe(el);

    // fallback check AFTER paint
    requestAnimationFrame(() => {
      const rect = el.getBoundingClientRect();
      if (rect.top < window.innerHeight) {
        el.classList.add("visible");
      }
    });
  });

  return () => {
    if (observerRef.current) observerRef.current.disconnect();
  };
}, []);

  return (
    <>
      {/*!-- FOOTER --*/}
      <footer>
        <div className="footer-inner">
          <div  className="footer-top">
            <div  className="footer-logo-block reveal">
              <div className="footer-logo">KAEORN</div>
              <p className="footer-tagline">Because care deserves luxury.</p>
            </div>
            <div  className="footer-col reveal">
              <h4>Collection</h4>
              <span className="link" onClick={() => navigate("/perfume/soft-skin")}>Thé Noir Men</span>
              <span className="link" onClick={() => navigate("/perfume/quiet-woods")}>Soié Femme</span>
              <span className="link" onClick={() => navigate("/perfume/morning-veil")}>Veil</span>
            </div>
            <div className="footer-col reveal">
              <h4>Brand</h4>
              <a href="#about">Our Story</a>
              <a href="#coming">Coming Soon</a>
            </div>
            <div className="footer-col reveal">
              <h4>Connect</h4>
              <a
                href="https://www.instagram.com/kaeornwellness"
                target="_blank"
              >
                Instagram
              </a>
              <a href="https://www.youtube.com/@KAEORNWELLNESS" target="_blank">
                YouTube
              </a>
              <a href="#">Newsletter</a>
            </div>
          </div>
          <div  className="footer-bottom reveal">
            <span className="footer-copy">© 2024 KAEORN. All rights reserved.</span>
            <div className="footer-social">
              <span className="link" onClick={() => navigate("/privacy")}>Privacy</span>
              <span className="link" onClick={() => navigate("/terms")}>Terms</span>
              <span className="link" onClick={() => navigate("/contact")}>Contact</span>
              <span className="link" onClick={() => navigate("/refund")}>Refund</span>
              <span className="link" onClick={() => navigate("/shipping")}>Shipping</span>
            
              <a href="https://kaeorn.com" target="_blank">
                kaeorn.com
              </a>
            </div>
          </div>
        </div>
      </footer>
    </>
  );
}
