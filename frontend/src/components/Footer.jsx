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
  observerRef.current = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add("visible");
        observerRef.current.unobserve(e.target);
      }
    });
  });

  return () => {
    if (observerRef.current) observerRef.current.disconnect();
  };
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

  return (
    <>
      {/*!-- FOOTER --*/}
      <footer>
        <div className="footer-inner">
          <div  className="footer-top">
            <div ref={addReveal} className="footer-logo-block reveal">
              <div className="footer-logo">KAEORN</div>
              <p className="footer-tagline">Because care deserves luxury.</p>
            </div>
            <div ref={addReveal} className="footer-col reveal">
              <h4>Collection</h4>
              <span className="link" onClick={() => navigate("/perfume/soft-skin")}>Thé Noir Men</span>
              <span className="link" onClick={() => navigate("/perfume/quiet-woods")}>Soié Femme</span>
              <span className="link" onClick={() => navigate("/perfume/morning-veil")}>Veil</span>
            </div>
            <div ref={addReveal} className="footer-col reveal">
              <h4>Brand</h4>
              <a href="#about">Our Story</a>
              <a href="#coming">Coming Soon</a>
            </div>
            <div ref={addReveal} className="footer-col reveal">
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
          <div ref={addReveal} className="footer-bottom reveal">
            <span className="footer-copy">© 2024 KAEORN. All rights reserved.</span>
            <div className="footer-social">
              <span className="link" onClick={() => navigate("/privacy")}>Privacy</span>
              <span className="link" onClick={() => navigate("/terms")}>Terms</span>
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
