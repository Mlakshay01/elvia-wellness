import { useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import "../styles/Footer/Footer.css";

export default function Footer() {
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
      },
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
      {/* FOOTER */}
      <footer>
        <div className="footer-inner">
          <div className="footer-top">
            <div className="footer-logo-block reveal">
              <div className="footer-logo">KAEORN</div>
              <p className="footer-tagline">Because care deserves luxury.</p>
            </div>
            <div className="footer-col reveal">
              <h4>Collection</h4>
              <Link className="link" to="/perfume/noir-party-perfume">Thé Noir Men</Link>
              <Link className="link" to="/perfume/soie-femme-floral-perfume">Soié Femme</Link>
              <Link className="link" to="/perfume/veil-fresh-perfume">Veil</Link>
              <Link className="link" to="/perfume/nox">Nox</Link>
              <Link className="link" to="/perfume/velion">Velion</Link>
              {/* <Link className="link" to="/perfume/discovery-set">Discovery Set</Link> */}
            </div>
            <div className="footer-col reveal">
              <h4>Brand</h4>
              <Link to="/about">About</Link>
              <a href="/#about">Our Story</a>
              <a href="/#coming">Coming Soon</a>
              <Link to="/blogs">Journal</Link>
              <Link to="/program/ambassador">Ambassador Program</Link>
            </div>
            <div className="footer-col reveal">
              <h4>Connect</h4>
              <a href="https://www.instagram.com/kaeorn.co" target="_blank" rel="noopener noreferrer">
                Instagram
              </a>
              <a href="https://www.youtube.com/@KAEORNWELLNESS" target="_blank" rel="noopener noreferrer">
                YouTube
              </a>
            </div>
          </div>
          <div className="footer-bottom reveal">
            <span className="footer-copy">
              © 2026 KAEORN. All rights reserved.
            </span>
            <div className="footer-social">
              <Link className="link" to="/privacy">Privacy</Link>
              <Link className="link" to="/terms">Terms</Link>
              <Link className="link" to="/contact">Contact</Link>
              <Link className="link" to="/refund">Refund</Link>
              <Link className="link" to="/shipping">Shipping</Link>

              <Link className="link" to="/">kaeorn.com</Link>
            </div>
          </div>
        </div>
      </footer>
    </>
  );
}
