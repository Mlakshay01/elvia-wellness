import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Instagram, Youtube, ArrowLeft } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import AuthModal from "./AuthModal";
import ProfileMenu from "./ProfileMenu";
import "../styles/Home/Navbar.css";

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();

  const [showAuth, setShowAuth] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  /* ── SCROLL ── */
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  /* ── RESIZE ── */
  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < 768);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  /* ── LOCK BODY WHEN MENU OPEN ── */
  useEffect(() => {
    document.body.style.overflow = menuOpen ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [menuOpen]);

  const showBack =
    location.pathname !== "/" &&
    !location.pathname.startsWith("/admin");

  const closeMenu = () => setMenuOpen(false);

  return (
    <>
      {showAuth && <AuthModal onClose={() => setShowAuth(false)} />}

      <button className={`nav-ham ${menuOpen ? "open" : ""}`} onClick={() => setMenuOpen(!menuOpen)}>
            <span />
            <span style={{ opacity: menuOpen ? 0 : 1 }} />  {/* middle bar fades out */}
            <span />
          </button>

      <nav className={scrolled ? "scrolled" : ""}>

        {/* ── LEFT ── */}
        <div className="nav-left">
          {showBack && (
            <button className="nav-back" onClick={() => navigate(-1)} aria-label="Go back">
              <ArrowLeft size={16} />
            </button>
          )}
          <a className="nav-logo" onClick={() => navigate("/")}>KAEORN</a>
        </div>

        {/* ── CENTER ── */}
        <div className="nav-center">
          <a href="#collection">Collection</a>
          <a href="#about">About</a>
          <a href="#coming">Coming Soon</a>
        </div>

        {/* ── RIGHT ── */}
        <div className="nav-right">

          {!isMobile && (
            <>
              <a href="https://www.instagram.com/kaeornwellness/" target="_blank" rel="noreferrer" className="nav-link">
                Instagram
              </a>
              <a href="https://www.youtube.com/@KAEORNWELLNESS" target="_blank" rel="noreferrer" className="nav-link">
                YouTube
              </a>
            </>
          )}

          {/* <button className="nav-cart" id="cartBtn">
            <span>Cart</span>
            <span className="cart-badge" id="cartBadge">0</span>
          </button> */}

          {!user ? (
            <button className="nav-signin" onClick={() => setShowAuth(true)}>
              Sign in
            </button>
          ) : (
            <ProfileMenu />
          )}

        </div>
      </nav>

      {/* ── FULLSCREEN MOBILE MENU ── */}
      <div className={`mob-menu ${menuOpen ? "open" : ""}`}>
        <a href="#collection" onClick={closeMenu}>Collection</a>
        <a href="#about" onClick={closeMenu}>About</a>
        <a href="#coming" onClick={closeMenu}>Coming Soon</a>
        <a href="https://www.instagram.com/kaeornwellness/" target="_blank" rel="noreferrer" onClick={closeMenu}>
          Instagram
        </a>
        <a href="https://www.youtube.com/@KAEORNWELLNESS" target="_blank" rel="noreferrer" onClick={closeMenu}>
          YouTube
        </a>
      </div>
    </>
  );
}