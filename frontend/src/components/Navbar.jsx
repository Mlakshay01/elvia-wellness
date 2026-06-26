import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import AuthModal from "./AuthModal";
import ProfileMenu from "./ProfileMenu";
import "../styles/Home/Navbar.css";
import { useCart } from "../context/CartContext";

const NAV_LINKS = [
  { label: "Collection", id: "collection" },
  { label: "About", id: "about" },
  { label: "Ambassador", id: "ambassador" },
  { label: "Coming Soon", id: "coming" },
  
];

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();

  const [showAuth, setShowAuth] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  const { cartItems } = useCart();
  const cartCount = cartItems.reduce((sum, item) => sum + item.quantity, 0);

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

  function scrollToSection(id) {
    if (location.pathname === "/") {
      document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
    } else {
      navigate("/");
      setTimeout(() => {
        document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
      }, 350);
    }
  }

  return (
    <>
      {showAuth && <AuthModal onClose={() => setShowAuth(false)} />}

      <button
        className={`nav-ham ${menuOpen ? "open" : ""}`}
        onClick={() => setMenuOpen(!menuOpen)}
      >
        <span />
        <span style={{ opacity: menuOpen ? 0 : 1 }} />
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
          {NAV_LINKS.map(({ label, id }) => (
            <a
              key={id}
              href={`/#${id}`}
              onClick={(e) => {
                e.preventDefault();
                scrollToSection(id);
              }}
            >
              {label}
            </a>
          ))}
        </div>

        {/* ── RIGHT ── */}
        <div className="nav-right">
          {!isMobile && (
            <>
              <a href="https://www.instagram.com/kaeorn.co/" target="_blank" rel="noreferrer" className="nav-link">
                Instagram
              </a>
              <a href="https://www.youtube.com/@KAEORNWELLNESS" target="_blank" rel="noreferrer" className="nav-link">
                YouTube
              </a>
              <a href="https://www.facebook.com/people/Kaeorn/61590374977606" target="_blank" rel="noreferrer" className="nav-link">
                Facebook
              </a>
            </>
          )}

          {!user ? (
            <button name="signIn" className="nav-signin" onClick={() => setShowAuth(true)}>
              Sign in
            </button>
          ) : (
            <>
              <button
                className="nav-cart"
                id="cartBtn"
                onClick={() => navigate("/cart")}
              >
                <span>Cart</span>
                <span className="cart-badge" id="cartBadge">{cartCount}</span>
              </button>
              <ProfileMenu />
            </>
          )}
        </div>
      </nav>

      {/* ── FULLSCREEN MOBILE MENU ── */}
      <div className={`mob-menu ${menuOpen ? "open" : ""}`}>
        {NAV_LINKS.map(({ label, id }) => (
          <a
            key={id}
            href={`/#${id}`}
            onClick={(e) => {
              e.preventDefault();
              closeMenu();
              scrollToSection(id);
            }}
          >
            {label}
          </a>
        ))}
        <a href="https://www.instagram.com/kaeorn.co/" target="_blank" rel="noreferrer" onClick={closeMenu}>
          Instagram
        </a>
        <a href="https://www.youtube.com/@KAEORNWELLNESS" target="_blank" rel="noreferrer" onClick={closeMenu}>
          YouTube
        </a>
        <a href="https://www.facebook.com/people/Kaeorn/61590374977606" target="_blank" rel="noreferrer" onClick={closeMenu}>
          Facebook
        </a>
      </div>
    </>
  );
}