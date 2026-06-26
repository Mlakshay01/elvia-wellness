import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { HelmetProvider } from "react-helmet-async";

import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import ScrollToTop from "./components/ScrollToTop";
import Loader from "./components/Loader";

import Home from "./pages/Home";
import Cart from "./pages/Cart";
import Address from "./pages/Address";
import Payment from "./pages/Payment";
import OrderSuccess from "./pages/OrderSuccess";
import Success from "./pages/Success";
import MyOrders from "./pages/MyOrders";
import OrderDetail from "./pages/OrderDetail";
import Account from "./pages/Account";
import AddressBook from "./pages/AddressBook";
import Support from "./pages/Support";
import AdminAnalytics from "./pages/AdminAnalytics";
import Blogs from "./pages/Blogs";
import BlogPost from "./pages/BlogPost";
import AmbassadorProgram from "./pages/AmbassadorProgram";

import PerfumeSoftSkin from "./pages/PerfumeSoftSkin";
import PerfumeMorningVeil from "./pages/PerfumeMorningVeil";
import PerfumeQuietWoods from "./pages/PerfumeQuietWoods";
import PerfumeNox from "./pages/PerfumeNox";
import PerfumeVelion from "./pages/PerfumeVelion";

import About from "./components/legal/About";
import Contact from "./components/legal/Contact";
import Privacy from "./components/legal/Privacy";
import Terms from "./components/legal/Terms";
import Refund from "./components/legal/Refund";
import Shipping from "./components/legal/Shipping";

import AdminLogin from "./admin/AdminLogin";
import Orders from "./admin/Orders";
import OrderPage from "./admin/OrderPage";
import Dashboard from "./admin/Dashboard";
import EmailAnalytics from "./admin/EmailAnalytics";
import Chats from "./admin/Chats";
import ChatDetail from "./admin/ChatDetail";
import AdminBlogs from "./admin/AdminBlogs";

import { AuthProvider } from "./context/AuthContext";
import { CartProvider } from "./context/CartContext";
import ProtectedRoute from "./components/ProtectedRoute";
import AdminProtected from "./components/AdminProtected";



import "./index.css";

/* ── LAYOUT ── hides Navbar + Footer on all /admin routes */
function Layout({ children }) {
  const location = useLocation();
  const isAdmin = location.pathname.startsWith("/admin");

  return (
    <>
      {!isAdmin && <Navbar />}
      <ScrollToTop />
      <Loader />
      {children}
      {!isAdmin && <Footer />}
    </>
  );
}

/* ── CURSOR ── */
function useCursor() {
  useEffect(() => {
    const cr = document.getElementById("cr");
    const cdot = document.getElementById("cd");
    if (!cr || !cdot) return;

    let mx = 0, my = 0, cx = 0, cy = 0;

    cr.style.setProperty("border-color", "#0d0c0b");
    cdot.style.setProperty("background", "#0d0c0b");

    const checkDark = () => {
      let el = document.elementFromPoint(mx, my);
      while (el) {
        const bg = getComputedStyle(el).backgroundColor;
        if (bg && bg !== "rgba(0, 0, 0, 0)" && bg !== "transparent") {
          const match = bg.match(/\d+/g);
          if (match) {
            const [r, g, b] = match.map(Number);
            const brightness = (r * 299 + g * 587 + b * 114) / 1000;
            const isDark = brightness < 80;
            cr.style.setProperty("border-color", isDark ? "white" : "#0d0c0b");
            cdot.style.setProperty("background", isDark ? "white" : "#0d0c0b");
            return;
          }
        }
        el = el.parentElement;
      }
      cr.style.setProperty("border-color", "#0d0c0b");
      cdot.style.setProperty("background", "#0d0c0b");
    };

    const onMove = (e) => {
      mx = e.clientX;
      my = e.clientY;
      cdot.style.left = mx + "px";
      cdot.style.top = my + "px";
      cr.classList.add("visible");
      cdot.classList.add("visible");
      checkDark();
    };

    let raf;
    const animCursor = () => {
      cx += (mx - cx) * 0.12;
      cy += (my - cy) * 0.12;
      cr.style.left = cx + "px";
      cr.style.top = cy + "px";
      raf = requestAnimationFrame(animCursor);
    };
    raf = requestAnimationFrame(animCursor);

    const onEnter = (e) => {
      if (e.target.closest("a, button, .prod-card")) cr.classList.add("grow");
    };
    const onLeave = (e) => {
      if (e.target.closest("a, button, .prod-card")) cr.classList.remove("grow");
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseover", onEnter);
    document.addEventListener("mouseout", onLeave);

    return () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseover", onEnter);
      document.removeEventListener("mouseout", onLeave);
      cancelAnimationFrame(raf);
    };
  }, []);
}

/* ── APP ROOT ── */
function AppRoot() {
  useCursor();

  return (
    <>
      <div className="cursor" id="cursorRing">
        <div className="cursor-ring" id="cr" />
      </div>
      <div className="cursor-dot" id="cd" />

      <Layout>
        <Routes>
          {/* ── PUBLIC ── */}
          <Route path="/" element={<Home />} />

          {/* ── PERFUMES ── */}
          <Route path="/perfume/noir-party-perfume" element={<PerfumeSoftSkin />} />
          <Route path="/perfume/veil-fresh-perfume" element={<PerfumeMorningVeil />} />
          <Route path="/perfume/soie-femme-floral-perfume" element={<PerfumeQuietWoods />} />
          <Route path="/perfume/nox" element={<PerfumeNox />} />
          <Route path="/perfume/velion" element={<PerfumeVelion />} />

          {/* AMBASSADOR PROGRAM */}
          <Route path="/program/ambassador" element={<AmbassadorProgram />} />

          {/* ── BLOG ── */}
          <Route path="/blogs" element={<Blogs />} />
          <Route path="/blogs/:slug" element={<BlogPost />} />

          {/* ── LEGAL & INFO ── */}
          <Route path="/about" element={<About />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/privacy" element={<Privacy />} />
          <Route path="/terms" element={<Terms />} />
          <Route path="/refund" element={<Refund />} />
          <Route path="/shipping" element={<Shipping />} />

          {/* ── AUTH ── */}
          <Route path="/success" element={<Success />} />

          {/* ── USER (protected) ── */}
          <Route path="/account" element={<ProtectedRoute><Account /></ProtectedRoute>} />
          <Route path="/addresses" element={<ProtectedRoute><AddressBook /></ProtectedRoute>} />
          <Route path="/my-orders" element={<ProtectedRoute><MyOrders /></ProtectedRoute>} />
          <Route path="/previous-orders" element={<ProtectedRoute><MyOrders type="previous" /></ProtectedRoute>} />
          <Route path="/order/:id" element={<ProtectedRoute><OrderDetail /></ProtectedRoute>} />
          <Route path="/support" element={<ProtectedRoute><Support /></ProtectedRoute>} />

          {/* ── CART / CHECKOUT (protected) ── */}
          <Route path="/cart" element={<ProtectedRoute><Cart /></ProtectedRoute>} />
          <Route path="/checkout/address" element={<ProtectedRoute><Address /></ProtectedRoute>} />
          <Route path="/checkout/payment" element={<ProtectedRoute><Payment /></ProtectedRoute>} />
          <Route path="/order-success" element={<OrderSuccess />} />

          {/* ── ADMIN ── */}
          <Route path="/admin/login" element={<AdminLogin />} />
          <Route path="/admin/dashboard" element={<AdminProtected><Dashboard /></AdminProtected>} />
          <Route path="/admin/orders" element={<AdminProtected><Orders /></AdminProtected>} />
          <Route path="/admin/orders/:id" element={<AdminProtected><OrderPage /></AdminProtected>} />
          <Route path="/admin/chats" element={<AdminProtected><Chats /></AdminProtected>} />
          <Route path="/admin/chats/:id" element={<AdminProtected><ChatDetail /></AdminProtected>} />
          <Route path="/admin/emails" element={<AdminProtected><EmailAnalytics /></AdminProtected>} />
          <Route path="/admin/analytics" element={<AdminProtected><AdminAnalytics /></AdminProtected>} />
          <Route path="/admin/blogs" element={<AdminProtected><AdminBlogs /></AdminProtected>} />
        </Routes>
      </Layout>
    </>
  );
}

/* ── RENDER ── */
ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <HelmetProvider>
      <AuthProvider>
        <CartProvider>
          <BrowserRouter>
            <AppRoot />
          </BrowserRouter>
        </CartProvider>
      </AuthProvider>
    </HelmetProvider>
  </React.StrictMode>
);