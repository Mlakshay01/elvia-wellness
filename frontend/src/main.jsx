import React from "react";
import ReactDOM from "react-dom/client";
import {
  BrowserRouter,
  Routes,
  Route,
  useLocation,
} from "react-router-dom";

import Navbar from "./components/Navbar";

import App from "./App";
import Home from "./pages/Home";
import ProductSpray from "./pages/ProductSpray";
import Chats from "./admin/Chats";

import Cart from "./pages/Cart";
import Address from "./pages/Address";
import Payment from "./pages/Payment";
import OrderSuccess from "./pages/OrderSuccess";
import Success from "./pages/Success";

import About from "./pages/legal/About";
import Contact from "./pages/legal/Contact";
import Privacy from "./pages/legal/Privacy";
import Terms from "./pages/legal/Terms";
import Refund from "./pages/legal/Refund";
import Shipping from "./pages/legal/Shipping";

import MyOrders from "./pages/MyOrders";
import OrderDetail from "./pages/OrderDetail";
import Account from "./pages/Account";
import AddressBook from "./pages/AddressBook";

import Perfume from "./pages/Perfume";
import PerfumeSoftSkin from "./pages/PerfumeSoftSkin";
import PerfumeMorningVeil from "./pages/PerfumeMorningVeil";
import PerfumeQuietWoods from "./pages/PerfumeQuietWoods";

import AdminLogin from "./admin/AdminLogin";
import Orders from "./admin/Orders";
import OrderPage from "./admin/OrderPage";
import Dashboard from "./admin/Dashboard";
import EmailAnalytics from "./admin/EmailAnalytics"; // ✅ FIXED IMPORT

import Support from "./pages/Support";

import { AuthProvider } from "./context/AuthContext";
import { CartProvider } from "./context/CartContext";

import ProtectedRoute from "./components/ProtectedRoute";
import AdminProtected from "./components/AdminProtected";
import ChatDetail from "./admin/ChatDetail";
import ResetPassword from "./pages/ResetPassword";
import ScrollToTop from "./components/ScrollToTop";
import Footer from "./components/Footer";
import AdminAnalytics from "./pages/AdminAnalytics";
import './index.css'


/* ---------------- NAVBAR CONTROLLER ---------------- */

function Layout({ children }) {
  const location = useLocation();
  const isAdminRoute = location.pathname.startsWith("/admin");

  return (
    <>
      {!isAdminRoute && <Navbar />}
      {children}
    </>
  );
}

/* ---------------- APP ROOT ---------------- */

function AppRoot() {
  return (
    <Layout>
      <ScrollToTop />
      <Routes>
        {/* ---------- PUBLIC ---------- */}
        <Route path="/" element={<Home />} />
        <Route path="/product" element={<App />} />
        <Route path="/product/spray" element={<ProductSpray />} />

        {/* ---------- PERFUME ---------- */}
        <Route path="/perfume" element={<Perfume />} />
        <Route path="/perfume/soft-skin" element={<PerfumeSoftSkin />} />
        <Route path="/perfume/morning-veil" element={<PerfumeMorningVeil />} />
        <Route path="/perfume/quiet-woods" element={<PerfumeQuietWoods />} />

        {/* ---------- USER ---------- */}
        <Route path="/account" element={<Account />} />
        <Route path="/addresses" element={<AddressBook />} />
        <Route path="/my-orders" element={<MyOrders />} />
        <Route path="/previous-orders" element={<MyOrders type="previous" />} />
        <Route path="/order/:id" element={<OrderDetail />} />

        {/* 🖤 EMAIL ANALYTICS */}
        <Route
          path="/admin/emails"
          element={
            <AdminProtected>
              <EmailAnalytics />
            </AdminProtected>
          }
        />

        {/* ---------- LEGAL ---------- */}
        <Route path="/about" element={<About />} />
        <Route path="/contact" element={<Contact />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/terms" element={<Terms />} />
        <Route path="/refund" element={<Refund />} />
        <Route path="/shipping" element={<Shipping />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/success" element={<Success />} />


        {/* ---------- CART ---------- */}
        <Route
          path="/cart"
          element={
            <ProtectedRoute>
              <Cart />
            </ProtectedRoute>
          }
        />
        <Route
          path="/checkout/address"
          element={
            <ProtectedRoute>
              <Address />
            </ProtectedRoute>
          }
        />
        <Route
          path="/checkout/payment"
          element={
            <ProtectedRoute>
              <Payment />
            </ProtectedRoute>
          }
        />
        <Route path="/order-success" element={<OrderSuccess />} />

        {/* ---------- SUPPORT ---------- */}
        <Route
          path="/support"
          element={
            <ProtectedRoute>
              <Support />
            </ProtectedRoute>
          }
        />

        {/* ---------- ADMIN ---------- */}
        <Route path="/admin/login" element={<AdminLogin />} />
<Route path="/admin/analytics" element={<AdminAnalytics />} />

        <Route
          path="/admin/dashboard"
          element={
            <AdminProtected>
              <Dashboard />
            </AdminProtected>
          }
        />
        <Route
          path="/admin/orders"
          element={
            <AdminProtected>
              <Orders />
            </AdminProtected>
          }
        />
        <Route
          path="/admin/orders/:id"
          element={
            <AdminProtected>
              <OrderPage />
            </AdminProtected>
          }
        />
        <Route
          path="/admin/chats"
          element={
            <AdminProtected>
              <Chats />
            </AdminProtected>
          }
        />
        <Route
          path="/admin/chats/:id"
          element={
            <AdminProtected>
              <ChatDetail />
            </AdminProtected>
          }
        />
      </Routes>
      <Footer />
    </Layout>
  );
}

/* ---------------- RENDER ---------------- */

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AuthProvider>
      <CartProvider>
        <BrowserRouter>
          <AppRoot />
        </BrowserRouter>
      </CartProvider>
    </AuthProvider>
  </React.StrictMode>
);
