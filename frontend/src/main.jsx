import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { HelmetProvider } from "react-helmet-async";

import { AuthProvider } from "./context/AuthContext";
import { CartProvider } from "./context/CartContext";
import AppRoot from "./App";

import "./index.css";

/* ── RENDER ──
   The build step (scripts/prerender.mjs) writes fully rendered HTML for every public
   page into the root element so crawlers get real content without running JS.
   createRoot() replaces that markup as soon as the bundle boots. */
// Head tags written by the prerender step are removed here; react-helmet-async re-creates the
// same tags for the current page, and keeps them correct on client-side navigation.
document.head.querySelectorAll("[data-prerender]").forEach((el) => el.remove());

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
