import React from "react";
import { renderToString } from "react-dom/server";
import { StaticRouter } from "react-router";
import { HelmetProvider } from "react-helmet-async";

import { AuthProvider } from "./context/AuthContext";
import { CartProvider } from "./context/CartContext";
import AppRoot from "./App";

/**
 * Used ONLY at build time by scripts/prerender.mjs.
 * Returns the HTML for one URL plus the <head> tags collected by react-helmet-async.
 */
export function render(url) {
  const helmetContext = {};

  const html = renderToString(
    <HelmetProvider context={helmetContext}>
      <AuthProvider>
        <CartProvider>
          <StaticRouter location={url}>
            <AppRoot />
          </StaticRouter>
        </CartProvider>
      </AuthProvider>
    </HelmetProvider>
  );

  const h = helmetContext.helmet;
  const head = h
    ? [h.title, h.priority, h.meta, h.link, h.script, h.style]
        .filter(Boolean)
        .map((x) => x.toString())
        .join("\n    ")
    : "";

  return { html, head };
}
