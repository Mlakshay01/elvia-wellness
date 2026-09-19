/* =========================================================
   30 ML PRICE

   Single place to change the 30 ml price on the storefront.
   The payment price actually charged comes from MongoDB, so
   after changing this, update the same number in
   backend/seed30mlProducts.js and re-run that script.
========================================================= */
export const PRICE_30ML = 599;

export const PRODUCTS = {
  "/perfume/noir-party-perfume": {
    id: "the-noir-men",
    name: "THÉ NOIR",
    price: 1399,
    image:
      "https://res.cloudinary.com/dhh2i1soo/image/upload/v1789834176/Untitled_2_tv5rbj.png",
    category: "MEN · EAU DE PARFUM",
    size: "100 ml",
  },

  "/perfume/noir-party-perfume?size=30ml": {
    id: "the-noir-men-30ml",
    name: "THÉ NOIR (30 ml)",
    price: PRICE_30ML,
    image:
      "https://res.cloudinary.com/dhh2i1soo/image/upload/v1789834176/Untitled_2_tv5rbj.png",
    category: "MEN · EAU DE PARFUM",
    size: "30 ml",
  },

  "/perfume/veil-fresh-perfume": {
    id: "perfume-veil-unisex",
    name: "VEIL",
    price: 1399,
    image:
      "https://res.cloudinary.com/dhh2i1soo/image/upload/v1789834174/IMG_20260919_210916_xy3hjl.png",
    category: "UNISEX · EAU DE PARFUM",
    size: "100 ml",
  },

  "/perfume/veil-fresh-perfume?size=30ml": {
    id: "perfume-veil-unisex-30ml",
    name: "VEIL (30 ml)",
    price: PRICE_30ML,
    image:
      "https://res.cloudinary.com/dhh2i1soo/image/upload/v1789834174/IMG_20260919_210916_xy3hjl.png",
    category: "UNISEX · EAU DE PARFUM",
    size: "30 ml",
  },

  "/perfume/soie-femme-floral-perfume": {
    id: "perfume-soie-femme",
    name: "SOIE FEMME",
    price: 1399,
    image:
      "https://res.cloudinary.com/dhh2i1soo/image/upload/v1789834140/IMG_20260919_210944_cynhod.png",
    category: "WOMEN · EAU DE PARFUM",
    size: "100 ml",
  },

  "/perfume/soie-femme-floral-perfume?size=30ml": {
    id: "perfume-soie-femme-30ml",
    name: "SOIE FEMME (30 ml)",
    price: PRICE_30ML,
    image:
      "https://res.cloudinary.com/dhh2i1soo/image/upload/v1789834140/IMG_20260919_210944_cynhod.png",
    category: "WOMEN · EAU DE PARFUM",
    size: "30 ml",
  },

  "/perfume/nox": {
    id: "nox",
    name: "NOX",
    price: 499,
    image:
      "https://res.cloudinary.com/dvmntn6vf/image/upload/v1777184309/ChatGPT_Image_Apr_26_2026_11_47_58_AM_dycgoa.png",
    category: "UNISEX · PERFUME BALM",
  },

  "/perfume/velion": {
    id: "velion",
    name: "VELION",
    price: 499,
    image:
      "https://res.cloudinary.com/dvmntn6vf/image/upload/v1777636662/velion_home_xpbqlc.png",
    category: "UNISEX · PERFUME BALM",
  },

  /* DISCOVERY SET — 3 × 30 ml (THÉ NOIR, VEIL, SOIE FEMME).
     The route key must match the route in main.jsx and NewArrivals.jsx. */
  "/perfume/discovery-set": {
    id: "discovery-set",
    name: "DISCOVERY SET",
    price: 1500,
    // Cart thumbnail — swap for a real set photo when you have one.
    image:
      "https://res.cloudinary.com/dvmntn6vf/image/upload/v1775280305/ChatGPT_Image_Apr_4_2026_10_54_03_AM_fjvuq2.png",
    category: "COLLECTION · EAU DE PARFUM",
    size: "3 × 30 ml",
  },
};

/* =========================================================
   SIZE OPTIONS

   Given a perfume's base (100 ml) route, returns the size
   options that exist for it, smallest first:

   [
     { id: "30ml",  label: "30 ml",  route: "<route>?size=30ml", price },
     { id: "100ml", label: "100 ml", route: "<route>",           price },
   ]

   `route` can be passed straight to addToCart().
========================================================= */
export function getSizeOptions(baseRoute) {
  return [
    // { id: "30ml", label: "30 ml", route: `${baseRoute}?size=30ml` },
    { id: "100ml", label: "100 ml", route: baseRoute },
  ]
    .filter((option) => PRODUCTS[option.route])
    .map((option) => ({ ...option, price: PRODUCTS[option.route].price }));
}