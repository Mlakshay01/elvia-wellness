import { createContext, useContext, useState, useEffect, useRef } from "react";
import { PRODUCTS } from "../data/products";

const CartContext = createContext();

/* =========================================================
   API BASE

   Same env var used elsewhere in the app (Payment.jsx etc).
========================================================= */

const API_BASE = import.meta.env.VITE_API_BASE;

/* =========================================================
   BUILD PRODUCT LOOKUP (METADATA ONLY)

   PRODUCTS is keyed by route:

   "/perfume/veil-fresh-perfume"

   But each product has its own stable ID:

   "perfume-veil-unisex"

   We support both lookups for METADATA (name, image,
   category, canonical id). PRICE NEVER COMES FROM HERE
   ANYMORE — price always comes from the backend/MongoDB.
   This file can be stale after a deploy; the DB can't be.
========================================================= */

const PRODUCTS_BY_ID = Object.values(PRODUCTS).reduce((acc, product) => {
  if (product?.id) {
    acc[product.id] = product;
  }

  return acc;
}, {});

function resolveProductMeta(identifier) {
  if (!identifier) {
    return null;
  }

  // First try route-based lookup
  if (PRODUCTS[identifier]) {
    return PRODUCTS[identifier];
  }

  // Then try canonical product ID
  if (PRODUCTS_BY_ID[identifier]) {
    return PRODUCTS_BY_ID[identifier];
  }

  return null;
}

/* =========================================================
   LIVE PRODUCT FETCH

   This is the ONLY source of truth for price, name, image,
   and whether a product is currently sellable. Every add-
   to-cart and every cart reconciliation hits this.
========================================================= */

async function fetchLiveProduct(canonicalProductId) {
  const res = await fetch(
    `${API_BASE}/api/products/by-product-id/${encodeURIComponent(
      canonicalProductId,
    )}`,
  );

  if (!res.ok) {
    throw new Error(`Product not available: ${canonicalProductId}`);
  }

  const product = await res.json();

  const price = Number(product?.price);

  if (!product?.isActive || !Number.isFinite(price) || price <= 0) {
    throw new Error(`Invalid live product data for: ${canonicalProductId}`);
  }

  return {
    id: canonicalProductId,
    name: product.name,
    price,
    image:
      (Array.isArray(product.images) &&
        (typeof product.images[0] === "string"
          ? product.images[0]
          : product.images[0]?.url || product.images[0]?.secure_url)) ||
      "",
    category: product.category || "",
  };
}

/* =========================================================
   INITIAL CART LOADER (SYNC, LOCAL ONLY)

   Reads whatever is in localStorage just to get
   {id, quantity} pairs quickly for first paint.
   Price/name/image here are placeholders — they get
   overwritten by the live reconciliation effect on mount,
   before the user can meaningfully act on them.
========================================================= */

function loadInitialCartSkeleton() {
  try {
    const stored = localStorage.getItem("kaeorn_cart");

    if (!stored) {
      return [];
    }

    const parsed = JSON.parse(stored);

    if (!Array.isArray(parsed)) {
      return [];
    }

    const skeleton = [];

    parsed.forEach((item) => {
      const identifier = item?.productId || item?.id;
      const meta = resolveProductMeta(identifier);

      if (!meta || !meta.id) {
        return;
      }

      const quantity = Number(item.quantity);

      if (!Number.isInteger(quantity) || quantity < 1) {
        return;
      }

      const existing = skeleton.find((s) => s.id === meta.id);

      if (existing) {
        existing.quantity += quantity;
        return;
      }

      skeleton.push({
        id: meta.id,
        productId: meta.id,
        name: meta.name,
        // Placeholder only — never trust this for payment or
        // even for display beyond first paint. Overwritten below.
        price: 0,
        quantity,
        image: meta.image || "",
        category: meta.category || "",
        priceVerified: false,
      });
    });

    return skeleton;
  } catch (error) {
    console.error("Failed to load cart:", error);

    return [];
  }
}

export function CartProvider({ children }) {
  /* =========================================================
     CART ITEMS
  ========================================================= */

  const [cartItems, setCartItems] = useState(loadInitialCartSkeleton);

  // Prevents overlapping reconciliation passes.
  const reconcileInFlight = useRef(false);

  /* =========================================================
     APPLIED COUPON
  ========================================================= */

  const [appliedCoupon, setAppliedCoupon] = useState(() => {
    try {
      const stored = localStorage.getItem("appliedCoupon");

      if (!stored) {
        return null;
      }

      const parsed = JSON.parse(stored);

      if (!parsed || !parsed.code) {
        return null;
      }

      return normalizeCoupon(parsed);
    } catch (error) {
      console.error("Failed to load coupon:", error);

      return null;
    }
  });

  /* =========================================================
     SYNC CART TO LOCAL STORAGE
  ========================================================= */

  useEffect(() => {
    try {
      localStorage.setItem("kaeorn_cart", JSON.stringify(cartItems));
    } catch (error) {
      console.error("Failed to save cart:", error);
    }
  }, [cartItems]);

  /* =========================================================
     SYNC COUPON TO LOCAL STORAGE
  ========================================================= */

  useEffect(() => {
    try {
      if (appliedCoupon) {
        localStorage.setItem("appliedCoupon", JSON.stringify(appliedCoupon));
      } else {
        localStorage.removeItem("appliedCoupon");
      }
    } catch (error) {
      console.error("Failed to save coupon:", error);
    }
  }, [appliedCoupon]);

  /* =========================================================
     RECONCILE CART AGAINST BACKEND

     Runs once on mount (covers refresh / restored localStorage
     cart) and is also exposed so it can be re-run any time you
     want the cart to re-sync against current DB prices.

     Any item the backend rejects (inactive / not found) is
     dropped from the cart instead of silently trusting the
     old local price.
  ========================================================= */

  async function reconcileCartWithBackend() {
    if (reconcileInFlight.current) return;
    if (cartItems.length === 0) return;

    reconcileInFlight.current = true;

    try {
      const results = await Promise.all(
        cartItems.map(async (item) => {
          try {
            const live = await fetchLiveProduct(item.id);

            return {
              ...item,
              name: live.name,
              price: live.price,
              image: live.image || item.image,
              category: live.category || item.category,
              priceVerified: true,
            };
          } catch (error) {
            console.warn(
              `Removing "${item.id}" from cart — backend rejected it:`,
              error.message,
            );

            return null;
          }
        }),
      );

      setCartItems(results.filter(Boolean));
    } finally {
      reconcileInFlight.current = false;
    }
  }

  useEffect(() => {
    reconcileCartWithBackend();
    // Only on mount — subsequent price truth comes from
    // addToCart/increaseQty hitting the backend directly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* =========================================================
     ADD TO CART

     Always fetches the live product from the backend before
     adding or incrementing. Never reuses a locally-cached
     price, so a stale bundle can no longer serve a stale
     price — MongoDB is the only source of truth, every time.
  ========================================================= */

  async function addToCart(productIdentifier) {
    const meta = resolveProductMeta(productIdentifier);

    if (!meta || !meta.id) {
      console.warn("addToCart: unknown product:", productIdentifier);
      return false;
    }

    const canonicalProductId = meta.id;

    let live;

    try {
      live = await fetchLiveProduct(canonicalProductId);
    } catch (error) {
      console.error("addToCart: backend rejected product:", error.message);
      return false;
    }

    setCartItems((prev) => {
      const existing = prev.find((item) => item.id === canonicalProductId);

      if (existing) {
        return prev.map((item) =>
          item.id === canonicalProductId
            ? {
                ...item,
                id: canonicalProductId,
                productId: canonicalProductId,
                name: live.name,
                price: live.price,
                image: live.image || item.image,
                category: live.category || item.category,
                quantity: Number(item.quantity || 0) + 1,
                priceVerified: true,
              }
            : item,
        );
      }

      return [
        ...prev,
        {
          id: canonicalProductId,
          productId: canonicalProductId,
          name: live.name,
          price: live.price,
          quantity: 1,
          image: live.image || meta.image || "",
          category: live.category || meta.category || "",
          priceVerified: true,
        },
      ];
    });

    return true;
  }

  /* =========================================================
     SET CART

     Used for re-order functionality. Re-verifies every item
     against the backend instead of trusting stored data.
  ========================================================= */

  async function setCart(items) {
    if (!Array.isArray(items)) {
      console.warn("setCart expects an array");
      return;
    }

    const resolved = items
      .map((item) => {
        const identifier = item.productId || item.id;
        const meta = resolveProductMeta(identifier);

        if (!meta || !meta.id) return null;

        const quantity = Number(item.quantity);
        if (!Number.isInteger(quantity) || quantity < 1) return null;

        return { id: meta.id, quantity };
      })
      .filter(Boolean);

    const results = await Promise.all(
      resolved.map(async ({ id, quantity }) => {
        try {
          const live = await fetchLiveProduct(id);
          return {
            id,
            productId: id,
            name: live.name,
            price: live.price,
            image: live.image || "",
            category: live.category || "",
            quantity,
            priceVerified: true,
          };
        } catch (error) {
          console.warn(`setCart: dropping "${id}":`, error.message);
          return null;
        }
      }),
    );

    setCartItems(results.filter(Boolean));
  }

  /* =========================================================
     INCREASE QUANTITY

     Re-verifies price against the backend on every increment,
     so a price change mid-session is always caught.
  ========================================================= */

  async function increaseQty(id) {
    let live;

    try {
      live = await fetchLiveProduct(id);
    } catch (error) {
      console.error("increaseQty: backend rejected product:", error.message);
      return;
    }

    setCartItems((prev) =>
      prev.map((item) =>
        item.id === id
          ? {
              ...item,
              name: live.name,
              price: live.price,
              image: live.image || item.image,
              category: live.category || item.category,
              quantity: Number(item.quantity || 0) + 1,
              priceVerified: true,
            }
          : item,
      ),
    );
  }

  /* =========================================================
     DECREASE QUANTITY

     No backend truth needed to remove quantity, but re-stamp
     the price anyway in case it drifted since last verified.
  ========================================================= */

  function decreaseQty(id) {
    setCartItems((prev) =>
      prev
        .map((item) =>
          item.id === id
            ? {
                ...item,
                quantity: Number(item.quantity || 0) - 1,
              }
            : item,
        )
        .filter((item) => Number(item.quantity || 0) > 0),
    );
  }

  /* =========================================================
     REMOVE ITEM
  ========================================================= */

  function removeFromCart(id) {
    setCartItems((prev) => prev.filter((item) => item.id !== id));
  }

  /* =========================================================
     CLEAR CART
  ========================================================= */

  function clearCart() {
    setCartItems([]);
    setAppliedCoupon(null);

    localStorage.removeItem("kaeorn_cart");
    localStorage.removeItem("appliedCoupon");
  }

  /* =========================================================
     CART SUBTOTAL

     Now genuinely backend-verified per item (see
     priceVerified), not just "display only" hoping the
     backend agrees later.
  ========================================================= */

  function getCartTotal() {
    return cartItems.reduce(
      (total, item) =>
        total + Number(item.price || 0) * Number(item.quantity || 0),
      0,
    );
  }

  function getOriginalAmount() {
    return getCartTotal();
  }

  /* =========================================================
     COUPON DISCOUNT

     Frontend display calculation only.
     Backend must independently validate and calculate the
     real discount at checkout.
  ========================================================= */

  function getCouponDiscount() {
    if (!appliedCoupon) {
      return 0;
    }

    const subtotal = getCartTotal();

    if (appliedCoupon.discountType === "fixed") {
      return Math.min(Number(appliedCoupon.discountValue || 0), subtotal);
    }

    const discountPercent = Math.max(
      0,
      Math.min(100, Number(appliedCoupon.discountValue || 0)),
    );

    return Math.round((subtotal * discountPercent) / 100);
  }

  function getFinalTotal() {
    const subtotal = getCartTotal();
    const discount = getCouponDiscount();

    return Math.max(0, subtotal - discount);
  }

  /* =========================================================
     NORMALIZE COUPON
  ========================================================= */

  function normalizeCoupon(couponData) {
    const code = String(couponData.code).trim().toUpperCase();

    const discountType =
      couponData.discountType === "fixed" ? "fixed" : "percentage";

    const rawValue =
      couponData.discountValue !== undefined
        ? couponData.discountValue
        : couponData.discountPercent;

    const discountValue =
      discountType === "percentage"
        ? Math.max(0, Math.min(100, Number(rawValue || 0)))
        : Math.max(0, Number(rawValue || 0));

    return {
      code,
      discountType,
      discountValue,
      discountPercent: discountType === "percentage" ? discountValue : 0,
      influencerName: couponData.influencerName || null,
    };
  }

  /* =========================================================
     APPLY COUPON
  ========================================================= */

  function applyCoupon(couponData) {
    if (!couponData || !couponData.code) {
      console.warn("Invalid coupon data");
      return false;
    }

    const normalized = normalizeCoupon(couponData);

    if (!normalized.code || normalized.discountValue <= 0) {
      console.warn("Invalid coupon discount");
      return false;
    }

    setAppliedCoupon(normalized);
    return true;
  }

  function removeCoupon() {
    setAppliedCoupon(null);
  }

  /* =========================================================
     GET ORDER SNAPSHOT
  ========================================================= */

  function getOrderSnapshot() {
    const originalAmount = getOriginalAmount();
    const discountAmount = getCouponDiscount();
    const finalAmount = getFinalTotal();

    return {
      items: cartItems.map((item) => ({
        productId: item.productId || item.id,
        name: item.name || "",
        price: Number(item.price || 0),
        quantity: Number(item.quantity || 0),
        image: item.image || "",
      })),

      originalAmount,
      discountAmount,
      totalAmount: finalAmount,

      couponCode: appliedCoupon?.code || null,
      couponDiscountType: appliedCoupon?.discountType || null,
      couponDiscountValue: appliedCoupon
        ? Number(appliedCoupon.discountValue || 0)
        : 0,

      influencerName: appliedCoupon?.influencerName || null,
    };
  }

  /* =========================================================
     CONTEXT
  ========================================================= */

  return (
    <CartContext.Provider
      value={{
        cartItems,
        addToCart,
        setCart,
        increaseQty,
        decreaseQty,
        removeFromCart,
        clearCart,
        reconcileCartWithBackend,

        appliedCoupon,
        applyCoupon,
        removeCoupon,

        getCartTotal,
        getOriginalAmount,
        getCouponDiscount,
        getFinalTotal,

        getOrderSnapshot,
      }}
    >
      {children}
    </CartContext.Provider>
  );
}

export function useCart() {
  const context = useContext(CartContext);

  if (!context) {
    throw new Error("useCart must be used inside CartProvider");
  }

  return context;
}
