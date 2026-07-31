import { createContext, useContext, useState, useEffect } from "react";
import { PRODUCTS } from "../data/products";

const CartContext = createContext();

/* =========================================================
   BUILD PRODUCT LOOKUP

   PRODUCTS is keyed by route:

   "/perfume/veil-fresh-perfume"

   But each product has its own stable ID:

   "perfume-veil-unisex"

   We support both lookups.
========================================================= */

const PRODUCTS_BY_ID = Object.values(PRODUCTS).reduce((acc, product) => {
  if (product?.id) {
    acc[product.id] = product;
  }

  return acc;
}, {});

/* =========================================================
   RESOLVE PRODUCT

   Accepts either:

   1. Product route:
      /perfume/veil-fresh-perfume

   2. Product ID:
      perfume-veil-unisex

   Always returns the canonical product.
========================================================= */

function resolveProduct(identifier) {
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
   MIGRATE OLD CART ITEM

   Older cart data may contain:

   {
     id: "/perfume/veil-fresh-perfume"
   }

   We convert it to:

   {
     id: "perfume-veil-unisex"
   }

   This prevents old localStorage data from breaking checkout.
========================================================= */

function normalizeCartItem(item) {
  if (!item || typeof item !== "object") {
    return null;
  }

  const identifier = item.productId || item.id;

  const product = resolveProduct(identifier);

  if (!product || !product.id) {
    console.warn("Cart item could not be resolved and will be removed:", item);

    return null;
  }

  const quantity = Number(item.quantity);

  if (!Number.isInteger(quantity) || quantity < 1) {
    return null;
  }

  return {
    // IMPORTANT:
    // Always store the canonical MongoDB productId
    id: product.id,

    productId: product.id,

    name: product.name,

    // Frontend price is display-only.
    // Backend/MongoDB remains the payment source of truth.
    price: Number(product.price) || 0,

    quantity,

    image: product.image || item.image || "",

    category: product.category || item.category || "",
  };
}

/* =========================================================
   INITIAL CART LOADER

   Automatically migrates old URL-based cart items.
========================================================= */

function loadInitialCart() {
  try {
    const stored = localStorage.getItem("kaeorn_cart");

    if (!stored) {
      return [];
    }

    const parsed = JSON.parse(stored);

    if (!Array.isArray(parsed)) {
      return [];
    }

    const normalized = parsed.map(normalizeCartItem).filter(Boolean);

    // Merge duplicate products created by old/new IDs.
    const merged = [];

    normalized.forEach((item) => {
      const existing = merged.find(
        (existingItem) => existingItem.id === item.id,
      );

      if (existing) {
        existing.quantity += item.quantity;
      } else {
        merged.push(item);
      }
    });

    return merged;
  } catch (error) {
    console.error("Failed to load cart:", error);

    return [];
  }
}

export function CartProvider({ children }) {
  /* =========================================================
     CART ITEMS
  ========================================================= */

  const [cartItems, setCartItems] = useState(loadInitialCart);

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
     ADD TO CART

     IMPORTANT:

     The function can receive:

     "/perfume/veil-fresh-perfume"

     But the cart stores:

     "perfume-veil-unisex"

     This is the permanent fix for your payment issue.
  ========================================================= */

  function addToCart(productIdentifier) {
    const product = resolveProduct(productIdentifier);

    if (!product) {
      console.warn("addToCart: unknown product:", productIdentifier);

      return false;
    }

    const canonicalProductId = product.id;

    setCartItems((prev) => {
      const existing = prev.find((item) => item.id === canonicalProductId);

      if (existing) {
        return prev.map((item) =>
          item.id === canonicalProductId
            ? {
                ...item,

                // Keep canonical IDs
                id: canonicalProductId,

                productId: canonicalProductId,

                quantity: Number(item.quantity || 0) + 1,
              }
            : item,
        );
      }

      return [
        ...prev,

        {
          // IMPORTANT:
          // Never store the route as the cart ID.
          id: canonicalProductId,

          productId: canonicalProductId,

          name: product.name,

          price: Number(product.price) || 0,

          quantity: 1,

          image: product.image || "",

          category: product.category || "",
        },
      ];
    });

    return true;
  }

  /* =========================================================
     SET CART

     Used for re-order functionality.

     Reorders may contain old URL-based IDs,
     so everything is normalized here.
  ========================================================= */

  function setCart(items) {
    if (!Array.isArray(items)) {
      console.warn("setCart expects an array");

      return;
    }

    const normalized = items.map(normalizeCartItem).filter(Boolean);

    setCartItems(normalized);
  }

  /* =========================================================
     INCREASE QUANTITY
  ========================================================= */

  function increaseQty(id) {
    const product = resolveProduct(id);

    const canonicalId = product?.id || id;

    setCartItems((prev) =>
      prev.map((item) =>
        item.id === canonicalId
          ? {
              ...item,

              id: canonicalId,

              productId: canonicalId,

              quantity: Number(item.quantity || 0) + 1,
            }
          : item,
      ),
    );
  }

  /* =========================================================
     DECREASE QUANTITY
  ========================================================= */

  function decreaseQty(id) {
    const product = resolveProduct(id);

    const canonicalId = product?.id || id;

    setCartItems((prev) =>
      prev
        .map((item) =>
          item.id === canonicalId
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
    const product = resolveProduct(id);

    const canonicalId = product?.id || id;

    setCartItems((prev) => prev.filter((item) => item.id !== canonicalId));
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

     IMPORTANT:

     This is for frontend display only.

     The backend MUST recalculate the amount
     from MongoDB before creating Razorpay order.
  ========================================================= */

  function getCartTotal() {
    return cartItems.reduce(
      (total, item) =>
        total + Number(item.price || 0) * Number(item.quantity || 0),
      0,
    );
  }

  /* =========================================================
     ORIGINAL AMOUNT
  ========================================================= */

  function getOriginalAmount() {
    return getCartTotal();
  }

  /* =========================================================
     COUPON DISCOUNT

     Frontend display calculation only.

     Backend must independently validate
     and calculate the real discount.
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

  /* =========================================================
     FINAL AMOUNT

     Frontend display only.

     NEVER trust this amount for payment.
  ========================================================= */

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

  /* =========================================================
     REMOVE COUPON
  ========================================================= */

  function removeCoupon() {
    setAppliedCoupon(null);
  }

  /* =========================================================
     GET ORDER SNAPSHOT

     IMPORTANT:

     productId is now ALWAYS the canonical
     MongoDB productId.

     Example:

     "perfume-veil-unisex"

     NOT:

     "/perfume/veil-fresh-perfume"

     The backend still ignores frontend prices
     and calculates everything independently.
  ========================================================= */

  function getOrderSnapshot() {
    const originalAmount = getOriginalAmount();

    const discountAmount = getCouponDiscount();

    const finalAmount = getFinalTotal();

    return {
      /* ---------------- ITEMS ---------------- */

      items: cartItems.map((item) => ({
        productId: item.productId || item.id,

        name: item.name || "",

        // Display/reference only.
        // Backend must ignore this for payment.
        price: Number(item.price || 0),

        quantity: Number(item.quantity || 0),

        image: item.image || "",
      })),

      /* ---------------- PRICING ---------------- */

      originalAmount,

      discountAmount,

      totalAmount: finalAmount,

      /* ---------------- COUPON ---------------- */

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
        /* ---------------- CART ---------------- */

        cartItems,

        addToCart,

        setCart,

        increaseQty,

        decreaseQty,

        removeFromCart,

        clearCart,

        /* ---------------- COUPON ---------------- */

        appliedCoupon,

        applyCoupon,

        removeCoupon,

        /* ---------------- PRICING ---------------- */

        getCartTotal,

        getOriginalAmount,

        getCouponDiscount,

        getFinalTotal,

        /* ---------------- CHECKOUT ---------------- */

        getOrderSnapshot,
      }}
    >
      {children}
    </CartContext.Provider>
  );
}

/* =========================================================
   CUSTOM HOOK
========================================================= */

export function useCart() {
  const context = useContext(CartContext);

  if (!context) {
    throw new Error("useCart must be used inside CartProvider");
  }

  return context;
}
