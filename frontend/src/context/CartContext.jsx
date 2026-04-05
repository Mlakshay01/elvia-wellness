import { createContext, useContext, useState, useEffect } from "react";
import { PRODUCTS } from "../data/products";

const CartContext = createContext();

export function CartProvider({ children }) {

  /* ---------------- STATE (rehydrate from localStorage) ---------------- */
  const [cartItems, setCartItems] = useState(() => {
    try {
      const stored = localStorage.getItem("kaeorn_cart");
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });

  /* ---------------- SYNC to localStorage on every change ---------------- */
  useEffect(() => {
    localStorage.setItem("kaeorn_cart", JSON.stringify(cartItems));
  }, [cartItems]);

  /* ---------------- ADD TO CART ---------------- */
  function addToCart(productId) {
    const product = PRODUCTS[productId];
    if (!product) {
      console.warn("addToCart: unknown product id", productId);
      return false;
    }

    setCartItems((prev) => {
      const existing = prev.find((item) => item.id === productId);
      if (existing) {
        return prev.map((item) =>
          item.id === productId
            ? { ...item, quantity: item.quantity + 1 }
            : item
        );
      }
      return [...prev, { ...product, quantity: 1 }];
    });

    return true;
  }

  /* ---------------- SET CART (RE-ORDER) ---------------- */
  function setCart(items) {
    setCartItems(items);
  }

  /* ---------------- INCREASE QTY ---------------- */
  function increaseQty(id) {
    setCartItems((prev) =>
      prev.map((item) =>
        item.id === id
          ? { ...item, quantity: item.quantity + 1 }
          : item
      )
    );
  }

  /* ---------------- DECREASE QTY ---------------- */
  function decreaseQty(id) {
    setCartItems((prev) =>
      prev
        .map((item) =>
          item.id === id
            ? { ...item, quantity: item.quantity - 1 }
            : item
        )
        .filter((item) => item.quantity > 0)
    );
  }

  /* ---------------- REMOVE ITEM ---------------- */
  function removeFromCart(id) {
    setCartItems((prev) => prev.filter((item) => item.id !== id));
  }

  /* ---------------- CLEAR CART ---------------- */
  function clearCart() {
    setCartItems([]);
  }

  /* ---------------- TOTAL ---------------- */
  function getCartTotal() {
    return cartItems.reduce(
      (total, item) => total + item.price * item.quantity,
      0
    );
  }

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
        getCartTotal,
      }}
    >
      {children}
    </CartContext.Provider>
  );
}

export function useCart() {
  return useContext(CartContext);
}