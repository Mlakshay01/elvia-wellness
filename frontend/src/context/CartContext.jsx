import { createContext, useContext, useState } from "react";
import { PRODUCTS } from "../data/products"; // 

const CartContext = createContext();

export function CartProvider({ children }) {
  const [cartItems, setCartItems] = useState([]);

  function addToCart(productId) {
    const product = PRODUCTS[productId]; // ← always use canonical data
    if (!product) {
      console.warn("addToCart: unknown product id", productId);
      return;
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
        setCart,          // ✅ NEW
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






