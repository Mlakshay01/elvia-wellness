import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ProfileMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function handleClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () =>
      document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Luxury initial (safe fallback)
  const initial = user?.name?.charAt(0)?.toUpperCase() || "K";

  return (
    <div ref={ref} style={{ position: "relative" }}>
      {/* PROFILE CIRCLE */}
      <div
        onClick={() => setOpen(!open)}
        style={{
          ...styles.avatar,
          ...(open ? styles.avatarActive : {}),
        }}
        title="Account"
      >
        {initial}
      </div>

      {open && (
        <div style={styles.menu}>
          <button
            style={styles.item}
            onClick={() => {
              navigate("/account");
              setOpen(false);
            }}
          >
            Account
          </button>

          {/* <button
            style={styles.item}
            onClick={() => {
              navigate("/addresses");
              setOpen(false);
            }}
          >
            Addresses
          </button> */}

          {/* NEW: CART */}
          {/* <button
            style={styles.item}
            onClick={() => {
              navigate("/cart");
              setOpen(false);
            }}
          >
            Cart
          </button> */}

          <div style={styles.divider} />

          <button
            style={styles.item}
            onClick={() => {
              navigate("/my-orders");
              setOpen(false);
            }}
          >
            My Orders
          </button>

          <button
            style={styles.item}
            onClick={() => {
              navigate("/previous-orders");
              setOpen(false);
            }}
          >
            Previous Orders
          </button>

          <div style={styles.divider} />


          <button
            style={styles.item}
            onClick={() => {
              navigate("/support");
              setOpen(false);
            }}
          >
            Support / Help
          </button>

          <button
            style={{ ...styles.item, color: "#8b1e1e" }}
            onClick={() => {
              logout();
              setOpen(false);
            }}
          >
            Logout
          </button>
        </div>
      )}
    </div>
  );
}

/* ---------- LUXURY STYLES ---------- */

const styles = {
  avatar: {
    width: 34,
    height: 34,
    borderRadius: "50%",
    background: "#f5f5f5",
    color: "#111",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    cursor: "pointer",
    fontSize: 14,
    fontWeight: 500,
    border: "1px solid #e6e6e6",
    transition: "all 0.25s ease",
    letterSpacing: "0.4px",
  },

  avatarActive: {
    background: "#111",
    color: "#fff",
    borderColor: "#111",
  },

  menu: {
    position: "absolute",
    right: 0,
    top: "120%",
    background: "#fff",
    borderRadius: 16,
    boxShadow: "0 14px 36px rgba(0,0,0,0.12)",
    minWidth: 190,
    padding: "10px 0",
    zIndex: 100,
  },

  item: {
    width: "100%",
    padding: "12px 18px",
    background: "none",
    border: "none",
    textAlign: "left",
    fontSize: 13,
    cursor: "pointer",
    color: "#111",
  },

  divider: {
    height: 1,
    background: "#eee",
    margin: "8px 0",
  },
};
