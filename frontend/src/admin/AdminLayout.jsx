import { useState } from "react";
import Sidebar from "./Sidebar";

export default function AdminLayout({ children }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div style={styles.layout}>
      {sidebarOpen && (
        <div style={styles.overlay} onClick={() => setSidebarOpen(false)} />
      )}

      <div
        className="admin-sidebar-wrap"
        style={{
          ...styles.sidebarWrap,
          transform: sidebarOpen ? "translateX(0)" : undefined,
        }}
      >
        <Sidebar onClose={() => setSidebarOpen(false)} />
      </div>

      <main style={styles.main}>
        <div className="admin-mobile-header" style={styles.mobileHeader}>
          <button style={styles.menuBtn} onClick={() => setSidebarOpen(true)}>
            ☰
          </button>
          <span style={styles.mobileBrand}>KAEORN</span>
        </div>
        {children}
      </main>
    </div>
  );
}

const styles = {
  layout: {
    display: "flex",
    minHeight: "100vh",
    background: "#fafafa",
    position: "relative",
  },
  overlay: {
    position: "fixed",
    inset: 0,
    background: "rgba(0,0,0,0.3)",
    zIndex: 99,
  },
  sidebarWrap: {
    position: "fixed",
    top: 0,
    left: 0,
    bottom: 0,
    zIndex: 100,
    transition: "transform 0.25s ease",
  },
  main: {
    flex: 1,
    minWidth: 0,
    marginLeft: 0,
  },
  mobileHeader: {
    alignItems: "center",
    gap: 16,
    padding: "16px 20px",
    borderBottom: "1px solid #eee",
    background: "#fff",
  },
  menuBtn: {
    fontSize: 20,
    background: "none",
    border: "none",
    cursor: "none",
  },
  mobileBrand: {
    letterSpacing: "3px",
    fontWeight: 500,
    fontSize: 14,
  },
};
