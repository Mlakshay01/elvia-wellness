/* =========================================================
   SIZE SELECTOR

   Pill-style bottle size picker used on the perfume pages.

   options: [{ id, label, price }]  (see getSizeOptions)
   value:   id of the selected option
   onChange(id)
========================================================= */
export default function SizeSelector({ options, value, onChange }) {
  if (!Array.isArray(options) || options.length < 2) return null;

  return (
    <div style={styles.wrap}>
      <span style={styles.label} id="size-label">
        SIZE
      </span>

      <div style={styles.row} role="radiogroup" aria-labelledby="size-label">
        {options.map((option) => {
          const active = option.id === value;

          return (
            <button
              key={option.id}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => onChange(option.id)}
              style={{ ...styles.option, ...(active ? styles.active : {}) }}
            >
              <span>{option.label}</span>
              <span
                style={{
                  ...styles.optionPrice,
                  ...(active ? styles.optionPriceActive : {}),
                }}
              >
                ₹{option.price}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

const styles = {
  wrap: { margin: "4px 0 24px" },
  label: {
    display: "block",
    fontSize: 12,
    letterSpacing: 2.5,
    color: "#888",
    marginBottom: 10,
  },
  row: { display: "flex", gap: 12, flexWrap: "wrap" },
  option: {
    display: "flex",
    alignItems: "baseline",
    gap: 10,
    padding: "11px 22px",
    borderRadius: 50,
    border: "1px solid #111",
    background: "transparent",
    color: "#111",
    cursor: "pointer",
    fontSize: 14,
    fontFamily: "inherit",
    transition: "background 0.2s ease, color 0.2s ease",
  },
  active: { background: "#111", color: "#fff" },
  optionPrice: { fontSize: 12.5, color: "#888" },
  optionPriceActive: { color: "rgba(255,255,255,0.75)" },
};
