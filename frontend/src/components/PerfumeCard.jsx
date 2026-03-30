function PerfumeCard({ to, img, gender, name, mood, price, mrp, navigate, addToCart, user, setShowAuth }) {
  const [added, setAdded] = useState(false);
  const [authType, setAuthType] = useState(null);

  function handleAdd(e) {
    e.stopPropagation(); // prevent card navigate
    if (!user) { setShowAuth(true); return; }
    addToCart({ id: to, name, price: parseInt(price.replace(/[^0-9]/g, "")), image: img, quantity: 1 });
    setAdded(true);
    setTimeout(() => setAdded(false), 2000);
  }

  return (
    <div className="reveal" onClick={() => navigate(to)}>
      <div >
        <img src={img} alt={name} />
        <div>
          <span>Discover →</span>
        </div>
      </div>
      <div >
        <span >{gender} · EAU DE PARFUM</span>
        <h4 >{name}</h4>
        <p >{mood}</p>
        <div >
          <span >{price}</span>
          <span >{mrp}</span>
        </div>
        <div className="prod-actions">
          <button className="prod-explore" onClick={(e) => { e.stopPropagation(); navigate(to); }}>
            Explore
          </button>
          <button
            className="prod-add"
            onClick={handleAdd}
            style={added ? { background: "var(--ink)", color: "var(--paper)" } : {}}
          >
            {added ? "Added ✓" : "Add to Cart"}
          </button>
        </div>
      </div>
    </div>
  );
}