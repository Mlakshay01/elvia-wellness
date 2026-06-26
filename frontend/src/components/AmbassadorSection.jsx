import "../styles/Program/AmbassadorSection.css";

export default function AmbassadorSection({ addReveal, navigate }) {
  return (
    <section className="creator-section">

      {/* LEFT */}
      <div className="creator-left reveal" ref={addReveal}>
        <span className="creator-eyebrow">KAEORN AMBASSADORS</span>

        <h2 className="creator-headline">
          <span className="creator-thin">Love Kaeorn?</span>
          Turn your passion
          <br />
          into <em>rewards.</em>
        </h2>

        <p>
          Join an exclusive circle of fragrance enthusiasts and creators
          shaping the world of Kaeorn — earn from every bottle you move.
        </p>

        <div className="creator-pills">
          <div className="creator-pill">
            <span className="creator-pill-dot" />
            50% creator discount
          </div>
          <div className="creator-pill">
            <span className="creator-pill-dot" />
            Personal creator code
          </div>
          <div className="creator-pill">
            <span className="creator-pill-dot" />
            10–20% commission
          </div>
          <div className="creator-pill">
            <span className="creator-pill-dot" />
            Early access & rewards
          </div>
        </div>

        <button className="creator-btn" onClick={() => navigate("/program/ambassador")}>
          Explore Program →
        </button>
      </div>

      {/* RIGHT */}
      <div className="creator-right reveal reveal-delay-1" ref={addReveal}>
        <div className="creator-img-frame">
          <img
            src="https://images.unsplash.com/photo-1524504388940-b1c1722653e1?w=900&q=80"
            alt="Kaeorn Ambassador"
          />
          <div className="creator-img-overlay" />
        </div>

        <div className="creator-floating-card">
          <p className="creator-card-label">FOUNDING CIRCLE</p>
          <h4>Founding Ambassadors</h4>
          <p>Limited applications open.</p>
        </div>

        <div className="creator-accent-bar" />
      </div>

    </section>
  );
}