import { useEffect, useState } from "react";
import "../styles/Home/DussehraOffer.css";
import { PRODUCTS } from "../data/products";
import {
  DUSSEHRA_OFFER,
  isDussehraOfferActive,
  computeDussehraOffer,
} from "../config/dussehraOffer";

/* The three signature perfumes this offer covers (100 ml). Halloween Edition is NOT here. */
const SIGNATURE = [
  { route: "/perfume/noir-party-perfume", gender: "MEN", mood: "Fruity · Aromatic · Gourmand" },
  { route: "/perfume/veil-fresh-perfume", gender: "UNISEX", mood: "Citrus · Spicy · Woody" },
  { route: "/perfume/soie-femme-floral-perfume", gender: "WOMEN", mood: "Floral · Roasted · Gourmand" },
];

const inr = (n) => `₹${Number(n).toLocaleString("en-IN")}`;
const pad = (n) => String(n).padStart(2, "0");

export function useOfferClock() {
  // false on server + first client render, so prerendered HTML never bakes in a stale "live" offer.
  const [state, setState] = useState({ active: false, left: null });
  useEffect(() => {
    const tick = () => {
      const now = Date.now();
      if (!isDussehraOfferActive(now)) return setState({ active: false, left: null });
      const ms = Math.max(0, Date.parse(DUSSEHRA_OFFER.end) - now);
      setState({
        active: true,
        left: {
          h: Math.floor(ms / 3600000),
          m: Math.floor((ms % 3600000) / 60000),
          s: Math.floor((ms % 60000) / 1000),
        },
      });
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return state;
}

export default function DussehraOffer({ navigate, addToCart, user, setShowAuth }) {
  const { active, left } = useOfferClock();
  const [added, setAdded] = useState(null);
  if (!active) return null;

  const unit = PRODUCTS[SIGNATURE[0].route].price; // 1399 — all three signature scents share it

  const tiers = DUSSEHRA_OFFER.tiers.map((t) => {
    const items = [{ id: DUSSEHRA_OFFER.eligibleProductIds[0], price: unit, quantity: t.units }];
    const r = computeDussehraOffer(items);
    return { ...t, total: unit * t.units - r.discount, save: r.discount };
  });

  function handleAdd(e, route) {
    e.stopPropagation();
    if (!user) return setShowAuth(true);
    const ok = addToCart(route);
    setAdded(ok ? route : null);
    setTimeout(() => setAdded(null), 1800);
  }

  return (
    <section className="dso" id="dussehra-offer" aria-label="Dussehra signature offer">
      <div className="dso-inner">
        <p className="dso-eyebrow">A FESTIVAL OF NEW BEGINNINGS</p>
        <h2 className="dso-title">
          This Dussehra, <em>discover your signature.</em>
        </h2>
        <p className="dso-sub">
          For 24 hours only, experience KAEORN&apos;s signature fragrances with an exclusive festive offer.
        </p>

        {left && (
          <p className="dso-clock" role="timer" aria-label="Time left on the Dussehra offer">
            Ends at midnight · {pad(left.h)}:{pad(left.m)}:{pad(left.s)} left
          </p>
        )}

        <div className="dso-tiers">
          {tiers.map((t, i) => (
            <div key={t.units} className={`dso-tier${i === tiers.length - 1 ? " dso-tier--best" : ""}`}>
              <span className="dso-tier-tag">TIER {i + 1} · {t.tag}</span>
              <span className="dso-tier-buy">{t.title}</span>
              <span className="dso-tier-pct">{t.percent}% OFF</span>
              <span className="dso-tier-total">
                {t.units === 1 ? inr(t.total) : `${inr(t.total)} total`} · Save {inr(t.save)}
              </span>
              {i === tiers.length - 1 && <span className="dso-tier-note">Maximum savings.</span>}
            </div>
          ))}
        </div>

        <div className="dso-products">
          {SIGNATURE.map((s) => {
            const p = PRODUCTS[s.route];
            return (
              <article key={s.route} className="dso-card" onClick={() => navigate(s.route)}>
                <img src={p.image} alt={`${p.name} Eau de Parfum by KAEORN`} loading="lazy" decoding="async" />
                <div className="dso-card-body">
                  <span className="dso-card-eyebrow">{s.gender} · 100 ml</span>
                  <h3 className="dso-card-name">{p.name}</h3>
                  <p className="dso-card-mood">{s.mood}</p>
                  <span className="dso-card-price">{inr(p.price)}</span>
                  <div className="dso-card-actions">
                    <button type="button" className="dso-btn dso-btn--ghost" onClick={(e) => { e.stopPropagation(); navigate(s.route); }}>
                      Explore
                    </button>
                    <button type="button" className="dso-btn" onClick={(e) => handleAdd(e, s.route)}>
                      {added === s.route ? "Added ✓" : "+ Cart"}
                    </button>
                  </div>
                </div>
              </article>
            );
          })}
        </div>

        <p className="dso-fine">
          Applied automatically in your cart on THÉ NOIR, VEIL and SOIE FEMME (100 ml), mix and match.
          Not valid on the Halloween Edition, Discovery Set or balms. Cannot be combined with partner codes.
        </p>
      </div>
    </section>
  );
}
