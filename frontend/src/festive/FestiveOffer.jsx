import { FESTIVE, FESTIVE_COPY, inr, tierPreview } from "../config/festive";
import { formatLeft, useCountdownTo, useFestivePhase } from "./useFestive";
import "../styles/Festive/festive.css";

/* Home section: "A Festival of New Beginnings" — the tiered Dussehra offer for the SIGNATURE perfumes.
   Shown while the offer is upcoming (teaser with countdown to the start) or live (countdown to the end);
   renders nothing before/after. Figures are computed from the real unit price, so they can't go stale.
   The server applies the discount at checkout (backend/config/festiveOffer.js). */
export default function FestiveOffer({ unitPrice, onChoose }) {
  const phase = useFestivePhase();
  const live = phase === "live";
  const left = useCountdownTo(Date.parse(live ? FESTIVE.endsAt : FESTIVE.startsAt));
  if (phase !== "live" && phase !== "upcoming") return null;

  const tiers = tierPreview(unitPrice);
  const C = FESTIVE_COPY;

  return (
    <section className="fo" id="festive-offer" aria-labelledby="fo-title">
      <div className="fo-inner">
        <div className="fo-head">
          <p className="fo-eyebrow">{C.eyebrow}</p>
          <h2 className="fo-title" id="fo-title">
            This Dussehra, discover your <em>signature.</em>
          </h2>
          <p className="fo-intro">{C.intro}</p>

          <div className={`fo-clock${live ? " is-live" : ""}`} role="timer">
            <span className="fo-clock-label">{live ? "Offer ends in" : "Starts Tuesday 20 October · in"}</span>
            <span className="fo-clock-time">{formatLeft(left)}</span>
          </div>
        </div>

        <div className="fo-tiers">
          {tiers.map((t, i) => (
            <article key={t.min} className={`fo-tier fo-tier--${i + 1}`}>
              <p className="fo-tier-tag">{C.tiers[i].tag}</p>
              <h3 className="fo-tier-buy">{C.tiers[i].buy}</h3>
              <p className="fo-tier-off">{t.percent}% OFF</p>
              <p className="fo-tier-price">
                {inr(t.total)}
                {t.min > 1 ? " total" : ""} · Save {inr(t.save)}
              </p>
              {C.tiers[i].note && <p className="fo-tier-note">{C.tiers[i].note}</p>}
            </article>
          ))}
        </div>

        <div className="fo-foot">
          <button type="button" className="fo-btn" onClick={onChoose}>
            {C.cta}
          </button>
          <p className="fo-terms">{C.terms}</p>
        </div>
      </div>
    </section>
  );
}
