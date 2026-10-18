import { FESTIVE, FESTIVE_COPY } from "../config/festive";
import { formatLeft, useCountdownTo, useFestivePhase } from "./useFestive";
import "../styles/Festive/festive.css";

/* Compact offer strip for the three SIGNATURE product pages (THÉ NOIR, SOIE FEMME, VEIL).
   Never rendered on the Halloween Edition pages. */
export default function FestiveBanner() {
  const phase = useFestivePhase();
  const live = phase === "live";
  const left = useCountdownTo(Date.parse(live ? FESTIVE.endsAt : FESTIVE.startsAt));
  if (phase !== "live" && phase !== "upcoming") return null;

  return (
    <aside className="fo-banner" aria-label="Dussehra festive offer">
      <p className="fo-banner-head">
        <span>Dussehra offer · 24 hours only</span>
        <span className="fo-banner-time">{live ? `Ends in ${formatLeft(left)}` : "Starts Tue 20 Oct"}</span>
      </p>
      <ul className="fo-banner-tiers">
        {FESTIVE.tiers.map((t, i) => (
          <li key={t.min}>
            <strong>{t.percent}% off</strong>
            <span>{FESTIVE_COPY.tiers[i].buy}</span>
          </li>
        ))}
      </ul>
      <p className="fo-banner-note">Any mix of THÉ NOIR, SOIE FEMME &amp; VEIL. Applied automatically at checkout.</p>
    </aside>
  );
}
