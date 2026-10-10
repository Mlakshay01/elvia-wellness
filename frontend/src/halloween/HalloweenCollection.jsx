import { useCallback, useEffect, useRef, useState } from "react";
import CrawlLink from "../components/CrawlLink";
import { HALLOWEEN_COPY, HALLOWEEN_PRODUCT_LIST } from "../config/halloween";
import { playBell } from "./audioEngine";
import { useCountdown } from "./hooks";

const pad = (n) => String(n).padStart(2, "0");

function Countdown() {
  const left = useCountdown();
  // Same markup on server and first client render (dashes), so there is no layout jump.
  const parts = left
    ? [["Days", left.days], ["Hours", pad(left.hours)], ["Minutes", pad(left.minutes)], ["Seconds", pad(left.seconds)]]
    : [["Days", "--"], ["Hours", "--"], ["Minutes", "--"], ["Seconds", "--"]];
  return (
    <div className="hw-countdown" role="timer" aria-label="Time until Halloween night ends">
      <p className="hw-countdown-label">
        {left === null ? "The night is here. Last chance." : "Until midnight, 31 October"}
      </p>
      <div className="hw-countdown-row">
        {parts.map(([label, v]) => (
          <div key={label} className="hw-countdown-cell">
            <span className="hw-countdown-num">{v}</span>
            <span className="hw-countdown-unit">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Card({ p, navigate, addToCart, user, setShowAuth, addReveal, index }) {
  const ref = useRef(null);
  const [added, setAdded] = useState(null);
  useEffect(() => {
    if (ref.current) addReveal(ref.current);
  }, [addReveal]);

  function handleAdd(e) {
    e.stopPropagation();
    if (!user) return setShowAuth(true);
    const ok = addToCart(p.route);
    if (ok) playBell();
    setAdded(ok ? "ok" : "err");
    setTimeout(() => setAdded(null), 2000);
  }

  return (
    <article
      ref={ref}
      className={`hw-card hw-card--${p.key} reveal reveal-delay-${index + 1}`}
      style={{ "--c-from": p.theme.bgFrom, "--c-to": p.theme.bgTo, "--c-glow": p.theme.glow, "--c-accent": p.theme.accent }}
      onClick={() => navigate(p.route)}
    >
      <div className="hw-card-art">
        <span className="hw-card-glow" aria-hidden="true" />
        <img src={p.images.front} width="400" height="700" loading="lazy" decoding="async" alt={`${p.name} Eau de Parfum by KAEORN`} />
      </div>
      <div className="hw-card-body">
        <span className="hw-card-eyebrow">{p.category} · {p.size}</span>
        <h3 className="hw-card-name"><CrawlLink to={p.route}>{p.name}</CrawlLink></h3>
        <p className="hw-card-tag">{p.tagline}</p>
        <p className="hw-card-mood">{p.mood}</p>
        <div className="hw-card-price">₹{p.price}</div>
        <div className="hw-card-actions">
          <button type="button" className="hw-btn hw-btn--ghost" onClick={(e) => { e.stopPropagation(); navigate(p.route); }}>
            Explore
          </button>
          <button type="button" className="hw-btn" onClick={handleAdd}>
            {added === "ok" ? "Added ✓" : added === "err" ? "Couldn't add" : "+ Cart"}
          </button>
        </div>
      </div>
    </article>
  );
}

export default function HalloweenCollection({ addReveal, ...rest }) {
  const headRef = useCallback((node) => { if (node) addReveal(node); }, [addReveal]);
  return (
    <section className="hw-collection" id="halloween">
      <div className="hw-collection-inner">
        <div ref={headRef} className="hw-collection-head reveal">
          <div>
            <p className="hw-eyebrow">{HALLOWEEN_COPY.collectionEyebrow}</p>
            <h2 className="hw-h2">
              {HALLOWEEN_COPY.collectionTitle}
              <br />
              <em>{HALLOWEEN_COPY.collectionTitleEm}</em>
            </h2>
            <p className="hw-collection-intro">{HALLOWEEN_COPY.collectionIntro}</p>
          </div>
          <Countdown />
        </div>
        <div className="hw-card-row">
          {HALLOWEEN_PRODUCT_LIST.map((p, i) => (
            <Card key={p.key} p={p} index={i} addReveal={addReveal} {...rest} />
          ))}
        </div>
      </div>
    </section>
  );
}
