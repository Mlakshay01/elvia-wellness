import { useRef } from "react";
import { Link } from "react-router-dom";
import { HALLOWEEN_COPY, HALLOWEEN_PRODUCT_LIST, HALLOWEEN_MRP, HALLOWEEN_PRICE, discountPercent } from "../config/halloween";
import useHeroVideoSrc from "../hooks/useHeroVideoSrc";
import { useParallax, useReducedMotion } from "./hooks";

/* Home hero while the Halloween theme is on.
   Server render = real headline, copy, links and <img> tags (crawlers see all of it).
   Everything animated (float, mist, embers, parallax, device tilt) is CSS/canvas/effects only. */
export default function HalloweenHero() {
  const stageRef = useRef(null);
  const reduced = useReducedMotion();
  const heroVideoSrc = useHeroVideoSrc();
  useParallax(stageRef, { enabled: !reduced });

  const scrollToSignature = () =>
    document.getElementById("collection")?.scrollIntoView({ behavior: reduced ? "auto" : "smooth" });

  const scrollToCollection = () =>
    document.getElementById("halloween")?.scrollIntoView({ behavior: reduced ? "auto" : "smooth" });

  return (
    <section className="hw-hero" id="hero">
      {heroVideoSrc && !reduced && (
        <video
          key={heroVideoSrc}
          className="hw-hero-video"
          data-boot-wait=""
          src={heroVideoSrc}
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
          aria-hidden="true"
          ref={(el) => {
            if (el) {
              el.muted = true;
              el.play().catch(() => {});
            }
          }}
        />
      )}
      <div className="hw-hero-bg" aria-hidden="true">
        <div className="hw-vignette" />
      </div>

      <div className="hw-hero-copy">
        <p className="hw-eyebrow hw-reveal" style={{ "--i": 0 }}>{HALLOWEEN_COPY.heroEyebrow}</p>
        <h1 className="hw-title hw-reveal" style={{ "--i": 1 }}>{HALLOWEEN_COPY.heroTitle}</h1>
      </div>

      <div className="hw-stage" ref={stageRef}>
        {HALLOWEEN_PRODUCT_LIST.map((p, i) => (
          <Link
            key={p.key}
            to={p.route}
            className={`hw-bottle hw-bottle--${p.key} hw-reveal`}
            style={{ "--i": 2 + i, "--glow": p.theme.glow }}
            aria-label={`${p.name} — ${p.tagline}`}
          >
            <span className="hw-bottle-glow" aria-hidden="true" />
            <span className="hw-bottle-tilt">
              <span className="hw-bottle-float" style={{ "--fd": `${i * -3.2}s` }}>
                <img
                  src={p.images.front}
                  width="400"
                  height="700"
                  alt={`${p.name} Eau de Parfum by KAEORN — ${p.tagline}`}
                  data-boot-wait=""
                  decoding="async"
                  fetchPriority="high"
                  draggable="false"
                />
              </span>
            </span>
            <span className="hw-bottle-caption">
              <span className="hw-bottle-name">{p.name}</span>
              <span className="hw-bottle-tag">{p.tagline}</span>
            </span>
          </Link>
        ))}
      </div>

      <div className="hw-hero-foot">
        <p className="hw-sub hw-reveal" style={{ "--i": 4 }}>{HALLOWEEN_COPY.heroSub}</p>
        <p className="hw-offer hw-reveal" style={{ "--i": 4.5 }}>
          <span className="hw-offer-label">{HALLOWEEN_COPY.offerLabel} · {HALLOWEEN_COPY.offerSeasonal}</span>
          <span className="hw-offer-prices">
            <strong>₹{HALLOWEEN_PRICE}</strong>
            <del>₹{HALLOWEEN_MRP}</del>
            <span className="hw-offer-pct">{discountPercent()}% off</span>
          </span>
        </p>
        <div className="hw-cta-row hw-reveal" style={{ "--i": 5 }}>
          <button type="button" className="hw-btn" onClick={scrollToCollection}>
            {HALLOWEEN_COPY.heroCta}
          </button>
          {/* so the signature scents are always one tap away, never buried under the seasonal edition */}
          <button type="button" className="hw-btn hw-btn--ghost" onClick={scrollToSignature}>
            Signature Scents
          </button>
        </div>
      </div>
    </section>
  );
}