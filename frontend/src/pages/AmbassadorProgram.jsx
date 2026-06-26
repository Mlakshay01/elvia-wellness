import { useState } from "react";
import "../styles/Program/AmbassadorProgram.css";

const TIERS = [
  {
    label: "I",
    name: "Ambassador",
    range: "0 – 10 sales",
    commission: "10%",
    perks: ["Personal creator code (10% off for your audience)", "Creator dashboard", "50% off personal purchases via email"],
  },
  {
    label: "II",
    name: "Growth Partner",
    range: "11 – 50 sales",
    commission: "15%",
    perks: ["Everything in Tier I", "Priority campaign access", "Early product launches"],
    featured: true,
  },
  {
    label: "III",
    name: "Kaeorn Partner",
    range: "51+ sales",
    commission: "20%",
    perks: ["Everything in Tier II", "Complimentary products", "Exclusive launches", "Priority collaborations"],
  },
];

function ApplyModal({ onClose }) {
  const [form, setForm] = useState({ name: "", instagram: "", email: "", reason: "" });
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  function handleChange(e) {
    setForm((f) => ({ ...f, [e.target.name]: e.target.value }));
  }

  async function handleSubmit() {
    if (!form.name || !form.instagram || !form.email) {
      alert("Please fill in all required fields.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) {
      alert("Please enter a valid email.");
      return;
    }
    setLoading(true);
    // TODO: Replace with your actual form endpoint (e.g. Formspree, your backend)
    await new Promise((r) => setTimeout(r, 1000));
    setLoading(false);
    setSubmitted(true);
  }

  return (
    <div className="ap-modal-overlay" onClick={onClose}>
      <div className="ap-modal" onClick={(e) => e.stopPropagation()}>
        <button className="ap-modal-close" onClick={onClose} aria-label="Close">✕</button>

        {submitted ? (
          <div className="ap-modal-success">
            <div className="ap-success-icon">✦</div>
            <h3>Application received.</h3>
            <p>We review every application personally. We'll reach out to <strong>{form.email}</strong> if you're selected.</p>
            <button className="ap-btn-primary" onClick={onClose}>Close</button>
          </div>
        ) : (
          <>
            <p className="ap-modal-eyebrow">AMBASSADOR APPLICATION</p>
            <h2 className="ap-modal-title">Tell us about yourself.</h2>

            <div className="ap-form">
              <div className="ap-field">
                <label htmlFor="ap-name">Full Name *</label>
                <input id="ap-name" name="name" type="text" placeholder="Your name" value={form.name} onChange={handleChange} />
              </div>
              <div className="ap-field">
                <label htmlFor="ap-instagram">Instagram Handle *</label>
                <input id="ap-instagram" name="instagram" type="text" placeholder="@yourhandle" value={form.instagram} onChange={handleChange} />
              </div>
              <div className="ap-field">
                <label htmlFor="ap-email">Email Address *</label>
                <input id="ap-email" name="email" type="email" placeholder="you@email.com" value={form.email} onChange={handleChange} />
              </div>
              <div className="ap-field">
                <label htmlFor="ap-reason">Why do you want to be a Kaeorn Ambassador?</label>
                <textarea id="ap-reason" name="reason" placeholder="Tell us what draws you to the brand..." rows={4} value={form.reason} onChange={handleChange} />
              </div>
              <button className="ap-btn-primary" onClick={handleSubmit} disabled={loading}>
                {loading ? "Submitting..." : "Submit Application →"}
              </button>
              <p className="ap-form-note">Applications are reviewed individually. Acceptance is not guaranteed.</p>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function AmbassadorProgram() {
  const [showModal, setShowModal] = useState(false);

  return (
    <div className="ap-page">
      {showModal && <ApplyModal onClose={() => setShowModal(false)} />}

      {/* ── HERO ── */}
      <section className="ap-hero">
        <div className="ap-hero-inner">
          <p className="ap-eyebrow">THE AMBASSADOR PROGRAM</p>
          <h1 className="ap-hero-title">
            Wear it.
            <br />
            <em>Share it.</em>
            <br />
            Earn from it.
          </h1>
          <p className="ap-hero-sub">
            Join a small circle of creators who believe scent deserves more than a swipe-up.
            Build with us — and earn commission on every bottle you move.
          </p>
          <button className="ap-btn-primary ap-hero-cta" onClick={() => setShowModal(true)}>
            Apply Now →
          </button>
          <p className="ap-hero-footnote">Takes 2 minutes. We review every application personally.</p>
        </div>
      </section>

      {/* ── EARN STRIP ── */}
      <div className="ap-earn-strip">
        <div className="ap-earn-inner">
          <div className="ap-earn-stat">
            <span className="ap-earn-num">10–20%</span>
            <span className="ap-earn-label">Commission per sale</span>
          </div>
          <div className="ap-earn-divider" />
          <div className="ap-earn-stat">
            <span className="ap-earn-num">50%</span>
            <span className="ap-earn-label">Ambassador discount</span>
          </div>
          <div className="ap-earn-divider" />
          <div className="ap-earn-stat">
            <span className="ap-earn-num">∞</span>
            <span className="ap-earn-label">No cap on earnings</span>
          </div>
        </div>
      </div>

      {/* ── BENEFITS ── */}
      <section className="ap-section">
        <div className="ap-section-inner">
          <p className="ap-eyebrow">WHAT YOU GET</p>
          <h2 className="ap-section-title">Built for creators who move with intention.</h2>
          <div className="ap-benefits">
            {[
              { icon: "◈", title: "Your Own Creator Code", body: "A personal code that gives your audience 10% off every order — they save, you earn commission on every sale." },
              { icon: "◉", title: "Live Dashboard", body: "Track clicks, conversions, and commissions in real time. No chasing payouts." },
              { icon: "✦", title: "50% Off Your Purchases", body: "As an ambassador, you're entitled to 50% off personal Kaeorn orders. Simply reach out to us at kaeornwellness.com and we'll process it for you directly." },
              { icon: "◎", title: "First Access", body: "New fragrances, campaigns, and collabs hit your inbox before they go public." },
            ].map((b) => (
              <div className="ap-benefit-card" key={b.title}>
                <span className="ap-benefit-icon">{b.icon}</span>
                <h3 className="ap-benefit-title">{b.title}</h3>
                <p className="ap-benefit-body">{b.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── TIERS ── */}
      <section className="ap-section ap-section--dark">
        <div className="ap-section-inner">
          <p className="ap-eyebrow ap-eyebrow--light">YOUR EARNINGS GROW</p>
          <h2 className="ap-section-title ap-section-title--light">The more you sell, the more you make.</h2>
          <div className="ap-tiers">
            {TIERS.map((t) => (
              <div className={`ap-tier${t.featured ? " ap-tier--featured" : ""}`} key={t.name}>
                {t.featured && <div className="ap-tier-badge">Most Reached</div>}
                <div className="ap-tier-label">Tier {t.label}</div>
                <div className="ap-tier-name">{t.name}</div>
                <div className="ap-tier-range">{t.range}</div>
                <div className="ap-tier-commission">{t.commission}</div>
                <div className="ap-tier-commission-label">commission</div>
                <ul className="ap-tier-perks">
                  {t.perks.map((p) => <li key={p}>{p}</li>)}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section className="ap-section">
        <div className="ap-section-inner">
          <p className="ap-eyebrow">HOW IT WORKS</p>
          <h2 className="ap-section-title">Three steps to your first commission.</h2>
          <div className="ap-steps">
            {[
              { n: "01", title: "Apply", body: "Fill out the short form. We review applications within 48 hours." },
              { n: "02", title: "Launch", body: "Post 1 Reel + 2 Stories featuring Kaeorn. Add your creator link to your bio." },
              { n: "03", title: "Earn", body: "Every sale through your code earns commission — paid out monthly, no minimum threshold." },
            ].map((s) => (
              <div className="ap-step" key={s.n}>
                <div className="ap-step-n">{s.n}</div>
                <h3 className="ap-step-title">{s.title}</h3>
                <p className="ap-step-body">{s.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── ELIGIBILITY ── */}
      <section className="ap-section ap-section--bordered">
        <div className="ap-section-inner ap-eligibility">
          <div>
            <p className="ap-eyebrow">WHO CAN APPLY</p>
            <h2 className="ap-section-title">A few things we look for.</h2>
          </div>
          <ul className="ap-elig-list">
            <li>Follow <strong>@kaeorn.co</strong> on Instagram</li>
            <li>Have personally experienced at least one Kaeorn fragrance</li>
            <li>Align with Kaeorn's aesthetic — quiet, intentional, real</li>
            <li>Willing to create authentic content, not just reposts</li>
          </ul>
        </div>
      </section>

      {/* ── CONTENT USAGE ── */}
      <section className="ap-section">
        <div className="ap-section-inner">
          <p className="ap-eyebrow">CONTENT RIGHTS</p>
          <p className="ap-legal">
            Content created as part of the Kaeorn Ambassador Program may be reposted, featured,
            edited, and used by Kaeorn across its website, social media channels, advertisements,
            and marketing materials. We'll always credit you.
          </p>
        </div>
      </section>

      {/* ── TERMS ── */}
      <section className="ap-section ap-section--bordered">
        <div className="ap-section-inner">
          <p className="ap-eyebrow">PROGRAM TERMS</p>
          <div className="ap-terms-grid">
            <div className="ap-term">
              <h3 className="ap-term-title">Personal Purchases</h3>
              <p className="ap-term-body">
                Your 50% ambassador discount applies to personal Kaeorn orders. These are processed
                manually — simply email us at{" "}
                <a href="mailto:contact@kaeornwellness.com" className="ap-term-link">
                  contact@kaeornwellness.com
                </a>{" "}
                with your order details and we'll take care of it.
              </p>
            </div>
            <div className="ap-term">
              <h3 className="ap-term-title">Your Creator Code</h3>
              <p className="ap-term-body">
                Your code gives your audience <strong>10% off</strong> their Kaeorn purchase.
                Every order placed through your code earns you commission at your current tier rate.
              </p>
            </div>
            <div className="ap-term">
              <h3 className="ap-term-title">Partnership & Termination</h3>
              <p className="ap-term-body">
                Kaeorn reserves the right to terminate any ambassador partnership at any time, with
                or without cause. Any accrued commissions up to the point of termination will be
                honoured. We hold ourselves to the same standard — if we're not showing up for you,
                you're free to walk away too.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── FINAL CTA ── */}
      <section className="ap-final-cta">
        <div className="ap-final-inner">
          <p className="ap-eyebrow">READY?</p>
          <h2 className="ap-final-title">
            Your first sale
            <br />
            <em>is closer than you think.</em>
          </h2>
          <p className="ap-final-sub">
            Kaeorn sells itself — you just have to introduce it.
          </p>
          <button className="ap-btn-primary ap-final-btn" onClick={() => setShowModal(true)}>
            Apply to the Program →
          </button>
        </div>
      </section>
    </div>
  );
}