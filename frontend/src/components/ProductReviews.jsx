import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import AuthModal from "./AuthModal";

const API = import.meta.env.VITE_API_BASE;
const token = () => localStorage.getItem("kaeorn_token");

function Stars({ value, size = 16 }) {
  const full = Math.round(value);
  return (
    <span
      role="img"
      aria-label={`${value} out of 5 stars`}
      style={{ color: "#b08d57", fontSize: size, letterSpacing: "0.1em", whiteSpace: "nowrap" }}
    >
      {"★".repeat(full)}
      {"☆".repeat(5 - full)}
    </span>
  );
}

/**
 * Customer reviews for one product: rating summary, list, and a "write a review" form.
 * Reviews are stored by the backend (/api/reviews) — nothing is hardcoded.
 * `data` comes from useProductReviews() in the product page (so the page can also use the
 * rating for its Product schema).
 */
export default function ProductReviews({ productId, productName, data }) {
  const { user } = useAuth();
  const { summary, reviews, reload } = data;

  const [mine, setMine] = useState(null);
  const [verified, setVerified] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [showAuth, setShowAuth] = useState(false);

  const [rating, setRating] = useState(0);
  const [hover, setHover] = useState(0);
  const [title, setTitle] = useState("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  /* who am I / do I already have a review here? */
  useEffect(() => {
    if (!user) {
      setMine(null);
      setVerified(false);
      return;
    }
    let cancelled = false;
    fetch(`${API}/api/reviews/${productId}/mine`, {
      headers: { Authorization: `Bearer ${token()}` },
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (cancelled || !d) return;
        setMine(d.review);
        setVerified(!!d.verifiedPurchase);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [user, productId]);

  function openForm() {
    if (!user) return setShowAuth(true);
    setRating(mine?.rating || 0);
    setTitle(mine?.title || "");
    setComment(mine?.comment || "");
    setError("");
    setNotice("");
    setShowForm(true);
  }

  async function submit(e) {
    e.preventDefault();
    setError("");
    if (!rating) return setError("Please choose a star rating.");
    if (comment.trim().length < 10) return setError("Please write at least 10 characters.");

    setBusy(true);
    try {
      const res = await fetch(`${API}/api/reviews/${productId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token()}` },
        body: JSON.stringify({ rating, title, comment }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.message || "Could not save your review.");
      setMine(body.review);
      setShowForm(false);
      setNotice("Thank you — your review is live.");
      reload();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm("Delete your review?")) return;
    setBusy(true);
    try {
      const res = await fetch(`${API}/api/reviews/${productId}/mine`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (!res.ok) throw new Error("Could not delete your review.");
      setMine(null);
      setShowForm(false);
      setNotice("Your review was deleted.");
      reload();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section id="reviews" style={s.section} aria-labelledby="reviews-heading">
      {showAuth && <AuthModal onClose={() => setShowAuth(false)} />}

      <div style={s.inner}>
        <p style={s.eyebrow}>Reviews</p>
        <h2 id="reviews-heading" style={s.heading}>
          What customers say about {productName}
        </h2>

        <div style={s.summaryRow}>
          {summary.count > 0 ? (
            <div style={s.summary}>
              <span style={s.avg}>{summary.average.toFixed(1)}</span>
              <div>
                <Stars value={summary.average} size={18} />
                <p style={s.count}>
                  {summary.count} review{summary.count === 1 ? "" : "s"}
                </p>
              </div>
            </div>
          ) : (
            <p style={s.empty}>No reviews yet — be the first to review {productName}.</p>
          )}

          {!showForm && (
            <button type="button" style={s.primaryBtn} onClick={openForm}>
              {!user ? "Sign in to write a review" : mine ? "Edit your review" : "Write a review"}
            </button>
          )}
        </div>

        {notice && <p style={s.notice}>{notice}</p>}

        {showForm && (
          <form onSubmit={submit} style={s.form}>
            <p style={s.formTitle}>
              {mine ? "Edit your review" : "Your review"}
              {verified && <span style={s.badge}>Verified buyer</span>}
            </p>

            <div style={s.field}>
              <span style={s.label}>Rating</span>
              <div onMouseLeave={() => setHover(0)}>
                {[1, 2, 3, 4, 5].map((n) => (
                  <button
                    key={n}
                    type="button"
                    aria-label={`${n} star${n === 1 ? "" : "s"}`}
                    aria-pressed={rating === n}
                    onClick={() => setRating(n)}
                    onMouseEnter={() => setHover(n)}
                    style={{ ...s.starBtn, color: n <= (hover || rating) ? "#b08d57" : "#cfc8bd" }}
                  >
                    ★
                  </button>
                ))}
              </div>
            </div>

            <label style={s.field}>
              <span style={s.label}>Title (optional)</span>
              <input
                style={s.input}
                value={title}
                maxLength={80}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Sum it up in a few words"
              />
            </label>

            <label style={s.field}>
              <span style={s.label}>
                Your review <span style={s.hint}>({comment.length}/1000)</span>
              </span>
              <textarea
                style={{ ...s.input, minHeight: 120, resize: "vertical" }}
                value={comment}
                maxLength={1000}
                onChange={(e) => setComment(e.target.value)}
                placeholder={`How does ${productName} wear on you? Longevity, projection, occasions…`}
              />
            </label>

            {error && <p style={s.error}>{error}</p>}

            <div style={s.actions}>
              <button type="submit" style={s.primaryBtn} disabled={busy}>
                {busy ? "Saving…" : mine ? "Update review" : "Submit review"}
              </button>
              <button type="button" style={s.ghostBtn} onClick={() => setShowForm(false)} disabled={busy}>
                Cancel
              </button>
              {mine && (
                <button type="button" style={s.dangerBtn} onClick={remove} disabled={busy}>
                  Delete
                </button>
              )}
            </div>
          </form>
        )}

        <div style={s.list}>
          {reviews.map((r) => (
            <article key={r._id} style={s.item}>
              <div style={s.itemTop}>
                <Stars value={r.rating} />
                {r.verifiedPurchase && <span style={s.badge}>Verified buyer</span>}
              </div>
              {r.title && <h3 style={s.itemTitle}>{r.title}</h3>}
              <p style={s.itemText}>{r.comment}</p>
              <p style={s.itemMeta}>
                {r.name} ·{" "}
                <time dateTime={r.createdAt}>
                  {new Date(r.createdAt).toLocaleDateString("en-IN", {
                    year: "numeric",
                    month: "short",
                    day: "numeric",
                  })}
                </time>
              </p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

const ink = "var(--ink, #0d0c0b)";
const s = {
  section: {
    background: "var(--paper, #f7f4f0)",
    color: ink,
    padding: "72px 24px 96px",
    fontFamily: "Inter, sans-serif",
    borderTop: "1px solid rgba(13,12,11,0.08)",
  },
  inner: { maxWidth: 820, margin: "0 auto" },
  eyebrow: {
    fontFamily: "'DM Mono', monospace",
    fontSize: 11,
    letterSpacing: "0.3em",
    textTransform: "uppercase",
    opacity: 0.6,
    margin: "0 0 12px",
  },
  heading: {
    fontFamily: "'Cormorant Garamond', serif",
    fontWeight: 400,
    fontSize: "clamp(26px, 4vw, 36px)",
    margin: "0 0 28px",
  },
  summaryRow: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: 20, flexWrap: "wrap" },
  summary: { display: "flex", alignItems: "center", gap: 16 },
  avg: { fontFamily: "'Cormorant Garamond', serif", fontSize: 54, lineHeight: 1 },
  count: { fontFamily: "'DM Mono', monospace", fontSize: 11, letterSpacing: "0.1em", margin: "4px 0 0", opacity: 0.6 },
  empty: { margin: 0, opacity: 0.7, fontSize: 15 },
  notice: { margin: "16px 0 0", fontSize: 14, color: "#4b6b4b" },
  primaryBtn: {
    background: ink,
    color: "var(--paper, #f7f4f0)",
    border: "none",
    borderRadius: 50,
    padding: "12px 26px",
    fontFamily: "'DM Mono', monospace",
    fontSize: 11,
    letterSpacing: "0.15em",
    textTransform: "uppercase",
  },
  ghostBtn: {
    background: "none",
    color: ink,
    border: "1px solid rgba(13,12,11,0.25)",
    borderRadius: 50,
    padding: "12px 22px",
    fontFamily: "'DM Mono', monospace",
    fontSize: 11,
    letterSpacing: "0.15em",
    textTransform: "uppercase",
  },
  dangerBtn: {
    background: "none",
    color: "#9b2c2c",
    border: "none",
    padding: "12px 8px",
    fontFamily: "'DM Mono', monospace",
    fontSize: 11,
    letterSpacing: "0.15em",
    textTransform: "uppercase",
  },
  form: {
    marginTop: 28,
    padding: 24,
    border: "1px solid rgba(13,12,11,0.12)",
    borderRadius: 16,
    background: "rgba(255,255,255,0.55)",
  },
  formTitle: { fontFamily: "'Cormorant Garamond', serif", fontSize: 24, margin: "0 0 16px" },
  field: { display: "block", marginBottom: 18 },
  label: { display: "block", fontFamily: "'DM Mono', monospace", fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8, opacity: 0.7 },
  hint: { opacity: 0.6, textTransform: "none", letterSpacing: 0 },
  input: {
    width: "100%",
    boxSizing: "border-box",
    padding: "12px 14px",
    border: "1px solid rgba(13,12,11,0.2)",
    borderRadius: 10,
    background: "#fff",
    fontFamily: "Inter, sans-serif",
    fontSize: 15,
    color: ink,
  },
  starBtn: { background: "none", border: "none", fontSize: 30, padding: "0 4px", lineHeight: 1 },
  error: { color: "#9b2c2c", fontSize: 14, margin: "0 0 14px" },
  actions: { display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" },
  badge: {
    display: "inline-block",
    marginLeft: 10,
    padding: "3px 10px",
    borderRadius: 50,
    background: "rgba(75,107,75,0.12)",
    color: "#4b6b4b",
    fontFamily: "'DM Mono', monospace",
    fontSize: 10,
    letterSpacing: "0.12em",
    textTransform: "uppercase",
    verticalAlign: "middle",
  },
  list: { marginTop: 36 },
  item: { padding: "24px 0", borderTop: "1px solid rgba(13,12,11,0.1)" },
  itemTop: { display: "flex", alignItems: "center", gap: 6, marginBottom: 8 },
  itemTitle: { fontFamily: "'Cormorant Garamond', serif", fontWeight: 500, fontSize: 22, margin: "0 0 6px" },
  itemText: { margin: "0 0 10px", lineHeight: 1.7, fontSize: 15, whiteSpace: "pre-line" },
  itemMeta: { margin: 0, fontFamily: "'DM Mono', monospace", fontSize: 11, letterSpacing: "0.08em", opacity: 0.6 },
};
