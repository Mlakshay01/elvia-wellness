import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";

const API = import.meta.env.VITE_API_BASE;

export default function BlogPost() {
  const { slug } = useParams();
  const navigate = useNavigate();
  const [blog, setBlog] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch(`${API}/api/blogs/${slug}`)
      .then((r) => {
        if (!r.ok) throw new Error("Not found");
        return r.json();
      })
      .then((data) => { setBlog(data); setLoading(false); })
      .catch(() => { setError(true); setLoading(false); });
  }, [slug]);

  /* ── LOADING ── */
  if (loading) {
    return (
      <div style={s.stateWrap}>
        <p style={s.loadingText}>—</p>
      </div>
    );
  }

  /* ── ERROR / NOT FOUND ── */
  if (error || !blog) {
    return (
      <>
        <Helmet>
          <title>Not Found | KAEORN Journal</title>
        </Helmet>
        <div style={s.stateWrap}>
          <p style={s.emptyText}>This story couldn't be found.</p>
          <button style={s.backBtn} onClick={() => navigate("/blogs")}>
            ← Back to Journal
          </button>
        </div>
      </>
    );
  }

  const formattedDate = new Date(blog.createdAt).toLocaleDateString("en-IN", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const canonicalUrl = `https://kaeorn.com/blogs/${slug}`;

  return (
    <>
      <Helmet>
        <title>{blog.title} | KAEORN Journal</title>
        <meta
          name="description"
          content={blog.excerpt || `${blog.title} — from the Kaeorn Journal.`}
        />
        <link rel="canonical" href={canonicalUrl} />
        <meta property="og:title" content={`${blog.title} | KAEORN`} />
        <meta
          property="og:description"
          content={blog.excerpt || `${blog.title} — from the Kaeorn Journal.`}
        />
        <meta property="og:url" content={canonicalUrl} />
        <meta property="og:type" content="article" />
        {blog.coverImage && (
          <meta property="og:image" content={blog.coverImage} />
        )}
        {blog.createdAt && (
          <meta
            property="article:published_time"
            content={new Date(blog.createdAt).toISOString()}
          />
        )}
      </Helmet>

      <div style={s.page}>
        <button style={s.back} onClick={() => navigate("/blogs")}>
          ← Back to Journal
        </button>

        {blog.coverImage && (
          <img
            src={blog.coverImage}
            alt={blog.title}
            style={s.cover}
          />
        )}

        <div style={s.meta}>
          {blog.tags?.map((t) => (
            <span key={t} style={s.tag}>{t}</span>
          ))}
        </div>

        <h1 style={s.title}>{blog.title}</h1>
        <p style={s.date}>{formattedDate}</p>

        <div style={s.content} dangerouslySetInnerHTML={{ __html: blog.content }} />

        {/* ── FOOTER NAV ── */}
        <div style={s.postFooter}>
          <button style={s.back} onClick={() => navigate("/blogs")}>
            ← Back to Journal
          </button>
        </div>
      </div>
    </>
  );
}

const s = {
  /* States */
  stateWrap: {
    textAlign: "center",
    padding: "120px 24px",
    fontFamily: "Inter, sans-serif",
  },
  loadingText: {
    fontFamily: "'DM Mono', monospace",
    fontSize: 20,
    color: "#ccc",
    letterSpacing: "0.3em",
  },
  emptyText: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "1.6rem",
    fontWeight: 300,
    color: "#888",
    marginBottom: 24,
  },
  backBtn: {
    background: "none",
    border: "1px solid #ddd",
    borderRadius: 50,
    padding: "10px 24px",
    cursor: "pointer",
    fontFamily: "'DM Mono', monospace",
    fontSize: 12,
    letterSpacing: "0.1em",
    color: "#555",
  },

  /* Article */
  page: {
    maxWidth: 740,
    margin: "0 auto",
    padding: "100px 24px 80px",
    fontFamily: "Inter, sans-serif",
  },
  back: {
    background: "none",
    border: "none",
    cursor: "pointer",
    color: "#888",
    fontSize: 13,
    marginBottom: 40,
    padding: 0,
    fontFamily: "'DM Mono', monospace",
    letterSpacing: "0.05em",
  },
  cover: {
    width: "100%",
    height: "auto",
    objectFit: "cover",
    borderRadius: 16,
    marginBottom: 32,
    display: "block",
  },
  meta: { display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 },
  tag: {
    fontSize: 11,
    letterSpacing: "0.15em",
    textTransform: "uppercase",
    color: "#8b7355",
    background: "rgba(139,115,85,0.1)",
    padding: "3px 10px",
    borderRadius: 20,
  },
  title: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "clamp(2rem, 5vw, 3.2rem)",
    fontWeight: 300,
    lineHeight: 1.2,
    marginBottom: 12,
  },
  date: {
    fontSize: 12,
    color: "#aaa",
    fontFamily: "'DM Mono', monospace",
    marginBottom: 48,
    letterSpacing: "0.1em",
  },
  content: {
    fontSize: 16,
    lineHeight: 1.9,
    color: "#333",
  },
  postFooter: {
    marginTop: 64,
    paddingTop: 32,
    borderTop: "1px solid #eee",
  },
};