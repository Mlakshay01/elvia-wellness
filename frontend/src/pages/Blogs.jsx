import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";

const API = import.meta.env.VITE_API_BASE;

export default function Blogs() {
  const [blogs, setBlogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetch(`${API}/api/blogs`)
      .then((r) => r.json())
      .then((data) => { setBlogs(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  return (
    <>
      <Helmet>
        <title>Journal | KAEORN</title>
        <meta
          name="description"
          content="Stories, insights, and the world of Kaeorn — fragrance, quiet luxury, and the art of everyday elegance."
        />
        <link rel="canonical" href="https://kaeorn.com/blogs" />
        <meta property="og:title" content="Journal | KAEORN" />
        <meta property="og:description" content="Stories and insights from the world of Kaeorn." />
        <meta property="og:url" content="https://kaeorn.com/blogs" />
        <meta property="og:type" content="website" />
      </Helmet>

      <div style={s.page}>
        <div style={s.header}>
          <p style={s.eyebrow}>Journal</p>
          <h1 style={s.title}>Stories & Insights</h1>
        </div>

        {/* ── LOADING ── */}
        {loading && (
          <div style={s.loadingWrap}>
            <p style={s.loadingText}>—</p>
          </div>
        )}

        {/* ── EMPTY STATE ── */}
        {!loading && blogs.length === 0 &&(
          <div style={s.emptyWrap}>
            <p style={s.emptyText}>The journal is quiet for now.</p>
            <p style={s.emptySubtext}>New stories are on their way.</p>
          </div>
        )}

        {/* ── GRID ── */}
        {!loading && blogs.length > 0 && (
          <div style={s.grid}>
            {blogs.map((blog) => (
              <div
                key={blog._id}
                style={s.card}
                onClick={() => navigate(`/blogs/${blog.slug}`)}
                onMouseEnter={(e) => (e.currentTarget.style.transform = "translateY(-4px)")}
                onMouseLeave={(e) => (e.currentTarget.style.transform = "translateY(0)")}
              >
                {blog.coverImage && (
                  <img
                    src={blog.coverImage}
                    alt={blog.title}
                    style={s.img}
                  />
                )}
                <div style={s.cardBody}>
                  {blog.tags?.length > 0 && (
                    <div style={s.tags}>
                      {blog.tags.map((t) => (
                        <span key={t} style={s.tag}>{t}</span>
                      ))}
                    </div>
                  )}
                  <h2 style={s.cardTitle}>{blog.title}</h2>
                  {blog.excerpt && <p style={s.excerpt}>{blog.excerpt}</p>}
                  <div style={s.cardFooter}>
                    <p style={s.date}>
                      {new Date(blog.createdAt).toLocaleDateString("en-IN", {
                        year: "numeric",
                        month: "long",
                        day: "numeric",
                      })}
                    </p>
                    <span style={s.readMore}>Read →</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

const s = {
  page: {
    maxWidth: 1100,
    margin: "0 auto",
    padding: "100px 24px 80px",
    fontFamily: "Inter, sans-serif",
  },
  header: { textAlign: "center", marginBottom: 64 },
  eyebrow: {
    fontFamily: "'DM Mono', monospace",
    fontSize: 11,
    letterSpacing: "0.25em",
    color: "#9a9089",
    textTransform: "uppercase",
    marginBottom: 16,
  },
  title: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "clamp(2.5rem, 5vw, 4rem)",
    fontWeight: 300,
  },

  /* Loading */
  loadingWrap: { textAlign: "center", padding: "80px 0" },
  loadingText: {
    fontFamily: "'DM Mono', monospace",
    fontSize: 20,
    color: "#ccc",
    letterSpacing: "0.3em",
    animation: "pulse 1.5s ease-in-out infinite",
  },

  /* Empty */
  emptyWrap: { textAlign: "center", padding: "80px 0" },
  emptyText: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: "1.6rem",
    fontWeight: 300,
    color: "#888",
    marginBottom: 8,
  },
  emptySubtext: {
    fontFamily: "'DM Mono', monospace",
    fontSize: 11,
    letterSpacing: "0.2em",
    color: "#bbb",
    textTransform: "uppercase",
  },

  /* Grid */
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
    gap: 32,
  },
  card: {
    background: "#fff",
    borderRadius: 16,
    border: "1px solid #eee",
    overflow: "hidden",
    cursor: "pointer",
    transition: "transform .25s ease, box-shadow .25s ease",
  },
  img: { width: "100%", height: 220, objectFit: "cover", display: "block" },
  cardBody: { padding: 24 },
  tags: { display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" },
  tag: {
    fontSize: 11,
    letterSpacing: "0.15em",
    textTransform: "uppercase",
    color: "#8b7355",
    background: "rgba(139,115,85,0.1)",
    padding: "3px 10px",
    borderRadius: 20,
  },
  cardTitle: {
    fontFamily: "'Cormorant Garamond', serif",
    fontSize: 22,
    fontWeight: 400,
    marginBottom: 10,
    lineHeight: 1.3,
  },
  excerpt: { fontSize: 14, color: "#666", lineHeight: 1.7, marginBottom: 20 },
  cardFooter: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },
  date: {
    fontSize: 12,
    color: "#aaa",
    fontFamily: "'DM Mono', monospace",
    margin: 0,
  },
  readMore: {
    fontFamily: "'DM Mono', monospace",
    fontSize: 11,
    letterSpacing: "0.15em",
    color: "#8b7355",
    textTransform: "uppercase",
  },
};