import { Helmet } from "react-helmet-async";
import { Link } from "react-router-dom";

/**
 * Catch-all route. Vercel serves /404.html (real HTTP 404) for unknown URLs,
 * and this component is what the browser then renders.
 */
export default function NotFound() {
  return (
    <>
      <Helmet>
        <title>Page not found | KAEORN</title>
        <meta name="robots" content="noindex" />
      </Helmet>

      <main
        style={{
          minHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          textAlign: "center",
          padding: "140px 24px 80px",
          fontFamily: "'Cormorant Garamond', serif",
        }}
      >
        <p
          style={{
            fontFamily: "'DM Mono', monospace",
            fontSize: 11,
            letterSpacing: "0.3em",
            textTransform: "uppercase",
            opacity: 0.6,
            marginBottom: 16,
          }}
        >
          404
        </p>
        <h1 style={{ fontSize: 40, fontWeight: 400, margin: "0 0 12px" }}>
          This page has drifted away.
        </h1>
        <p style={{ opacity: 0.7, marginBottom: 32 }}>
          The link may be old or mistyped.
        </p>
        <div style={{ display: "flex", gap: 24, flexWrap: "wrap", justifyContent: "center" }}>
          <Link to="/" style={{ color: "inherit" }}>Back to KAEORN</Link>
          <Link to="/perfume/noir-party-perfume" style={{ color: "inherit" }}>Shop THÉ NOIR</Link>
          <Link to="/blogs" style={{ color: "inherit" }}>Journal</Link>
        </div>
      </main>
    </>
  );
}
