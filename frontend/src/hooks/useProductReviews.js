import { useCallback, useEffect, useState } from "react";

const API = import.meta.env.VITE_API_BASE;

export const EMPTY_SUMMARY = {
  count: 0,
  average: 0,
  distribution: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
};

/**
 * Loads the published reviews + rating summary for one product.
 * At build time scripts/prerender.mjs passes the latest reviews in via globalThis, so the
 * server-rendered HTML (and Product schema) already contain them; in the browser it fetches.
 */
export default function useProductReviews(productId) {
  const pre = globalThis.__PRERENDER_DATA__?.reviews?.[productId];

  const [summary, setSummary] = useState(pre?.summary ?? EMPTY_SUMMARY);
  const [reviews, setReviews] = useState(pre?.reviews ?? []);
  const [loading, setLoading] = useState(!pre);

  const reload = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/reviews/${productId}`);
      if (!res.ok) throw new Error("bad response");
      const data = await res.json();
      setSummary(data.summary || EMPTY_SUMMARY);
      setReviews(Array.isArray(data.reviews) ? data.reviews : []);
    } catch {
      /* keep whatever we already have (prerendered data or empty) */
    } finally {
      setLoading(false);
    }
  }, [productId]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { summary, reviews, loading, reload };
}
