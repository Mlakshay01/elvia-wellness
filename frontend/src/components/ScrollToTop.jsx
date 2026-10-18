import { useEffect } from "react";
import { useLocation } from "react-router-dom";

/* On every route change: jump to the top — OR, when the URL has a #section (e.g. "/#about" from the
   footer or navbar on another page), scroll to that section.

   Why it needs care: after a route change the home page may still be mounting, and images / fonts /
   the hero video shift the layout for a moment, so a single scroll lands in the wrong place (usually
   the top). So it keeps re-aligning to the section for ~2 s, and stops the instant the visitor
   scrolls, touches or presses a key themselves. */
export default function ScrollToTop() {
  const { pathname, hash } = useLocation();

  useEffect(() => {
    if (!hash || hash.length < 2) {
      // instant jump to top on every route change
      window.scrollTo(0, 0);
      return;
    }

    let id = hash.slice(1);
    try {
      id = decodeURIComponent(id);
    } catch {
      /* keep raw id */
    }

    let cancelled = false;
    let timer = 0;
    let tries = 0;

    const stop = () => {
      cancelled = true;
      clearTimeout(timer);
    };
    const userEvents = ["wheel", "touchstart", "keydown", "pointerdown"];
    userEvents.forEach((ev) => window.addEventListener(ev, stop, { passive: true, once: true }));

    const align = () => {
      if (cancelled) return;
      // "instant" overrides the site's smooth-scroll CSS, so repeated corrections don't lag behind
      document.getElementById(id)?.scrollIntoView({ behavior: "instant", block: "start" });
      if (++tries < 30) timer = setTimeout(align, 70);
    };
    align();

    return () => {
      stop();
      userEvents.forEach((ev) => window.removeEventListener(ev, stop));
    };
  }, [pathname, hash]);

  return null;
}
