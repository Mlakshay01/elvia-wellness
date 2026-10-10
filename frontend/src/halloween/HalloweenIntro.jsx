import { useEffect, useLayoutEffect, useState } from "react";
import { HALLOWEEN, isHalloweenActive } from "../config/halloween";
import { setIntroActive } from "./audioEngine";

/* ===========================================================================
   HALLOWEEN INTRO — replaces the KAEORN splash while the theme is on.
   ~2.5 s, fully automatic (no button, no pause): fog → one lightning flash →
   bats crossing → KAEORN fades in red → dissolves straight into the hero.
   Tap / click / Esc / Enter skips. Once per session. Skipped for bots,
   prefers-reduced-motion (no flashing) and private/app routes.
   All timing is proportional to HALLOWEEN.introMs via the --hw-t CSS variable.
=========================================================================== */
const SEEN_KEY = "hw_intro_seen";
const BOT = /bot|crawl|spider|slurp|lighthouse|pagespeed|headless/i;
const SKIP_PATHS = ["/admin", "/cart", "/checkout", "/account", "/addresses", "/my-orders", "/previous-orders", "/order", "/order-success", "/success", "/support", "/verify"];

const useIsoLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect;

function shouldShowHalloweenIntro() {
  if (typeof window === "undefined" || !isHalloweenActive()) return false;
  if (BOT.test(navigator.userAgent)) return false;
  if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return false;
  const p = window.location.pathname;
  if (SKIP_PATHS.some((x) => p === x || p.startsWith(x + "/"))) return false;
  try {
    if (sessionStorage.getItem(SEEN_KEY)) return false;
    if (sessionStorage.getItem("internalNav")) return false;
  } catch {
    /* storage blocked: just show it */
  }
  return true;
}

/* a simple bat silhouette (viewBox 100x34) */
const BAT_PATH =
  "M50 12 C48.4 9.4 48 6.4 47.4 2.6 C46 4.6 45 7 43.4 8.6 C36 4 22 4 4 14 C13 13 18 16 21 23 C24 20 28 20 31 24 C35 21 39 23 42 29 C44 27 48 26 50 30 C52 26 56 27 58 29 C61 23 65 21 69 24 C72 20 76 20 79 23 C82 16 87 13 96 14 C78 4 64 4 56.6 8.6 C55 7 54 4.6 52.6 2.6 C52 6.4 51.6 9.4 50 12 Z";

const BATS = [
  { y: "18%", s: 0.9, d: 0.1, dur: 0.62, dir: 1 },
  { y: "34%", s: 1.5, d: 0.2, dur: 0.58, dir: -1 },
  { y: "58%", s: 0.7, d: 0.3, dur: 0.66, dir: 1 },
  { y: "26%", s: 0.55, d: 0.34, dur: 0.6, dir: -1 },
  { y: "68%", s: 1.1, d: 0.42, dur: 0.54, dir: -1 },
];

export default function HalloweenIntro() {
  const [show, setShow] = useState(shouldShowHalloweenIntro);
  const [leaving, setLeaving] = useState(false);
  const T = HALLOWEEN.introMs;

  useIsoLayoutEffect(() => {
    if (!show) return;
    const body = document.body;
    body.classList.add("hw-intro-on");
    setIntroActive(true);
    try {
      sessionStorage.setItem(SEEN_KEY, "1");
      sessionStorage.removeItem("internalNav");
    } catch { /* ignore */ }

    // the hero starts revealing as the dissolve starts, so one flows into the other
    const reveal = () => {
      body.classList.remove("hw-intro-on");
      body.classList.add("hw-revealing"); // plays the hero entrance (see halloween.css)
      setTimeout(() => body.classList.remove("hw-revealing"), 2600);
    };
    const tReveal = setTimeout(reveal, T * 0.8);
    const tEnd = setTimeout(finish, T);

    function finish() {
      body.classList.remove("hw-intro-on");
      setIntroActive(false);
      setShow(false);
    }

    const skip = () => {
      clearTimeout(tReveal);
      clearTimeout(tEnd);
      reveal();
      setLeaving(true);
      setTimeout(finish, 320);
    };
    const onKey = (e) => (e.key === "Escape" || e.key === "Enter" || e.key === " ") && skip();
    window.addEventListener("keydown", onKey);
    window.__hwSkipIntro = skip;

    return () => {
      clearTimeout(tReveal);
      clearTimeout(tEnd);
      window.removeEventListener("keydown", onKey);
      delete window.__hwSkipIntro;
      body.classList.remove("hw-intro-on");
      setIntroActive(false);
    };
  }, [show, T]);

  if (!show) return null;

  return (
    <div
      className={`hw-intro${leaving ? " hw-intro--leave" : ""}`}
      style={{ "--hw-t": `${T}ms` }}
      onClick={() => window.__hwSkipIntro?.()}
      aria-hidden="true"
    >
      <div className="hw-intro-fog hw-intro-fog--a" />
      <div className="hw-intro-fog hw-intro-fog--b" />

      <svg className="hw-intro-bolt" viewBox="0 0 200 400" preserveAspectRatio="xMidYMin slice">
        <polyline points="108,0 92,80 118,96 84,190 112,204 70,330 96,340 80,400" fill="none" stroke="#dfe9ff" strokeWidth="2.2" strokeLinejoin="round" />
      </svg>
      <div className="hw-intro-flash" />

      {BATS.map((b, i) => (
        <div
          key={i}
          className={`hw-bat ${b.dir > 0 ? "hw-bat--r" : "hw-bat--l"}`}
          style={{ top: b.y, "--s": b.s, "--d": b.d, "--dur": b.dur }}
        >
          <svg viewBox="0 0 100 34" width="130" height="44">
            <path d={BAT_PATH} fill="#050205" />
          </svg>
        </div>
      ))}

      <div className="hw-intro-word">KAEORN</div>
    </div>
  );
}
