import { useEffect, useLayoutEffect, useState } from "react";
import { HALLOWEEN, isHalloweenActive } from "../config/halloween";
import { bootAllowed, waitForPageReady } from "../boot/bootGate";
import { setIntroActive } from "./audioEngine";

/* ===========================================================================
   HALLOWEEN INTRO — replaces the KAEORN splash while the theme is on.

   Two modes (decided synchronously on the first render, so there is never a frame
   of the page showing before the loader):
     "intro"  first load in this session: ~2.5 s cinematic — fog, one lightning
              flash, bats, KAEORN fading in red.
     "quick"  later loads in the same session, and prefers-reduced-motion (no
              flash): just the red KAEORN wordmark and a thin progress line.

   PURPOSEFUL: it does not leave on a timer. After its minimum time it waits
   until the page behind it is genuinely ready — fonts, the hero video's first
   frame, the hero bottle photos (everything marked data-boot-wait; see
   src/boot/bootGate.js) — and holds on the wordmark with a progress line until
   then. A hard maximum means it can never hang. Tap / Esc / Enter skips the
   ANIMATION but still waits for readiness.

   The static cover painted by index.html (before any JS) is removed by <Loader>
   in the same commit this overlay appears, so the hand-over is seamless.
   Skipped for bots and private/app routes (bootAllowed).
=========================================================================== */
const SEEN_KEY = "hw_intro_seen";
const MAX_WAIT_MS = 7000; // never hold the visitor longer than this
const QUICK_MIN_MS = 450; // avoids a 1-frame flicker when everything is already cached

const useIsoLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect;

function decideMode() {
  if (typeof window === "undefined" || !isHalloweenActive() || !bootAllowed()) return "off";
  const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  let seen = false;
  try {
    seen = !!sessionStorage.getItem(SEEN_KEY);
  } catch {
    /* storage blocked: treat as first visit */
  }
  return reduced || seen ? "quick" : "intro";
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
  const [mode] = useState(decideMode);
  const [phase, setPhase] = useState("run"); // run → hold (waiting for the page) → out (dissolving)
  const [fast, setFast] = useState(false);
  const [done, setDone] = useState(false);
  const T = HALLOWEEN.introMs;

  useIsoLayoutEffect(() => {
    if (mode === "off") return;
    const body = document.body;
    body.classList.add("hw-intro-on");
    setIntroActive(mode === "intro"); // thunder only plays during the real intro
    if (mode === "intro") {
      try {
        sessionStorage.setItem(SEEN_KEY, "1");
        sessionStorage.removeItem("internalNav");
      } catch { /* ignore */ }
    }

    const minMs = mode === "intro" ? T * 0.8 : QUICK_MIN_MS;
    const outMs = mode === "intro" ? T * 0.2 : 350;
    const gate = waitForPageReady({ minMs, maxMs: MAX_WAIT_MS });
    let tRevealClear = 0;
    let tEnd = 0;

    // still waiting once the minimum has passed → show the "waiting" state (breathing wordmark + line)
    const tHold = setTimeout(() => setPhase((p) => (p === "run" ? "hold" : p)), minMs + 120);

    gate.promise.then(() => {
      clearTimeout(tHold);
      // the hero starts revealing as the dissolve starts, so one flows into the other
      body.classList.remove("hw-intro-on");
      body.classList.add("hw-revealing"); // plays the hero entrance (see halloween.css)
      tRevealClear = setTimeout(() => body.classList.remove("hw-revealing"), 2600);
      setPhase("out");
      tEnd = setTimeout(() => {
        setIntroActive(false);
        setDone(true);
      }, outMs);
    });

    // tap / Esc / Enter / Space: skip the animation, but still wait for the page to be ready
    const skip = () => {
      setFast(true);
      gate.expedite();
    };
    const onKey = (e) => (e.key === "Escape" || e.key === "Enter" || e.key === " ") && skip();
    window.addEventListener("keydown", onKey);
    window.__hwSkipIntro = skip;

    return () => {
      gate.cancel();
      clearTimeout(tHold);
      clearTimeout(tEnd);
      clearTimeout(tRevealClear);
      window.removeEventListener("keydown", onKey);
      delete window.__hwSkipIntro;
      body.classList.remove("hw-intro-on", "hw-revealing");
      setIntroActive(false);
    };
  }, [mode, T]);

  if (mode === "off" || done) return null;

  const cls = ["hw-intro", `hw-intro--${mode}`, phase === "hold" && "hw-intro--hold", phase === "out" && "hw-intro--out", fast && "hw-intro--fast"]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={cls} style={{ "--hw-t": `${T}ms` }} onClick={() => window.__hwSkipIntro?.()} aria-hidden="true">
      {mode === "intro" && (
        <>
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
        </>
      )}

      <div className="hw-intro-word">KAEORN</div>
      <div className="hw-intro-line"><span /></div>
    </div>
  );
}
