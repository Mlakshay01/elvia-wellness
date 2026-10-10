import { useEffect, useLayoutEffect, useState } from "react";
import "../styles/Global/Utils.css";
import { isHalloweenActive } from "../config/halloween";
import HalloweenIntro from "../halloween/HalloweenIntro";
import { bootAllowed, removeBootCover, waitForPageReady } from "../boot/bootGate";

const useIsoLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect;

const CLASSIC_MIN_MS = 2200; // the original splash length — the hero's staged entrance is timed to it
const MAX_WAIT_MS = 7000; // never hold the visitor longer than this

/* The original KAEORN splash (used when the Halloween theme is off).
   Same upgrades as the Halloween intro:
   • the decision to show is made on the FIRST render (it used to start hidden and flip on in an
     effect, which let one frame of the page flash before the splash),
   • it stays until the page is genuinely ready (fonts, hero video first frame, marked images),
     with a hard maximum so it can never hang,
   • it fades out instead of vanishing. */
function ClassicLoader() {
  const [phase, setPhase] = useState(() => (bootAllowed() ? "show" : "off")); // show → out → off
  const [holding, setHolding] = useState(false);

  useEffect(() => {
    if (phase === "off") return;
    const gate = waitForPageReady({ minMs: CLASSIC_MIN_MS, maxMs: MAX_WAIT_MS });
    const tHold = setTimeout(() => setHolding(true), CLASSIC_MIN_MS + 120);
    let tEnd = 0;
    gate.promise.then(() => {
      clearTimeout(tHold);
      setPhase("out"); // CSS fades #loader.out over .8 s
      tEnd = setTimeout(() => setPhase("off"), 850);
    });
    return () => {
      gate.cancel();
      clearTimeout(tHold);
      clearTimeout(tEnd);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- run once on mount
  }, []);

  if (phase === "off") return null;

  return (
    <div id="loader" className={`${phase === "out" ? "out" : ""}${holding ? " loader-hold" : ""}`}>
      <div className="loader-word">KAEORN</div>
      <div className="loader-line-wrap">
        <div className="loader-line-fill"></div>
      </div>
      <div className="loader-sub">Because care deserves luxury</div>
    </div>
  );
}

/* While the Halloween theme is on, its intro replaces the KAEORN splash.
   After the end date (or with the flag off) the original splash is used again.
   Either way, the static cover from index.html is removed here, in the same commit in which the
   loader mounts (or immediately, if no loader applies), so there is no gap and no flash. */
export default function Loader() {
  useIsoLayoutEffect(() => {
    removeBootCover();
  }, []);
  return isHalloweenActive() ? <HalloweenIntro /> : <ClassicLoader />;
}
