import { useEffect, useState } from "react";

// Portrait screens (phones) -> mobile clip; PCs / landscape -> desktop clip.
export default function useHeroVideoSrc() {
  const pick = (mq) => (mq.matches ? "/videos/hero-mobile.mp4" : "/videos/hero-desktop.mp4");
  // null on the server (prerender has no video). On the client the clip is chosen on the very
  // first render — not after an effect — so the <video> starts loading immediately and the
  // boot gate (src/boot/bootGate.js) can wait for it. (The app uses createRoot, not hydrate,
  // so there is no hydration mismatch.)
  const [src, setSrc] = useState(() =>
    typeof window === "undefined" ? null : pick(window.matchMedia("(orientation: portrait)")),
  );
  useEffect(() => {
    const mq = window.matchMedia("(orientation: portrait)");
    const update = () => setSrc(pick(mq));
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  return src;
}