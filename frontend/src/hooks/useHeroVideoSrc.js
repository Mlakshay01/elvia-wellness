import { useEffect, useState } from "react";

// Portrait screens (phones) -> mobile clip; PCs / landscape -> desktop clip.
export default function useHeroVideoSrc() {
  const [src, setSrc] = useState(null); // null on server -> no hydration mismatch
  useEffect(() => {
    const mq = window.matchMedia("(orientation: portrait)");
    const update = () =>
      setSrc(mq.matches ? "/videos/hero-mobile.mp4" : "/videos/hero-desktop.mp4");
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  return src;
}