import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { HALLOWEEN_AUDIO, HALLOWEEN_PRODUCT_LIST } from "../config/halloween";
import { armHalloweenAudio, setBed } from "./audioEngine";
import { useHalloweenActive } from "./hooks";
import SoundToggle from "./SoundToggle";

/* Mounted once in <Layout>. While Halloween is on it:
   • arms the first-interaction audio unlock,
   • picks the ambient bed for the current route (home bed, per-perfume bed, or silence),
   • shows the floating mute toggle (never on /admin). */
export default function HalloweenGlobals() {
  const active = useHalloweenActive();
  const { pathname } = useLocation();
  const isAdmin = pathname.startsWith("/admin");

  // body.halloween = the palette's master class (also lets the owner scope extra CSS to the theme)
  useEffect(() => {
    const on = active && !isAdmin;
    document.body.classList.toggle("halloween", on);
    if (on) armHalloweenAudio();
    return () => document.body.classList.remove("halloween");
  }, [active, isAdmin]);

  useEffect(() => {
    if (!active) return setBed(null);
    const product = HALLOWEEN_PRODUCT_LIST.find((p) => p.route === pathname);
    if (isAdmin) setBed(null);
    else if (pathname === "/") setBed(HALLOWEEN_AUDIO.ambient);
    else if (product) setBed(HALLOWEEN_AUDIO.pages[product.key]);
    else setBed(null);
  }, [active, pathname, isAdmin]);

  if (!active || isAdmin) return null;
  return <SoundToggle />;
}
