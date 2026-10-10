/* Small client-only hooks shared by the Halloween components. */
import { useEffect, useState, useSyncExternalStore } from "react";
import { HALLOWEEN, isHalloweenActive } from "../config/halloween";
import { isMuted, subscribeAudio } from "./audioEngine";

/** Adds body classes while a component is mounted (and removes them after). */
export function useBodyClass(...classes) {
  const key = classes.join(" ");
  useEffect(() => {
    if (!key) return;
    const list = key.split(" ");
    document.body.classList.add(...list);
    return () => document.body.classList.remove(...list);
  }, [key]);
}

/** prefers-reduced-motion (false on the server so crawlers get the full markup). */
export function useReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(mq.matches);
    update();
    mq.addEventListener?.("change", update);
    return () => mq.removeEventListener?.("change", update);
  }, []);
  return reduced;
}

/** true for phones/tablets (coarse pointer) — used to cut particle counts. */
export function useIsMobile() {
  const [m, setM] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(max-width: 768px), (pointer: coarse)");
    const update = () => setM(mq.matches);
    update();
    mq.addEventListener?.("change", update);
    return () => mq.removeEventListener?.("change", update);
  }, []);
  return m;
}

/** Reactive mute state shared with the audio engine. */
export function useMuted() {
  return useSyncExternalStore(subscribeAudio, isMuted, () => false);
}

/** Re-evaluates "is Halloween still on?" every minute so the theme ends by itself mid-session. */
export function useHalloweenActive() {
  const [active, setActive] = useState(() => isHalloweenActive());
  useEffect(() => {
    const id = setInterval(() => setActive(isHalloweenActive()), 60_000);
    return () => clearInterval(id);
  }, []);
  return active;
}

/** Countdown to HALLOWEEN.countdownTo. undefined before the first tick (and on the server), null once passed. */
export function useCountdown() {
  const target = Date.parse(HALLOWEEN.countdownTo);
  const [left, setLeft] = useState(undefined); // undefined = not ticked yet, null = date has passed
  useEffect(() => {
    const tick = () => {
      const ms = target - Date.now();
      if (ms <= 0) return setLeft(null);
      const s = Math.floor(ms / 1000);
      setLeft({
        days: Math.floor(s / 86400),
        hours: Math.floor((s % 86400) / 3600),
        minutes: Math.floor((s % 3600) / 60),
        seconds: s % 60,
      });
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [target]);
  return left;
}

/**
 * Mouse parallax + tilt (desktop) and device tilt (mobile) for a container.
 * Writes two CSS variables (--px, --py in -1..1) on the element using rAF —
 * children then translate/rotate with transform only.
 * Feature-detected and permission-safe: iOS asks for motion permission only
 * from a user gesture; if it is denied or unavailable we silently do nothing.
 */
export function useParallax(ref, { enabled = true } = {}) {
  useEffect(() => {
    const el = ref.current;
    if (!el || !enabled) return;

    let tx = 0, ty = 0, cx = 0, cy = 0, raf = 0, running = false;

    const loop = () => {
      cx += (tx - cx) * 0.08;
      cy += (ty - cy) * 0.08;
      el.style.setProperty("--px", cx.toFixed(4));
      el.style.setProperty("--py", cy.toFixed(4));
      if (Math.abs(tx - cx) > 0.001 || Math.abs(ty - cy) > 0.001) raf = requestAnimationFrame(loop);
      else running = false;
    };
    const kick = () => {
      if (!running) {
        running = true;
        raf = requestAnimationFrame(loop);
      }
    };

    const onMove = (e) => {
      if (e.pointerType === "touch") return;
      const r = el.getBoundingClientRect();
      tx = Math.max(-1, Math.min(1, ((e.clientX - r.left) / r.width - 0.5) * 2));
      ty = Math.max(-1, Math.min(1, ((e.clientY - r.top) / r.height - 0.5) * 2));
      kick();
    };
    const onLeave = () => { tx = 0; ty = 0; kick(); };

    let orientationOn = false;
    const onOrient = (e) => {
      if (e.gamma == null || e.beta == null) return; // desktops fire one empty event
      tx = Math.max(-1, Math.min(1, e.gamma / 25));
      ty = Math.max(-1, Math.min(1, (e.beta - 45) / 25));
      kick();
    };
    const startOrientation = () => {
      if (orientationOn) return;
      orientationOn = true;
      window.addEventListener("deviceorientation", onOrient, { passive: true });
    };

    const coarse = window.matchMedia("(pointer: coarse)").matches;
    let permHandler;
    if (coarse && typeof window.DeviceOrientationEvent !== "undefined") {
      if (typeof window.DeviceOrientationEvent.requestPermission === "function") {
        // iOS 13+: must be requested from a gesture. Piggy-back on the first tap, never block it.
        permHandler = () => {
          window.DeviceOrientationEvent.requestPermission()
            .then((r) => r === "granted" && startOrientation())
            .catch(() => {});
        };
        window.addEventListener("touchend", permHandler, { once: true, passive: true });
      } else {
        startOrientation();
      }
    }

    el.addEventListener("pointermove", onMove, { passive: true });
    el.addEventListener("pointerleave", onLeave, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      el.removeEventListener("pointermove", onMove);
      el.removeEventListener("pointerleave", onLeave);
      window.removeEventListener("deviceorientation", onOrient);
      if (permHandler) window.removeEventListener("touchend", permHandler);
    };
  }, [ref, enabled]);
}

export { HALLOWEEN };
