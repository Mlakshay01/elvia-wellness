import { useEffect, useState } from "react";
import { FESTIVE, festivePhase } from "../config/festive";

/** Current offer phase ("off" | "upcoming" | "live" | "ended"); re-renders exactly when it changes. */
export function useFestivePhase() {
  const [phase, setPhase] = useState(() => festivePhase());
  useEffect(() => {
    let t = 0;
    const arm = () => {
      const now = Date.now();
      const next = [Date.parse(FESTIVE.startsAt), Date.parse(FESTIVE.endsAt)].filter((b) => b > now);
      if (!next.length) return;
      // setTimeout caps at ~24.8 days; re-arm in chunks for anything further away
      const wait = Math.min(Math.min(...next) - now + 50, 2 ** 31 - 1);
      t = setTimeout(() => {
        setPhase(festivePhase());
        arm();
      }, wait);
    };
    arm();
    return () => clearTimeout(t);
  }, []);
  return phase;
}

/** { days, hours, minutes, seconds } until `target` (ms). undefined before the first tick, null once passed. */
export function useCountdownTo(target) {
  const [left, setLeft] = useState(undefined);
  useEffect(() => {
    const tick = () => {
      const ms = target - Date.now();
      if (ms <= 0) return setLeft(null);
      const s = Math.floor(ms / 1000);
      setLeft({ days: Math.floor(s / 86400), hours: Math.floor((s % 86400) / 3600), minutes: Math.floor((s % 3600) / 60), seconds: s % 60 });
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [target]);
  return left;
}

const pad = (n) => String(n).padStart(2, "0");

/** "07:42:10", or "2d 07h 42m" when more than a day away; "--:--:--" before the first tick. */
export function formatLeft(left) {
  if (!left) return "--:--:--";
  if (left.days > 0) return `${left.days}d ${pad(left.hours)}h ${pad(left.minutes)}m`;
  return `${pad(left.hours)}:${pad(left.minutes)}:${pad(left.seconds)}`;
}
