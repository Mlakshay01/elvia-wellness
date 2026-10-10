import { useEffect, useRef } from "react";
import { useIsMobile, useReducedMotion } from "./hooks";

/* Soft glowing dots drifting across a section: "ember" rises (warm), "frost" falls (cold).
   • Client only — draws nothing on the server, so crawlers see clean HTML.
   • One pre-rendered sprite + drawImage (cheap). Pauses when off-screen or tab hidden.
   • Fewer particles on mobile, none at all with prefers-reduced-motion. */
const PALETTES = {
  ember: { core: "255,196,120", glow: "255,70,40" },
  frost: { core: "235,248,255", glow: "140,200,255" },
  dust: { core: "255,225,210", glow: "200,60,80" },
};

function makeSprite(p) {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grd = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grd.addColorStop(0, `rgba(${p.core},1)`);
  grd.addColorStop(0.18, `rgba(${p.core},0.85)`);
  grd.addColorStop(0.45, `rgba(${p.glow},0.28)`);
  grd.addColorStop(1, `rgba(${p.glow},0)`);
  g.fillStyle = grd;
  g.fillRect(0, 0, 64, 64);
  return c;
}

export default function ParticleCanvas({ type = "ember", desktop = 46, mobile = 18, className = "" }) {
  const ref = useRef(null);
  const mobileView = useIsMobile();
  const reduced = useReducedMotion();

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || reduced) return;
    const ctx = canvas.getContext("2d");
    const sprite = makeSprite(PALETTES[type] || PALETTES.ember);
    const rising = type !== "frost";
    const count = mobileView ? mobile : desktop;
    const dpr = Math.min(window.devicePixelRatio || 1, mobileView ? 1 : 1.75);

    let w = 0, h = 0, raf = 0, visible = true, last = 0;
    const parts = [];

    const resize = () => {
      const r = canvas.getBoundingClientRect();
      w = Math.max(1, r.width);
      h = Math.max(1, r.height);
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const spawn = (initial) => ({
      x: Math.random() * w,
      y: initial ? Math.random() * h : rising ? h + 10 : -10,
      r: (type === "frost" ? 1.6 : 2.2) + Math.random() * (type === "frost" ? 3 : 4.5),
      vy: (rising ? -1 : 1) * (type === "frost" ? 7 + Math.random() * 9 : 14 + Math.random() * 22),
      vx: (Math.random() - 0.5) * 8,
      ph: Math.random() * Math.PI * 2,
      sw: 0.4 + Math.random() * 0.9,
      a: 0.35 + Math.random() * 0.65,
    });

    const frame = (now) => {
      raf = requestAnimationFrame(frame);
      if (!visible || document.hidden) { last = now; return; }
      const dt = Math.min(0.05, (now - last) / 1000 || 0.016);
      last = now;
      ctx.clearRect(0, 0, w, h);
      for (let i = 0; i < parts.length; i++) {
        const p = parts[i];
        p.ph += dt * p.sw;
        p.x += (p.vx + Math.sin(p.ph) * 10) * dt;
        p.y += p.vy * dt;
        const edge = rising ? p.y / h : 1 - p.y / h; // 1 at start edge, 0 at far edge
        const fade = Math.max(0, Math.min(1, rising ? p.y / (h * 0.85) : (h - p.y) / (h * 0.85)));
        const twinkle = type === "ember" ? 0.7 + 0.3 * Math.sin(p.ph * 4) : 1;
        ctx.globalAlpha = p.a * fade * twinkle * (edge < 0 ? 0 : 1);
        const s = p.r * 6;
        ctx.drawImage(sprite, p.x - s / 2, p.y - s / 2, s, s);
        if (p.y < -20 || p.y > h + 20 || p.x < -20 || p.x > w + 20) parts[i] = spawn(false);
      }
      ctx.globalAlpha = 1;
    };

    resize();
    for (let i = 0; i < count; i++) parts.push(spawn(true));

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; });
    io.observe(canvas);
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
    };
  }, [type, desktop, mobile, mobileView, reduced]);

  return <canvas ref={ref} className={`hw-particles ${className}`} aria-hidden="true" />;
}
