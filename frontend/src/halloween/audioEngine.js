/* =========================================================================
   HALLOWEEN AUDIO ENGINE  (client only — every entry point is guarded)
   -------------------------------------------------------------------------
   • Browsers block autoplay, so we ARM listeners and start on the first
     user interaction. No prompt, no banner.
   • Uses Web Audio (GainNode) rather than <audio>.volume, because iOS Safari
     ignores .volume — this is the only way the 20 % level + fades work on
     iPhones.
   • NOTE: scroll / wheel are not "user activation" events in Chrome/Safari
     (only click, tap, key press are). We listen to them as the brief asks,
     but audio can only truly start once an activating event has happened;
     we simply retry on every event until the browser lets us through.
   • The AudioContext is not created until a real gesture, so there are no
     autoplay warnings in the console.
   • Mute choice persists in localStorage ("hw_muted"). Muted = nothing is
     fetched, decoded or played.
========================================================================= */
import { HALLOWEEN, HALLOWEEN_AUDIO, isHalloweenActive } from "../config/halloween";

const MUTE_KEY = "hw_muted";
const THUNDER_VOL = 0.5;
const BELL_VOL = 0.28;
const BED_FADE_IN = 2.6; // seconds
const BED_FADE_OUT = 1.4;

const isBrowser = typeof window !== "undefined";

const s = {
  ctx: null,
  master: null,
  armed: false,
  unlocked: false,
  introActive: false,
  muted: false,
  rawThunder: null, // ArrayBuffer prefetched before unlock
  buffers: new Map(), // url -> AudioBuffer
  loading: new Map(), // url -> Promise
  bed: null, // { url, src, gain }
  wantedBed: null, // url the UI currently wants
  subs: new Set(),
};

if (isBrowser) {
  try {
    s.muted = localStorage.getItem(MUTE_KEY) === "1";
  } catch {
    /* private mode — default to sound allowed */
  }
}

/* ── subscription (for the toggle UI) ─────────────────────────────────── */
const emit = () => s.subs.forEach((fn) => fn());
export function subscribeAudio(fn) {
  s.subs.add(fn);
  return () => s.subs.delete(fn);
}
export const isMuted = () => s.muted;

/* ── helpers ──────────────────────────────────────────────────────────── */
function fetchBytes(url) {
  return fetch(url).then((r) => {
    if (!r.ok) throw new Error(`audio ${url}: ${r.status}`);
    return r.arrayBuffer();
  });
}

function decode(bytes) {
  return new Promise((resolve, reject) => {
    // callback form for old Safari
    s.ctx.decodeAudioData(bytes, resolve, reject);
  });
}

function loadBuffer(url) {
  if (s.buffers.has(url)) return Promise.resolve(s.buffers.get(url));
  if (s.loading.has(url)) return s.loading.get(url);
  const p = (url === HALLOWEEN_AUDIO.thunder && s.rawThunder
    ? Promise.resolve(s.rawThunder)
    : fetchBytes(url)
  )
    .then((bytes) => decode(bytes.slice ? bytes.slice(0) : bytes))
    .then((buf) => {
      s.buffers.set(url, buf);
      s.loading.delete(url);
      return buf;
    })
    .catch(() => {
      // Missing/undecodable file: stay silent, never throw into the UI.
      s.loading.delete(url);
      return null;
    });
  s.loading.set(url, p);
  return p;
}

const canPlay = () => isBrowser && isHalloweenActive() && s.unlocked && !s.muted && s.ctx;

/* ── one-shots ────────────────────────────────────────────────────────── */
async function playOnce(url, volume) {
  if (!canPlay()) return;
  const buf = await loadBuffer(url);
  if (!buf || !canPlay()) return;
  const src = s.ctx.createBufferSource();
  const g = s.ctx.createGain();
  g.gain.value = volume;
  src.buffer = buf;
  src.connect(g).connect(s.master);
  src.start();
}

export const playThunder = () => playOnce(HALLOWEEN_AUDIO.thunder, THUNDER_VOL);
export const playBell = () => playOnce(HALLOWEEN_AUDIO.bell, BELL_VOL);

/* ── looping ambient bed (cross-fades between pages) ──────────────────── */
async function startBed(url) {
  if (!url || !canPlay()) return;
  if (s.bed && s.bed.url === url) return;
  const buf = await loadBuffer(url);
  // the wanted bed may have changed while we were loading
  if (!buf || !canPlay() || s.wantedBed !== url) return;

  const t = s.ctx.currentTime;
  const old = s.bed;
  if (old) {
    old.gain.gain.cancelScheduledValues(t);
    old.gain.gain.setValueAtTime(old.gain.gain.value, t);
    old.gain.gain.linearRampToValueAtTime(0, t + BED_FADE_OUT);
    try {
      old.src.stop(t + BED_FADE_OUT + 0.05);
    } catch {
      /* already stopped */
    }
  }

  const src = s.ctx.createBufferSource();
  const gain = s.ctx.createGain();
  src.buffer = buf;
  src.loop = true;
  gain.gain.setValueAtTime(0, t);
  gain.gain.linearRampToValueAtTime(HALLOWEEN.ambientVolume, t + BED_FADE_IN);
  src.connect(gain).connect(s.master);
  src.start();
  s.bed = { url, src, gain };
}

function stopBed() {
  const b = s.bed;
  if (!b || !s.ctx) return;
  const t = s.ctx.currentTime;
  b.gain.gain.cancelScheduledValues(t);
  b.gain.gain.setValueAtTime(b.gain.gain.value, t);
  b.gain.gain.linearRampToValueAtTime(0, t + 0.5);
  try {
    b.src.stop(t + 0.6);
  } catch {
    /* already stopped */
  }
  s.bed = null;
}

/** Tell the engine which ambient bed the current page wants (url or null). */
export function setBed(url) {
  if (!isBrowser || !isHalloweenActive()) return;
  s.wantedBed = url || null;
  if (!s.wantedBed) return stopBed();
  if (canPlay()) startBed(s.wantedBed);
}

/* ── unlocking ────────────────────────────────────────────────────────── */
const EVENTS = ["pointerdown", "click", "touchend", "keydown", "wheel", "scroll"];

function onGesture(e) {
  if (s.unlocked) return;

  // Don't create a context from events the browser won't count as activation.
  if (e.type === "pointerdown" && e.pointerType === "touch") return;
  if (e.type === "keydown" && (e.key === "Escape" || e.key === "Shift" || e.key === "Control" || e.key === "Alt" || e.key === "Meta")) return;
  if (e.type === "wheel" || e.type === "scroll") {
    const ua = navigator.userActivation;
    if (ua && !ua.hasBeenActive) return;
  }
  if (s.muted) return; // muted: do nothing at all (the toggle unlocks when the user un-mutes)

  unlock();
}

async function unlock() {
  const Ctx = window.AudioContext || window.webkitAudioContext;
  if (!Ctx) return disarm();

  try {
    if (!s.ctx) {
      s.ctx = new Ctx();
      s.master = s.ctx.createGain();
      s.master.gain.value = 1;
      s.master.connect(s.ctx.destination);
    }
    if (s.ctx.state !== "running") await s.ctx.resume();
  } catch {
    return; // stay armed, try again on the next gesture
  }
  if (s.ctx.state !== "running") return; // not allowed yet — stay armed

  s.unlocked = true;
  disarm();
  document.addEventListener("visibilitychange", onVisibility);

  if (s.muted || !isHalloweenActive()) return;

  // Thunder only if the intro is still on screen when the visitor first interacts.
  if (s.introActive) {
    playThunder();
    setTimeout(() => s.wantedBed && startBed(s.wantedBed), 900);
  } else if (s.wantedBed) {
    startBed(s.wantedBed);
  }
}

function disarm() {
  if (!s.armed) return;
  EVENTS.forEach((ev) => window.removeEventListener(ev, onGesture, true));
  s.armed = false;
}

function onVisibility() {
  if (!s.ctx) return;
  if (document.hidden) s.ctx.suspend().catch(() => {});
  else if (!s.muted) s.ctx.resume().catch(() => {});
}

/* ── public: arm once at app start ────────────────────────────────────── */
export function armHalloweenAudio() {
  if (!isBrowser || s.armed || s.unlocked || !isHalloweenActive()) return;
  s.armed = true;
  EVENTS.forEach((ev) => window.addEventListener(ev, onGesture, { capture: true, passive: true }));

  // Lazy: prefetch the (small) thunder file when the browser is idle so it can fire instantly.
  if (!s.muted) {
    const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 800));
    idle(() => {
      if (s.muted || s.rawThunder) return;
      fetchBytes(HALLOWEEN_AUDIO.thunder)
        .then((b) => {
          s.rawThunder = b;
        })
        .catch(() => {});
    });
  }
}

export function setIntroActive(v) {
  s.introActive = !!v;
}

/* ── mute toggle ──────────────────────────────────────────────────────── */
export function setMuted(muted) {
  s.muted = !!muted;
  try {
    localStorage.setItem(MUTE_KEY, s.muted ? "1" : "0");
  } catch {
    /* ignore */
  }
  if (s.muted) {
    stopBed();
  } else if (isBrowser) {
    // Un-muting is itself a user gesture: unlock now and start the wanted bed.
    if (s.unlocked) {
      s.ctx?.resume().catch(() => {});
      if (s.wantedBed) startBed(s.wantedBed);
    } else {
      armHalloweenAudio();
      unlock().then(() => s.unlocked && s.wantedBed && startBed(s.wantedBed));
    }
  }
  emit();
}
