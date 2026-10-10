import { useSyncExternalStore } from "react";
import { setMuted } from "./audioEngine";
import { useMuted } from "./hooks";

const noopSubscribe = () => () => {};

/* Floating mute toggle, bottom-left. Choice persists in localStorage (see audioEngine). */
export default function SoundToggle() {
  const muted = useMuted();
  // false on the server / first render, true on the client — so nothing is rendered into the prerendered HTML
  const mounted = useSyncExternalStore(noopSubscribe, () => true, () => false);
  if (!mounted) return null;

  return (
    <button
      type="button"
      className="hw-sound"
      aria-label={muted ? "Turn sound on" : "Turn sound off"}
      aria-pressed={!muted}
      title={muted ? "Sound off" : "Sound on"}
      onClick={() => setMuted(!muted)}
    >
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M4 9.5v5h3.5L12 18.5v-13L7.5 9.5H4z" />
        {muted ? (
          <>
            <path d="M16 9.5l5 5" />
            <path d="M21 9.5l-5 5" />
          </>
        ) : (
          <>
            <path d="M15.5 9a4 4 0 010 6" />
            <path d="M18 6.5a8 8 0 010 11" />
          </>
        )}
      </svg>
    </button>
  );
}
