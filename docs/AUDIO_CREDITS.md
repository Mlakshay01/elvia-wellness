# Halloween Edition — Audio files and credits

All files live in `frontend/public/audio/` and are referenced from `HALLOWEEN_AUDIO` in `frontend/src/config/halloween.js`. Every file is under 300 KB.

| File | Used for | Size | Length | Source and licence |
|------|----------|------|--------|--------------------|
| `halloween-ambient.mp3` | Quiet looping bed on the home page | ~151 KB | 22 s loop | Synthesised in-house by `frontend/scripts/generate-halloween-assets.py`. **No third-party material. No licence or attribution needed.** |
| `ambient-nocturne.mp3` | Bed on the NOCTURNE page (low drone and slow heartbeat) | ~110 KB | 16 s loop | Same: synthesised in-house |
| `ambient-azur.mp3` | Bed on the AZUR page (cold air and glassy shimmer) | ~137 KB | 20 s loop | Same: synthesised in-house |
| `halloween-thunder.mp3` | One thunder roll on first interaction during the intro | ~59 KB | 6 s | Same: synthesised in-house |
| `halloween-bell.mp3` | Soft bell on add-to-cart | ~23 KB | 2.8 s | Same: synthesised in-house |

## Why synthesised, and an honest note

The build environment had no access to Pixabay/Freesound (no download possible), so instead of leaving empty placeholders the files were **generated from scratch** with code. That means they are free of any licence risk, but they are **simpler than real recordings**, particularly the thunder. They were checked for levels, clipping and seamless loop points, but not auditioned by ear, so **please listen to them once** (on phone speakers too) before launch.

## Replacing them with recorded audio (optional, recommended for the thunder)

Use only **CC0** or **Pixabay Content Licence** files. Pixabay search ideas: "distant thunder", "dark ambient drone", "wind night ambience", "small bell chime".

1. Trim to the lengths above, export **MP3, 44.1 kHz, 56–80 kbps**, under 300 KB. For the loops, pick or edit a clip that loops without a click.
2. Save it with the **same filename** over the old one (or change the path in `HALLOWEEN_AUDIO`).
3. **Add a row to the table above** with the file, the author, the source URL and the licence (Pixabay asks you to keep the link).

## How playback works (so you are not surprised)

- Browsers block autoplay, so nothing plays until the visitor's **first click, tap or key press**. Scrolling alone cannot start audio in Chrome or Safari (it does not count as a user gesture); the engine listens for scroll as well, but it only works if the visitor has already interacted.
- The ambient bed plays at **20% volume** with a ~2.6 s fade-in and cross-fades between pages. Thunder plays only if that first interaction happens while the intro is still on screen.
- The bottom-left toggle mutes everything and is remembered in the visitor's browser (`localStorage` key `hw_muted`). If muted, no audio file is even downloaded.
- All sound stops automatically when the Halloween theme ends.
