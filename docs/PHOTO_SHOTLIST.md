# Halloween Edition — Photo Shot List

Right now the site uses **generated SVG placeholder bottles** (`frontend/public/halloween/*.svg`) so everything works end to end. This is how to replace them with real photos. You only need a phone, a window and a plain background.

## Setup (10 minutes)

- **Background:** a plain, matte, light-grey or white sheet/wall/board. No patterns, no creases. (Plain = easy cut-out.)
- **Light:** a big window, **side-on**, daytime, no direct sun. Turn all room lights off (mixed light turns glass yellow). A white card/foam board opposite the window bounces soft fill into the shadow side.
- **Phone:** wipe the lens. Lock focus and exposure on the bottle (tap and hold). Use the 2x lens if you have it (flatters bottles, avoids distortion), 12 MP or higher, HDR off if the glass looks flat.
- **Stability:** prop the phone on a stack of books or a cheap tripod. Camera at the **middle of the bottle**, not looking down on it.
- **Clean the glass** (microfibre cloth) and check for fingerprints on every frame.

## The shots (do both NOCTURNE and AZUR)

| # | Shot | What to do | Needs transparent PNG? | Config key |
|---|------|-----------|------------------------|------------|
| 1 | **Front hero** | Bottle straight-on, centred, whole bottle visible with a little space around it, label facing camera. | **Yes** | `images.front` |
| 2 | **Three-quarter angle** | Rotate the bottle ~30–40° so you see the front and a side. Same framing and light as #1. | **Yes** | `images.threeQuarter` |
| 3 | **Close-up: cap and label** | Fill the frame with the cap, neck and label. Light skimming across the glass for edge highlights. Portrait 4:5. | No | `images.detail` |
| 4 | **Lifestyle** | **NOCTURNE:** on a dark surface with a dark red rose (or petals) and a thread of incense smoke behind it. **AZUR:** on frosted glass / a cold-looking surface with a few ice cubes or a bowl of ice. Keep it dark and moody, underexpose slightly. Portrait 4:5. | No | `images.lifestyle` |
| 5 | **Flat-lay** | Shoot straight down: bottle lying on its side on the plain background, cap beside it, maybe the box. Landscape 5:4. | No | `images.flatlay` |

Tips: take 5–10 frames of each shot and keep the sharpest. Don't use the phone's beauty/"portrait" mode (it blurs edges wrongly). Don't add filters before the cut-out.

## Turning photos into website images

1. **Cut out #1 and #2 to transparent PNG.** Use remove.bg, Photoshop "Remove Background", Canva "BG Remover", or Cloudinary's background-removal add-on. Zoom in and check the glass edges and the cap for leftover halo.
2. **Export size/shape:** portrait **4:7** (for example **1200 × 2100 px**), bottle centred with about 8% empty margin on every side. The pages reserve a 400×700 box (4:7) so there is no layout jump when the image loads. If your ratio differs, tell the developer so the boxes can be adjusted.
3. **Lifestyle / close-up:** export as JPG or WebP, ~1600 px on the long side (detail and lifestyle are 4:5 portrait; the flat-lay is 5:4). Aim for under 300 KB each (use Cloudinary's automatic quality).
4. **Upload to Cloudinary** (same account as the other product images).
5. **Replace the URLs** in `frontend/src/config/halloween.js`, in `HALLOWEEN_PRODUCTS.<product>.images`. Use Cloudinary's delivery URL, ideally with `f_auto,q_auto` in it (for example `.../image/upload/f_auto,q_auto/...`).
6. **Also update** `images: [...]` in `backend/seedHalloweenPerfumes.js` and re-run the seed so orders store the real image.
7. Rebuild and deploy.

> **Social previews:** the placeholder SVGs will not show as link previews on WhatsApp, Instagram, Facebook or X (they don't support SVG). Real PNG/JPG URLs fix this automatically because the page's `og:image` and JSON-LD use `images.front`.
