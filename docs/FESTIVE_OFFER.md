# Dussehra festive offer: owner notes

Tiered discount on the **signature perfumes only** (THÉ NOIR, SOIE FEMME, VEIL): buy 1 → 10%, buy 2 → 15%, buy 3+ → 25%, any mix.
The Halloween Edition keeps its own ₹799 launch offer and never counts toward, or receives, these tiers.

**Where it lives (keep both in sync; `npm test` in /backend fails if they drift):**
- `backend/config/festiveOffer.js`: what is actually CHARGED (applied in `/create-order` from database prices).
- `frontend/src/config/festive.js`: what the site SHOWS.

**Dates:** default window is Tue 20 Oct 2026 00:00 → 21 Oct 00:00 IST (Dussehra). Change `startsAt` / `endsAt` in BOTH files.
Before the start the home page shows a teaser with a countdown; after the end everything disappears and prices return to normal on their own (no redeploy needed).

**Coupon / ambassador codes (decision to confirm):** `couponPolicy: "best-of"`: the customer gets the larger of the festive offer or their code, never both.
If the festive offer wins, the code is not applied and no partner commission is attributed. Equal-percentage codes keep their attribution. Set `"stack"` (both files) to apply both.

**Navigation:** signature scents now come first on the home page; the nav says "Signature Scents"; the Halloween hero has a second "Signature Scents" button.
Footer/navbar links to home sections now scroll to the exact section from any page.
