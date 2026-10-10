import { discountPercent, offerLabel } from "../config/halloween";
import { useHalloweenActive } from "./hooks";

/* Sale price + struck-through MRP + "% off". Shows only the price when there is no offer
   (mrp missing or not higher than price). Screen readers get real words, not just a strike. */
export default function PriceBlock({ price, mrp, size = "md" }) {
  const pct = discountPercent(mrp, price);
  return (
    <div className={`hw-price hw-price--${size}`}>
      <span className="hw-price-now">
        <span className="hw-sr">{pct ? "Offer price " : "Price "}</span>₹{price}
      </span>
      {pct > 0 && (
        <>
          <del className="hw-price-mrp">
            <span className="hw-sr">Original price </span>₹{mrp}
          </del>
          <span className="hw-price-off">{pct}% off</span>
        </>
      )}
    </div>
  );
}

/* "Limited launch offer · Halloween special" (theme on) / "Limited launch offer" (theme over). */
export function OfferTag({ className = "" }) {
  const themed = useHalloweenActive();
  return <p className={`hw-offer-tag ${className}`}>{offerLabel(themed)}</p>;
}
