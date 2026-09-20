import { Link } from "react-router-dom";

/**
 * A real <a href> that Googlebot can follow, with normal SPA navigation for users.
 *
 * The storefront's product cards are clickable <div>s (onClick → navigate). Google does NOT
 * follow onClick handlers, so those pages were only discoverable through the sitemap.
 * Dropping <CrawlLink> inside a card gives crawlers a real link without changing the design:
 * it inherits colour/typography and stops the click from bubbling to the card's own onClick
 * (which would navigate a second time).
 */
export default function CrawlLink({ to, children, style, ...rest }) {
  return (
    <Link
      to={to}
      onClick={(e) => e.stopPropagation()}
      style={{ color: "inherit", textDecoration: "none", ...style }}
      {...rest}
    >
      {children}
    </Link>
  );
}
