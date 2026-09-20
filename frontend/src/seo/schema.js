/**
 * Structured data (schema.org JSON-LD) helpers.
 * Product data is read from data/products.js so price / SKU / image always match the storefront
 * (Google requires structured data to match what's visible on the page).
 */
import { PRODUCTS } from "../data/products";

export const SITE_URL = "https://kaeorn.com";

const ORG_REF = { "@id": `${SITE_URL}/#organization` };

export const ORGANIZATION_JSONLD = {
  "@context": "https://schema.org",
  "@type": "Organization",
  "@id": `${SITE_URL}/#organization`,
  name: "KAEORN",
  alternateName: ["Kaeorn", "Kaeorn Perfumes"],
  url: SITE_URL,
  logo: `${SITE_URL}/apple-touch-icon.png`,
  description:
    "KAEORN is a luxury perfume brand offering premium Eau de Parfum for men, women, and unisex wear. Made in India.",
  foundingLocation: { "@type": "Country", name: "India" },
  sameAs: [
    "https://www.instagram.com/kaeorn.co/",
    "https://www.facebook.com/people/Kaeorn/61590374977606",
    "https://www.youtube.com/@KAEORNWELLNESS",
  ],
};

export const WEBSITE_JSONLD = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  "@id": `${SITE_URL}/#website`,
  name: "KAEORN",
  alternateName: ["Kaeorn", "Kaeorn Perfumes"],
  url: SITE_URL,
  publisher: ORG_REF,
  inLanguage: "en-IN",
};

/** BreadcrumbList — `items` = [{ name, path }] in order, e.g. Home → Product */
export function breadcrumbJsonLd(items) {
  return {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: items.map((it, i) => ({
      "@type": "ListItem",
      position: i + 1,
      name: it.name,
      item: `${SITE_URL}${it.path}`,
    })),
  };
}

/**
 * Product + Offer for a storefront route (must exist in PRODUCTS).
 * aggregateRating/review are added only when real reviews exist (never hardcode them).
 */
export function productJsonLd(route, { description, category, images, availability = "InStock", rating, reviews } = {}) {
  const p = PRODUCTS[route];
  if (!p) return null;
  const url = `${SITE_URL}${route}`;
  return {
    "@context": "https://schema.org",
    "@type": "Product",
    "@id": `${url}#product`,
    name: p.name,
    sku: p.id,
    url,
    description,
    category,
    image: images && images.length ? images : [p.image],
    brand: { "@type": "Brand", name: "KAEORN" },
    offers: {
      "@type": "Offer",
      url,
      priceCurrency: "INR",
      price: String(p.price),
      availability: `https://schema.org/${availability}`,
      itemCondition: "https://schema.org/NewCondition",
      seller: ORG_REF,
    },
    // Only emitted when real, visible customer reviews exist (see components/ProductReviews.jsx)
    ...(rating && rating.count > 0
      ? {
          aggregateRating: {
            "@type": "AggregateRating",
            ratingValue: String(rating.average),
            reviewCount: String(rating.count),
            bestRating: "5",
            worstRating: "1",
          },
          review: (reviews || []).slice(0, 5).map((r) => ({
            "@type": "Review",
            author: { "@type": "Person", name: r.name },
            datePublished: new Date(r.createdAt).toISOString().slice(0, 10),
            name: r.title || undefined,
            reviewBody: r.comment,
            reviewRating: { "@type": "Rating", ratingValue: String(r.rating), bestRating: "5", worstRating: "1" },
          })),
        }
      : {}),
  };
}

/** Article for a journal post (blog) */
export function articleJsonLd({ slug, title, description, image, createdAt, updatedAt }) {
  const url = `${SITE_URL}/blogs/${slug}`;
  return {
    "@context": "https://schema.org",
    "@type": "Article",
    "@id": `${url}#article`,
    mainEntityOfPage: url,
    headline: title,
    description,
    image: image ? [image] : undefined,
    datePublished: createdAt ? new Date(createdAt).toISOString() : undefined,
    dateModified: (updatedAt || createdAt) ? new Date(updatedAt || createdAt).toISOString() : undefined,
    author: ORG_REF,
    publisher: ORG_REF,
  };
}

/** Use inside <Helmet>:  <script type="application/ld+json">{ld(obj)}</script> */
export const ld = (obj) => JSON.stringify(obj);
