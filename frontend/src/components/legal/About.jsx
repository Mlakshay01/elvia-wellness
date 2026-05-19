import { Helmet } from "react-helmet-async";
import PolicyLayout from "../legal/PolicyLayout"; // adjust path as needed

export default function About() {
  return (
    <>
      <Helmet>
        <title>About KAEORN | Luxury Perfume Brand</title>
        <meta
          name="description"
          content="Kaeorn is a luxury perfume brand made in India. Built on the belief that fragrance should feel like a second skin — quiet, intimate, and entirely your own."
        />
        <link rel="canonical" href="https://kaeorn.com/about" />
      </Helmet>

      <PolicyLayout eyebrow="WHO WE ARE" title="About KAEORN">
        <p>
          Kaeorn is a luxury perfume brand built on one belief — that a great
          scent shouldn't announce itself. It should settle into your skin,
          stay close, and become something people notice only when you've
          already left the room.
        </p>

        <p>
          We make Eau de Parfum for people who don't need to be loud about
          their taste. Every fragrance in the Kaeorn collection is composed
          around a feeling — not a trend, not a season. Woody, Gourmand, floral,
          spicy — chosen because they work on real skin, in real life.
        </p>

        <p>
          The name KAEORN brings together two ideas: to endure, and to
          radiate. It's the standard every bottle is held to. Crafted with
          care, made in India, and built to last far beyond the first wear.
        </p>

        <p>
          Because care deserves luxury. That's not just a tagline — it's the
          reason Kaeorn exists.
        </p>
      </PolicyLayout>
    </>
  );
}