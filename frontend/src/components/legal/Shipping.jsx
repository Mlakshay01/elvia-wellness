import { Helmet } from "react-helmet-async";
import PolicyLayout from "../legal/PolicyLayout"; // adjust path as needed

export default function Shipping() {
  return (
    <>
      <Helmet>
        <title>Shipping Policy | KAEORN</title>
        <meta
          name="description"
          content="Kaeorn shipping policy — order processing times, delivery timelines, and tracking details for India-wide delivery."
        />
        <link rel="canonical" href="https://kaeorn.com/shipping" />
      </Helmet>

      <PolicyLayout eyebrow="DELIVERY" title="Shipping Policy">
        <p>
          Orders are processed within 1–3 business days of being placed,
          excluding weekends and public holidays. We take the time to package
          every order with care before it goes out.
        </p>

        <p>
          Delivery typically takes 5–10 business days depending on your
          location and the courier partner handling your shipment. Once your
          order is on its way, you'll receive tracking details via email or SMS.
        </p>

        <p>
          Delays caused by courier partners, weather, or regional restrictions
          are outside our control. If something seems off with your delivery,
          reach out — we'll help figure it out.
        </p>
      </PolicyLayout>
    </>
  );
}