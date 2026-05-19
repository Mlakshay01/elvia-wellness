import { Helmet } from "react-helmet-async";
import PolicyLayout from "../legal/PolicyLayout"; // adjust path as needed

export default function Privacy() {
  return (
    <>
      <Helmet>
        <title>Privacy Policy | KAEORN</title>
        <meta
          name="description"
          content="Kaeorn's privacy policy — how we collect, use, and protect your personal information when you shop with us."
        />
        <link rel="canonical" href="https://kaeorn.com/privacy" />
      </Helmet>

      <PolicyLayout eyebrow="YOUR DATA" title="Privacy Policy">
        <p>
          Kaeorn collects only the information needed to process your orders
          and provide you with proper support. We don't collect anything we
          don't use, and we don't use anything without your knowledge.
        </p>

        <p>
          Information we may collect includes your name, email address, phone
          number, shipping address, and order details. This is used solely for
          fulfillment, delivery updates, and customer support.
        </p>

        <p>
          All payments are processed through secure, authorized third-party
          payment gateways. Kaeorn does not store or have access to your card,
          UPI, or banking information at any point.
        </p>

        <p>
          We do not sell, rent, or share your personal information with any
          third party, except where necessary to deliver your order or meet a
          legal obligation.
        </p>
      </PolicyLayout>
    </>
  );
}