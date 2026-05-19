import { Helmet } from "react-helmet-async";
import PolicyLayout from "../legal/PolicyLayout"; // adjust path as needed

export default function Contact() {
  return (
    <>
      <Helmet>
        <title>Contact KAEORN | Get in Touch</title>
        <meta
          name="description"
          content="Reach out to Kaeorn for order support, fragrance questions, or collaboration inquiries. We respond within 24–48 business hours."
        />
        <link rel="canonical" href="https://kaeorn.com/contact" />
      </Helmet>

      <PolicyLayout eyebrow="REACH US" title="Contact">
        <p>
          Whether it's a question about your order, a fragrance you'd like to
          know more about, or something else entirely — we're here. Reach us
          over email or use the support chat in your profile for a faster
          response. We'll get back to you within 24–48 business hours.
        </p>

        <div className="policy-info-block">
          <p>
            <span className="policy-label">Brand</span>
            KAEORN
          </p>
          <p>
            <span className="policy-label">Email</span>
            <a href="mailto:kaeornwellness@gmail.com">kaeornwellness@gmail.com</a>
          </p>
          <p>
            <span className="policy-label">Region</span>
            India
          </p>
        </div>
      </PolicyLayout>
    </>
  );
}