import { Helmet } from "react-helmet-async";
import PolicyLayout from "../legal/PolicyLayout"; // adjust path as needed

export default function Terms() {
  return (
    <>
      <Helmet>
        <title>Terms & Conditions | KAEORN</title>
        <meta
          name="description"
          content="Terms and conditions for using the Kaeorn website and purchasing our products."
        />
        <link rel="canonical" href="https://kaeorn.com/terms" />
      </Helmet>

      <PolicyLayout eyebrow="LEGAL" title="Terms & Conditions">
        <p>
          By visiting and using the Kaeorn website, you agree to the terms
          outlined on this page. Please take a moment to read them — they're
          straightforward.
        </p>

        <p>
          Product descriptions, pricing, and availability are subject to change
          without prior notice. We do our best to keep everything accurate and
          up to date.
        </p>

        <p>
          Kaeorn reserves the right to refuse service, cancel orders, or
          limit purchase quantities where necessary — for example, in cases of
          suspected fraud or policy violations.
        </p>

        <p>
          Continued use of this website means you accept these terms as they
          stand. If anything changes significantly, we'll make sure it's
          clearly communicated.
        </p>
      </PolicyLayout>
    </>
  );
}