import { Helmet } from "react-helmet-async";
import PolicyLayout from "../legal/PolicyLayout"; // adjust path as needed

export default function Refund() {
  return (
    <>
      <Helmet>
        <title>Refund & Cancellation Policy | KAEORN</title>
        <meta
          name="description"
          content="Kaeorn's refund and cancellation policy — what qualifies, how to report an issue, and how refunds are processed."
        />
        <link rel="canonical" href="https://kaeorn.com/refund" />
      </Helmet>

      <PolicyLayout eyebrow="RETURNS & REFUNDS" title="Refund & Cancellation Policy">
        <p>
          Every Kaeorn order goes through careful quality checks before it
          leaves us. In the rare event that your product arrives damaged,
          defective, or incorrect, we'll make it right.
        </p>

        <p>
          To raise a concern, contact us within 48 hours of receiving your
          order with clear photos and unboxing video along with your order details. Once verified, we'll
          arrange a replacement or process a refund — whichever works best
          for you.
        </p>

        <p>
          Approved refunds are returned to your original payment method within
          7–10 business days. Shipping charges, if any, are non-refundable.
        </p>

        <p>
          Orders that have already been shipped cannot be cancelled. If you
          need to make any changes, please reach out to us as early as
          possible after placing your order.
        </p>
      </PolicyLayout>
    </>
  );
}