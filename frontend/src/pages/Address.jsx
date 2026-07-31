import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import PageLoader from "../components/PageLoader";

export default function Address() {
  const navigate = useNavigate();

  const [addresses, setAddresses] = useState([]);
  const [selected, setSelected] = useState(null);
  const [manual, setManual] = useState(false);
  const [loading, setLoading] = useState(true);
  const [navigating, setNavigating] = useState(false);
  const [errors, setErrors] = useState({});

  const [form, setForm] = useState({
    name: "",
    phone: "",
    email: "",
    address: "",
    city: "",
    state: "",
    pincode: "",
  });

  /* ======================================
     LOAD SAVED ADDRESSES
  ====================================== */

  useEffect(() => {
    const token = localStorage.getItem("kaeorn_token");

    // Guest checkout / no login
    if (!token) {
      setManual(true);
      setLoading(false);
      return;
    }

    let cancelled = false;

    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();

      if (!cancelled) {
        setManual(true);
        setLoading(false);
      }
    }, 5000);

    async function loadAddresses() {
      try {
        const response = await fetch(
          `${import.meta.env.VITE_API_BASE}/api/addresses`,
          {
            method: "GET",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${token}`,
            },
            signal: controller.signal,
          }
        );

        clearTimeout(timeout);

        let data = null;

        try {
          data = await response.json();
        } catch {
          data = null;
        }

        /* ======================================
           TOKEN IS INVALID / EXPIRED
        ====================================== */

        if (response.status === 401) {
          console.error(
            "Authentication failed while loading addresses:",
            data
          );

          /*
            Remove only the invalid token.

            The user can still continue checkout
            manually instead of being permanently
            blocked.
          */

          localStorage.removeItem("kaeorn_token");

          if (!cancelled) {
            setAddresses([]);
            setSelected(null);
            setManual(true);
          }

          return;
        }

        /* ======================================
           OTHER SERVER ERRORS
        ====================================== */

        if (!response.ok) {
          throw new Error(
            data?.message ||
              "Unable to load saved addresses"
          );
        }

        /* ======================================
           SUCCESS
        ====================================== */

        const addressList = Array.isArray(data)
          ? data
          : Array.isArray(data?.addresses)
          ? data.addresses
          : [];

        if (cancelled) return;

        setAddresses(addressList);

        const defaultAddress = addressList.find(
          (address) => address.isDefault
        );

        if (defaultAddress) {
          setSelected(defaultAddress);
        }

        if (addressList.length === 0) {
          setManual(true);
        }
      } catch (error) {
        clearTimeout(timeout);

        if (error.name === "AbortError") {
          return;
        }

        console.error(
          "Failed to load saved addresses:",
          error
        );

        if (!cancelled) {
          setAddresses([]);
          setSelected(null);
          setManual(true);
        }
      } finally {
        clearTimeout(timeout);

        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadAddresses();

    return () => {
      cancelled = true;
      clearTimeout(timeout);
      controller.abort();
    };
  }, []);

  /* ======================================
     FORM CHANGE
  ====================================== */

  function handleChange(e) {
    const { name, value } = e.target;

    setForm((previous) => ({
      ...previous,
      [name]: value,
    }));

    if (errors[name]) {
      setErrors((previous) => ({
        ...previous,
        [name]: null,
      }));
    }
  }

  /* ======================================
     CONTINUE WITH SAVED ADDRESS
  ====================================== */

  function continueWithSaved() {
    if (!selected) {
      alert("Please select an address.");
      return;
    }

    setNavigating(true);

    const deliveryAddress = {
      name: selected.fullName || "",
      phone: selected.phone || "",
      email: selected.email || "",
      address: selected.street || "",
      city: selected.city || "",
      state: selected.state || "",
      pincode: selected.postalCode || "",
    };

    localStorage.setItem(
      "deliveryAddress",
      JSON.stringify(deliveryAddress)
    );

    setTimeout(() => {
      navigate("/checkout/payment");
    }, 300);
  }

  /* ======================================
     VALIDATE MANUAL ADDRESS
  ====================================== */

  function validate() {
    const nextErrors = {};

    if (!form.name.trim()) {
      nextErrors.name = "Required";
    }

    if (!/^\d{10}$/.test(form.phone.trim())) {
      nextErrors.phone =
        "Enter a valid 10-digit number";
    }

    if (!/^\S+@\S+\.\S+$/.test(form.email.trim())) {
      nextErrors.email =
        "Enter a valid email";
    }

    if (!form.address.trim()) {
      nextErrors.address = "Required";
    }

    if (!form.city.trim()) {
      nextErrors.city = "Required";
    }

    if (!form.state.trim()) {
      nextErrors.state = "Required";
    }

    if (!/^\d{6}$/.test(form.pincode.trim())) {
      nextErrors.pincode =
        "Enter a valid 6-digit pincode";
    }

    setErrors(nextErrors);

    return Object.keys(nextErrors).length === 0;
  }

  /* ======================================
     CONTINUE WITH MANUAL ADDRESS
  ====================================== */

  function continueManual(e) {
    e.preventDefault();

    if (!validate()) {
      return;
    }

    setNavigating(true);

    localStorage.setItem(
      "deliveryAddress",
      JSON.stringify({
        name: form.name.trim(),
        phone: form.phone.trim(),
        email: form.email.trim().toLowerCase(),
        address: form.address.trim(),
        city: form.city.trim(),
        state: form.state.trim(),
        pincode: form.pincode.trim(),
      })
    );

    setTimeout(() => {
      navigate("/checkout/payment");
    }, 300);
  }

  /* ======================================
     PAGE LOADER
  ====================================== */

  if (navigating) {
    return <PageLoader />;
  }

  return (
    <div style={styles.page}>
      <Steps current={1} />

      {loading ? (
        <div style={styles.card}>
          <div style={styles.skeletonHeading} />
          <div style={styles.skeletonLine} />
          <div style={styles.skeletonLine} />
          <div
            style={{
              ...styles.skeletonLine,
              width: "55%",
            }}
          />
        </div>
      ) : (
        <>
          <h1 style={styles.heading}>
            Delivery Address
          </h1>

          <p style={styles.subtext}>
            Tell us where to deliver your order.
            We'll only use these details for
            shipping and order updates.
          </p>

          <div style={styles.trust}>
            <span style={styles.trustPill}>
              🔒 &nbsp;Secure Checkout
            </span>

            <span style={styles.trustPill}>
              📦 &nbsp;Discreet Packaging
            </span>

            <span style={styles.trustPill}>
              ↩ &nbsp;Easy Returns
            </span>
          </div>

          {/* SAVED ADDRESSES */}

          {!manual && addresses.length > 0 && (
            <>
              <h3 style={styles.section}>
                Saved Addresses
              </h3>

              <div style={styles.addressList}>
                {addresses.map((address, index) => {
                  const isSelected =
                    selected === address;

                  return (
                    <div
                      key={
                        address._id ||
                        address.id ||
                        index
                      }
                      onClick={() =>
                        setSelected(address)
                      }
                      style={{
                        ...styles.addressCard,
                        ...(isSelected
                          ? styles.addressCardSelected
                          : {}),
                      }}
                    >
                      <div style={styles.addressRadio}>
                        <span
                          style={{
                            ...styles.addressRadioDot,
                            opacity: isSelected
                              ? 1
                              : 0,
                          }}
                        />
                      </div>

                      <div style={styles.addressBody}>
                        <p style={styles.addressName}>
                          {address.fullName}
                        </p>

                        <p style={styles.addressLine}>
                          {address.street}
                        </p>

                        <p style={styles.addressLine}>
                          {address.city},{" "}
                          {address.state} &ndash;{" "}
                          {address.postalCode}
                        </p>

                        <p style={styles.addressPhone}>
                          {address.phone}
                        </p>
                      </div>

                      {address.isDefault && (
                        <span style={styles.defaultTag}>
                          Default
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>

              <button
                style={styles.button}
                onClick={continueWithSaved}
              >
                Continue to Payment
              </button>

              <p
                style={styles.link}
                onClick={() => setManual(true)}
              >
                + Use a different address
              </p>
            </>
          )}

          {/* MANUAL FORM */}

          {manual && (
            <form
              style={styles.formCard}
              onSubmit={continueManual}
              noValidate
            >
              <Field
                label="Full Name"
                name="name"
                value={form.name}
                onChange={handleChange}
                error={errors.name}
              />

              <div style={styles.row}>
                <Field
                  label="Phone Number"
                  name="phone"
                  value={form.phone}
                  onChange={handleChange}
                  error={errors.phone}
                />

                <Field
                  label="Email Address"
                  name="email"
                  type="email"
                  value={form.email}
                  onChange={handleChange}
                  error={errors.email}
                />
              </div>

              <Field
                label="House / Flat / Street Address"
                name="address"
                as="textarea"
                value={form.address}
                onChange={handleChange}
                error={errors.address}
              />

              <div style={styles.row}>
                <Field
                  label="City"
                  name="city"
                  value={form.city}
                  onChange={handleChange}
                  error={errors.city}
                />

                <Field
                  label="State"
                  name="state"
                  value={form.state}
                  onChange={handleChange}
                  error={errors.state}
                />

                <Field
                  label="Pincode"
                  name="pincode"
                  value={form.pincode}
                  onChange={handleChange}
                  error={errors.pincode}
                />
              </div>

              <p style={styles.helperText}>
                We'll use this address only for
                order delivery and updates.
              </p>

              <button
                type="submit"
                style={styles.button}
              >
                Continue to Payment
              </button>

              {addresses.length > 0 && (
                <p
                  style={styles.link}
                  onClick={() =>
                    setManual(false)
                  }
                >
                  ← Back to saved addresses
                </p>
              )}
            </form>
          )}
        </>
      )}
    </div>
  );
}

/* ======================================
   CHECKOUT STEPS
====================================== */

function Steps({ current }) {
  const items = ["Address", "Payment"];

  return (
    <div style={styles.steps}>
      {items.map((label, index) => {
        const step = index + 1;

        const active = step === current;
        const done = step < current;

        return (
          <div
            key={label}
            style={styles.stepItem}
          >
            <div
              style={{
                ...styles.stepDot,
                ...(active
                  ? styles.stepDotActive
                  : {}),
                ...(done
                  ? styles.stepDotDone
                  : {}),
              }}
            >
              {done ? "✓" : step}
            </div>

            <span
              style={{
                ...styles.stepLabel,
                ...(active
                  ? styles.stepLabelActive
                  : {}),
              }}
            >
              {label}
            </span>

            {step !== items.length && (
              <span style={styles.stepRule} />
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ======================================
   FORM FIELD
====================================== */

function Field({
  label,
  name,
  value,
  onChange,
  error,
  type = "text",
  as,
}) {
  const Tag =
    as === "textarea"
      ? "textarea"
      : "input";

  return (
    <label style={styles.field}>
      <span style={styles.fieldLabel}>
        {label}
      </span>

      <Tag
        name={name}
        type={
          as === "textarea"
            ? undefined
            : type
        }
        value={value}
        onChange={onChange}
        rows={
          as === "textarea"
            ? 3
            : undefined
        }
        style={{
          ...(as === "textarea"
            ? styles.textarea
            : styles.input),
          ...(error
            ? styles.inputError
            : {}),
        }}
      />

      {error && (
        <span style={styles.errorText}>
          {error}
        </span>
      )}
    </label>
  );
}

/* ======================================
   STYLES
====================================== */

const GOLD = "#B08D57";
const INK = "#141210";
const PARCHMENT = "#FAF7F1";
const HAIRLINE = "#E7E1D6";
const MUTED = "#8A8177";

const styles = {
  page: {
    maxWidth: "560px",
    margin: "0 auto",
    padding: "48px 20px 80px",
    fontFamily: "'DM Sans', sans-serif",
    color: INK,
  },

  steps: {
    display: "flex",
    alignItems: "center",
    marginBottom: "40px",
  },

  stepItem: {
    display: "flex",
    alignItems: "center",
  },

  stepDot: {
    width: 26,
    height: 26,
    borderRadius: "50%",
    border: `1px solid ${HAIRLINE}`,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 12,
    color: MUTED,
    background: "#fff",
    marginRight: 8,
  },

  stepDotActive: {
    borderColor: INK,
    color: INK,
    fontWeight: 600,
  },

  stepDotDone: {
    background: GOLD,
    borderColor: GOLD,
    color: "#fff",
  },

  stepLabel: {
    fontSize: 13,
    color: MUTED,
    marginRight: 16,
  },

  stepLabelActive: {
    color: INK,
    fontWeight: 600,
  },

  stepRule: {
    width: 32,
    height: 1,
    background: HAIRLINE,
    marginRight: 16,
  },

  heading: {
    fontFamily: "'Playfair Display', serif",
    fontSize: "32px",
    fontWeight: 500,
    marginBottom: "10px",
    letterSpacing: "0.2px",
  },

  subtext: {
    fontSize: "14px",
    color: MUTED,
    marginBottom: "28px",
    lineHeight: 1.7,
  },

  trust: {
    display: "flex",
    flexWrap: "wrap",
    gap: "10px",
    marginBottom: "36px",
  },

  trustPill: {
    fontSize: "12px",
    color: INK,
    border: `1px solid ${HAIRLINE}`,
    borderRadius: "999px",
    padding: "8px 14px",
    background: "#fff",
  },

  section: {
    fontFamily: "'Playfair Display', serif",
    fontSize: "16px",
    fontWeight: 500,
    marginBottom: "14px",
  },

  addressList: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
    marginBottom: "20px",
  },

  addressCard: {
    display: "flex",
    gap: "14px",
    alignItems: "flex-start",
    position: "relative",
    border: `1px solid ${HAIRLINE}`,
    borderRadius: "14px",
    padding: "18px 20px",
    cursor: "pointer",
    background: "#fff",
    transition:
      "border-color 0.15s ease, box-shadow 0.15s ease",
  },

  addressCardSelected: {
    borderColor: INK,
    boxShadow: `0 0 0 1px ${INK}`,
  },

  addressRadio: {
    width: 18,
    height: 18,
    borderRadius: "50%",
    border: `1px solid ${GOLD}`,
    marginTop: 3,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },

  addressRadioDot: {
    width: 9,
    height: 9,
    borderRadius: "50%",
    background: GOLD,
    transition: "opacity 0.15s ease",
  },

  addressBody: {
    flex: 1,
  },

  addressName: {
    fontWeight: 600,
    marginBottom: 4,
    fontSize: 14,
  },

  addressLine: {
    fontSize: 13,
    color: MUTED,
    lineHeight: 1.6,
    margin: 0,
  },

  addressPhone: {
    fontSize: 13,
    color: MUTED,
    marginTop: 4,
  },

  defaultTag: {
    fontSize: 10,
    letterSpacing: "0.06em",
    textTransform: "uppercase",
    color: GOLD,
    border: `1px solid ${GOLD}`,
    borderRadius: "999px",
    padding: "3px 8px",
    height: "fit-content",
  },

  formCard: {
    display: "flex",
    flexDirection: "column",
    gap: "18px",
    border: `1px solid ${HAIRLINE}`,
    borderRadius: "16px",
    padding: "28px 24px",
    background: "#fff",
  },

  row: {
    display: "flex",
    gap: "14px",
    flexWrap: "wrap",
  },

  field: {
    display: "flex",
    flexDirection: "column",
    gap: "6px",
    flex: 1,
    minWidth: "140px",
  },

  fieldLabel: {
    fontSize: "11px",
    letterSpacing: "0.05em",
    textTransform: "uppercase",
    color: MUTED,
  },

  input: {
    padding: "13px 14px",
    borderRadius: "10px",
    border: `1px solid ${HAIRLINE}`,
    fontSize: "14px",
    fontFamily: "'DM Sans', sans-serif",
    outline: "none",
    background: PARCHMENT,
  },

  textarea: {
    padding: "13px 14px",
    borderRadius: "10px",
    border: `1px solid ${HAIRLINE}`,
    fontSize: "14px",
    fontFamily: "'DM Sans', sans-serif",
    resize: "none",
    outline: "none",
    background: PARCHMENT,
  },

  inputError: {
    borderColor: "#B5453E",
  },

  errorText: {
    fontSize: "11px",
    color: "#B5453E",
  },

  helperText: {
    fontSize: "12px",
    color: MUTED,
    marginTop: "-6px",
  },

  button: {
    marginTop: "8px",
    padding: "17px",
    borderRadius: "40px",
    border: "none",
    background: INK,
    color: "#fff",
    fontSize: "14.5px",
    letterSpacing: "0.02em",
    cursor: "pointer",
  },

  link: {
    marginTop: "8px",
    fontSize: "13px",
    color: INK,
    cursor: "pointer",
    textDecoration: "underline",
    textAlign: "center",
  },

  card: {
    border: `1px solid ${HAIRLINE}`,
    borderRadius: "16px",
    padding: "24px",
  },

  skeletonHeading: {
    height: 32,
    width: "50%",
    background: "#F0EBE0",
    borderRadius: 8,
    marginBottom: 16,
  },

  skeletonLine: {
    height: 16,
    width: "80%",
    background: "#F0EBE0",
    borderRadius: 6,
    marginBottom: 12,
  },
};