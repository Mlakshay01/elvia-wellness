import { useEffect, useState } from "react";
import "../styles/Global/Utils.css";

export default function Loader() {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const internalNav = sessionStorage.getItem("internalNav");

    if (internalNav) {
      // navigation inside app → skip loader
      sessionStorage.removeItem("internalNav");
      return;
    }

    // first load → show loader
    setShow(true);

    const t = setTimeout(() => {
      setShow(false);
    }, 2200);

    return () => clearTimeout(t);
  }, []); // ❗ ONLY ONCE

  if (!show) return null;

  return (
    <div id="loader">
      <div className="loader-word">KAEORN</div>
      <div className="loader-line-wrap">
        <div className="loader-line-fill"></div>
      </div>
      <div className="loader-sub">Because care deserves luxury</div>
    </div>
  );
}