import "../../styles/Policy/Policy.css";

export default function PolicyLayout({ title, children }) {
  return (
    <div className="policy-container">
      <div className="policy-content">
        <h1>{title}</h1>
        <div className="policy-body">
          {children}
        </div>
      </div>
    </div>
  );
}