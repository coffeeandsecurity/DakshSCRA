export default function DeleteButton({ children, className = '', ...props }) {
  return <button type="button" {...props} className={`btn btn-danger btn-xs delete-button ${className}`}>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6M14 10v6" /></svg>
    <span>{children}</span>
  </button>
}
