// Shield + lock brand mark (replaces the plain green square).
export default function ShieldMark({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" style={{ display: "block", flexShrink: 0 }}>
      <path
        d="M32 5 L55 14 V31 C55 45 44 54 32 59 C20 54 9 45 9 31 V14 Z"
        fill="rgba(198,255,58,0.08)" stroke="#c6ff3a" strokeWidth="4" strokeLinejoin="round"
      />
      <path d="M25 30 V24 a7 7 0 0 1 14 0 V30" fill="none" stroke="#c6ff3a" strokeWidth="4" />
      <rect x="21" y="30" width="22" height="16" rx="2" fill="#c6ff3a" />
      <circle cx="32" cy="37" r="3" fill="#0a0a0b" />
      <rect x="30.8" y="38" width="2.4" height="5" rx="1" fill="#0a0a0b" />
    </svg>
  );
}
