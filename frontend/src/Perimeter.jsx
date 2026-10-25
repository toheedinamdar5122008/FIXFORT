import React from 'react'

// Command-Center hero visual: a security perimeter closing around an exposed
// endpoint. It is a pure function of the real shield state (same states the
// Shield component uses), so it never depicts protection the app doesn't have.
//   exposed  -> broken red ring, the attack request reaches the endpoint
//   testing  -> cyan segments assembling (Practice Room)
//   failed   -> red, perimeter rejected
//   live     -> closed cyan ring, the request is stopped at the boundary
//   verified/retired -> calm green, ring dimmed, protection retired
const LABEL = { exposed:'Exposed', testing:'Proving rule', failed:'Exam failed', verified:'Fix verified', live:'Protected', retired:'Rule retired' }
const TONE  = { exposed:'rd', testing:'cy', failed:'rd', verified:'gn', live:'cy', retired:'mu' }

export default function Perimeter({ state = 'exposed' }) {
  const tone = TONE[state] || 'cy'
  const closed = state === 'live'
  const open = state === 'exposed' || state === 'failed'
  // 12 perimeter segments around the endpoint
  const segs = Array.from({ length: 12 }, (_, i) => i)
  return (
    <figure className={'perim ' + state} aria-label={'Protection state: ' + (LABEL[state] || state)}>
      <svg viewBox="0 0 220 220" role="img">
        <defs>
          <radialGradient id="pm-core" cx="50%" cy="50%" r="50%">
            <stop offset="0" stopColor="currentColor" stopOpacity=".28"/><stop offset="1" stopColor="currentColor" stopOpacity="0"/>
          </radialGradient>
        </defs>
        {/* ambient glow */}
        <circle className="pm-glow" cx="110" cy="110" r="78" fill="url(#pm-core)"/>
        {/* incoming request path */}
        <g className="pm-req" aria-hidden="true">
          <line x1="6" y1="110" x2="78" y2="110"/>
          <circle className="pm-packet" cx="6" cy="110" r="4"/>
        </g>
        {/* segmented perimeter ring */}
        <g className="pm-ring">
          {segs.map(i => {
            const a0 = (i / 12) * 2 * Math.PI - Math.PI / 2 + 0.06
            const a1 = ((i + 1) / 12) * 2 * Math.PI - Math.PI / 2 - 0.06
            const r = 82, cx = 110, cy = 110
            const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0)
            const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1)
            // when "open", leave the left-facing segments (where the request enters) missing
            const facing = Math.cos((a0 + a1) / 2) < -0.5
            const missing = open && facing
            return <path key={i} className={'pm-seg' + (missing ? ' gap' : '')}
              style={{ '--i': i }} d={`M ${x0.toFixed(1)} ${y0.toFixed(1)} A ${r} ${r} 0 0 1 ${x1.toFixed(1)} ${y1.toFixed(1)}`}/>
          })}
        </g>
        {/* the endpoint being protected */}
        <g className="pm-core">
          <rect x="88" y="88" width="44" height="44" rx="10"/>
          <text x="110" y="116" textAnchor="middle" className="pm-label">app</text>
        </g>
        {/* block marker at the boundary when live */}
        {closed && <g className="pm-block"><circle cx="78" cy="110" r="9"/><path d="M74 110h8" /></g>}
        {(state === 'verified' || state === 'retired') && <path className="pm-check" d="M96 110l10 10 20-24"/>}
      </svg>
      <figcaption className={'badge ' + tone}>{LABEL[state] || state}</figcaption>
    </figure>
  )
}
