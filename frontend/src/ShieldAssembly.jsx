import React, { useEffect, useRef, useState } from 'react'

// Shield-assembly animation (Mission page).
// A node travels a full circle on the right; as it passes each quarter the next
// band of a shield drops into place, one below the previous. When the circle is
// complete, all four bands have combined into a single glowing shield and the
// crest + "temporary → retired" seal light up. Pure SVG/CSS + one rAF loop, no deps.
// The four steps stay in lock-step with the four FixFort principles beside it.

const CX = 180, CY = 188, R = 150
const THRESH = [0.20, 0.45, 0.70, 0.95]           // when each band locks in
// Shield silhouette (centred on CX). Four horizontal bands slice it top→bottom.
const SHIELD = `M180 70 L116 94 V170 C116 236 146 282 180 304 C214 282 244 236 244 170 V94 Z`
const BANDS = [
  { y: 70,  h: 61 },   // crest / wordmark
  { y: 131, h: 56 },   // proof
  { y: 187, h: 56 },   // human
  { y: 243, h: 61 },   // retire tip
]

function easeInOut(t) { return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2 }

export default function ShieldAssembly({ onStep }) {
  const wrap = useRef(null)
  const [p, setP] = useState(0)
  const raf = useRef(0), started = useRef(false)

  // Play once when it scrolls into view; replay each time it re-enters.
  useEffect(() => {
    const el = wrap.current
    if (!el) return
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const play = () => {
      cancelAnimationFrame(raf.current)
      if (reduce) { setP(1); return }
      const DUR = 6200, t0 = performance.now()
      const tick = (now) => {
        const k = Math.min(1, (now - t0) / DUR)
        setP(easeInOut(k))
        if (k < 1) raf.current = requestAnimationFrame(tick)
      }
      raf.current = requestAnimationFrame(tick)
    }
    const io = new IntersectionObserver((es) => {
      es.forEach(e => {
        if (e.isIntersecting) { if (!started.current) { started.current = true; play() } }
        else { started.current = false; setP(0) }      // arm for replay
      })
    }, { threshold: 0.35 })
    io.observe(el)
    return () => { io.disconnect(); cancelAnimationFrame(raf.current) }
  }, [])

  const step = THRESH.reduce((n, t) => n + (p >= t ? 1 : 0), 0)   // 0..4
  useEffect(() => { onStep && onStep(step) }, [step, onStep])

  // Node position on the ring (starts at top, −90°, clockwise).
  const ang = (-90 + p * 360) * Math.PI / 180
  const nx = CX + R * Math.cos(ang), ny = CY + R * Math.sin(ang)
  const done = p >= 1

  return (
    <div className={'shieldstage' + (done ? ' done' : '')} ref={wrap} aria-hidden="true">
      <svg viewBox="0 0 360 400" role="img">
        <defs>
          <clipPath id="sa-shield"><path d={SHIELD} /></clipPath>
          <linearGradient id="sa-band" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#22D3EE" stopOpacity=".30" />
            <stop offset="1" stopColor="#8B7CF6" stopOpacity=".18" />
          </linearGradient>
          <radialGradient id="sa-glow" cx="50%" cy="46%" r="60%">
            <stop offset="0" stopColor="#22D3EE" stopOpacity=".28" />
            <stop offset="1" stopColor="#22D3EE" stopOpacity="0" />
          </radialGradient>
          <filter id="sa-blur" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" />
          </filter>
        </defs>

        {/* soft glow behind the finished shield */}
        <circle cx={CX} cy={CY} r={120} fill="url(#sa-glow)" className="sa-halo" />

        {/* orbit track + progress arc */}
        <circle cx={CX} cy={CY} r={R} className="sa-track" />
        <circle cx={CX} cy={CY} r={R} className="sa-arc" pathLength="1"
          style={{ strokeDashoffset: 1 - p }} transform={`rotate(-90 ${CX} ${CY})`} />
        {THRESH.map((t, i) => {
          const a = (-90 + t * 360) * Math.PI / 180
          return <circle key={i} className={'sa-tick' + (step > i ? ' lit' : '')}
            cx={CX + R * Math.cos(a)} cy={CY + R * Math.sin(a)} r="4.5" />
        })}

        {/* the shield, built band by band */}
        <g clipPath="url(#sa-shield)">
          <rect x="110" y="60" width="140" height="260" fill="#0c141f" />
          {BANDS.map((b, i) => (
            <rect key={i} className={'sa-bandrect' + (step > i ? ' in' : '')}
              x="110" y={b.y} width="140" height={b.h} fill="url(#sa-band)" />
          ))}
          {/* scan sweep while assembling */}
          <rect className="sa-sweep" x="110" width="140" height="26" fill="#22D3EE" opacity=".22" />
        </g>
        <path d={SHIELD} className="sa-outline" pathLength="1" style={{ strokeDashoffset: 1 - Math.min(1, p * 1.05) }} />

        {/* crest mark — draws in near completion */}
        <path className={'sa-crest' + (done ? ' in' : '')} pathLength="1"
          d="M152 150 l20 20 l40 -44" />
        <text x={CX} y="214" className={'sa-word' + (done ? ' in' : '')} textAnchor="middle">FixFort</text>

        {/* travelling node + comet head */}
        <circle className="sa-node-halo" cx={nx} cy={ny} r="13" filter="url(#sa-blur)" opacity={done ? 0 : 0.9} />
        <circle className="sa-node" cx={nx} cy={ny} r="6" opacity={done ? 0 : 1} />
      </svg>
    </div>
  )
}
