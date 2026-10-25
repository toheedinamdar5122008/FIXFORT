import { useEffect, useRef, useState } from 'react'
// True when the visitor asks the OS for reduced motion. All motion keys off this.
export function useReducedMotion() {
  const q = '(prefers-reduced-motion: reduce)'
  const [r, setR] = useState(() => typeof window !== 'undefined' && window.matchMedia(q).matches)
  useEffect(() => { const m = window.matchMedia(q); const f = () => setR(m.matches); m.addEventListener('change', f); return () => m.removeEventListener('change', f) }, [])
  return r
}
// Ticks once per second only while `active`; used for the live MTTP timer.
export function useNow(active) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => { if (!active) return; setNow(Date.now()); const id = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(id) }, [active])
  return now
}
// Counts a number up to `value` using rAF for a short, interruptible animation.
export function useCountUp(value, ms = 700) {
  const reduce = useReducedMotion(); const [v, setV] = useState(value); const from = useRef(value)
  useEffect(() => {
    if (reduce || typeof value !== 'number') { setV(value); from.current = value; return }
    let raf = 0, t0 = 0; const a = from.current
    const step = (t) => { t0 = t0 || t; const k = Math.min(1, (t - t0) / ms); setV(Math.round(a + (value - a) * (1 - Math.pow(1 - k, 3)))); if (k < 1) raf = requestAnimationFrame(step); else from.current = value }
    raf = requestAnimationFrame(step); return () => cancelAnimationFrame(raf)
  }, [value, ms, reduce])
  return v
}
// Adds .in to an element when it enters the viewport (one observer per element, disconnected after use).
export function useReveal() {
  const ref = useRef(null)
  useEffect(() => {
    const el = ref.current; if (!el) return
    if (!('IntersectionObserver' in window)) { el.classList.add('in'); return }
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { el.classList.add('in'); io.disconnect() } }, { threshold: .15 })
    io.observe(el); return () => io.disconnect()
  }, [])
  return ref
}
