import React, { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useReducedMotion } from '../hooks.js'
import Scene from './Scene.jsx'

/* The hero scene is built entirely from code (see Scene.jsx): SVG geometry for the city, fortress, dome, orbit ring,
   threat trails and water reflection, animated with CSS keyframes. There is no video and no raster image here.
   Intro timeline (CSS delays, seconds): fortress rises 0.5 > dome and ring draw 1.2-3.2 > first threat wave lands ~3.5-4.3 > text 4.0-5.6.
   After the intro, one small wave of threats hits the shield every 11 s. Reduced motion renders the finished static scene. */
export default function Hero() {
  const reduce = useReducedMotion()
  const stage = useRef(null)
  const [wave, setWave] = useState(0)

  useEffect(() => {
    if (reduce) return
    const id = setInterval(() => { if (!document.hidden) setWave(w => w + 1) }, 11000)
    return () => clearInterval(id)
  }, [reduce])

  // Pointer parallax (fine pointers only): three depth layers read --px/--py.
  useEffect(() => {
    if (reduce || !window.matchMedia('(pointer:fine)').matches) return
    let raf = 0
    const move = (e) => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => {
      stage.current?.style.setProperty('--px', `${(e.clientX / innerWidth - .5) * -14}px`); stage.current?.style.setProperty('--py', `${(e.clientY / innerHeight - .5) * -8}px`) }) }
    addEventListener('pointermove', move); return () => { removeEventListener('pointermove', move); cancelAnimationFrame(raf) }
  }, [reduce])

  return (
    <section className={`hero ${reduce ? 'reduce' : ''}`} aria-label="FixFort introduction">
      <div className="stage" ref={stage}><Scene wave={wave} animate={!reduce}/><div className="shade"/></div>
      <div className="copy">
        <h1><span>The fort between</span><span>vulnerability</span><span>and resolution.</span></h1>
        <p>FixFort writes a temporary protection for a known weakness, proves it in a Practice Room, lets a human approve it, then retires it once the permanent fix is verified.</p>
        <Link className="btn outline" to="/about">Explore the Mission</Link>
      </div>
      <div className="cue" aria-hidden="true"><i/>Scroll</div>
      <div className="tag">The AI suggests. The Practice Room proves. The human decides.</div>
    </section>
  )
}
