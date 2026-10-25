import React, { useRef, useCallback } from 'react'
import { Link } from 'react-router-dom'
import Hero from './Hero.jsx'
import { Reveal } from '../ui.jsx'

const Icon = ({ d }) => <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{d}</svg>
const STEPS = [
  { n: '01', t: 'Scan', c: 'cy', z: -70,
    d: 'FixFort scans the live site the way an attacker would and surfaces the real holes — SQL injection, XSS, even a fresh PHP zero-day.',
    icon: <><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></> },
  { n: '02', t: 'Prove', c: 'vi', z: 0,
    d: 'An AI writes a temporary shield rule. The Practice Room proves it blocks every attack and still lets real users through — before anything goes live.',
    icon: <><path d="M9 12l2 2 4-4"/><path d="M12 3l7 4v5c0 5-3.5 8-7 9-3.5-1-7-4-7-9V7z"/></> },
  { n: '03', t: 'Retire', c: 'gn', z: -70,
    d: 'A human approves it, protection is live in minutes, and the rule retires itself once the permanent fix is verified. Nothing stays temporary forever.',
    icon: <><path d="M3 12a9 9 0 1 0 9-9"/><path d="M3 4v5h5"/><path d="M12 7v5l3 2"/></> },
]
// Dominant principle + two supporting (editorial, not three identical cards).
const LEAD_PRINCIPLE = ['Proven, not trusted',
  'Every rule is tested against real attacks AND real legitimate users before a human can approve it — the attacks-blocked and users-OK counts are on screen, so nothing goes live on faith.']
const SUPPORT = [
  ['Self-correcting', 'A rule that wrongly blocks a real customer (O’Brien) fails its own exam, and the next attempt narrows the pattern until attacks are blocked and real users pass.'],
  ['Fresh-CVE ready', 'The same engine that shields SQL injection is virtually patching a specific disclosed PHP RCE — CVE-2026-109618 — until every server is permanently upgraded.'],
]
// Decorative "spatial corridor" — faint cards flying toward the viewer behind the section.
const SHARDS = [
  { l: 8, t: 20, d: 0.0, u: 7.5, c: 'cy' }, { l: 86, t: 16, d: 1.1, u: 8.2, c: 'vi' },
  { l: 18, t: 72, d: 2.3, u: 7.0, c: 'gn' }, { l: 78, t: 66, d: 3.0, u: 8.8, c: 'cy' },
  { l: 4, t: 48, d: 4.2, u: 7.8, c: 'vi' },  { l: 92, t: 44, d: 0.7, u: 9.1, c: 'cy' },
  { l: 30, t: 10, d: 5.0, u: 8.0, c: 'gn' }, { l: 64, t: 84, d: 2.8, u: 7.4, c: 'vi' },
  { l: 48, t: 6,  d: 3.7, u: 9.4, c: 'cy' }, { l: 50, t: 90, d: 1.6, u: 8.6, c: 'gn' },
  { l: 12, t: 36, d: 6.1, u: 7.2, c: 'cy' }, { l: 88, t: 78, d: 4.8, u: 8.4, c: 'vi' },
]

export default function Home() {
  const deck = useRef(null)
  // Mouse parallax: tilt the whole 3D stage toward the cursor.
  const onMove = useCallback((e) => {
    const el = deck.current; if (!el) return
    const r = el.getBoundingClientRect()
    const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5
    el.style.setProperty('--ry', (x * 10).toFixed(2) + 'deg')
    el.style.setProperty('--rx', (-y * 8).toFixed(2) + 'deg')
  }, [])
  const onLeave = useCallback(() => {
    const el = deck.current; if (!el) return
    el.style.setProperty('--ry', '0deg'); el.style.setProperty('--rx', '0deg')
  }, [])

  return <>
    <Hero/>
    <section className="band wrap flowzone">
      <div className="corridor" aria-hidden="true">
        {SHARDS.map((s, i) => <span key={i} className={'shard ' + s.c}
          style={{ left: s.l + '%', top: s.t + '%', '--d': s.d + 's', '--u': s.u + 's' }}/>)}
      </div>

      <Reveal className="deckhead-wrap"><span className="deckring" aria-hidden="true"/>
        <span className="eyebrow">How FixFort works</span><h2 className="deckhead">Scan. Prove. Retire.</h2>
        <p className="note deckintro">Three moves close the gap between a hole found and a hole fixed — each one proven before the next begins.</p>
      </Reveal>

      <div className="flowdeck" ref={deck} onMouseMove={onMove} onMouseLeave={onLeave}>
        <div className="flowdeck-rail" aria-hidden="true"/>
        <div className="flowdeck-stage">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} className={'deckcard ' + s.c} delay={i * 160} style={{ '--z': s.z + 'px' }}>
              <span className="deck-n">{s.n}</span>
              <span className="deck-ic"><Icon d={s.icon}/></span>
              <b>{s.t}</b>
              <p>{s.d}</p>
              <span className="deck-glow" aria-hidden="true"/>
            </Reveal>
          ))}
        </div>
      </div>

      <Reveal><span className="eyebrow siglead">What makes it different</span></Reveal>
      <div className="whatdiff">
        <Reveal className="wd-lead card edge">
          <span className="wd-mark" aria-hidden="true">01</span>
          <span className="eyebrow">The principle</span>
          <b>{LEAD_PRINCIPLE[0]}</b>
          <p className="note">{LEAD_PRINCIPLE[1]}</p>
        </Reveal>
        <div className="wd-support">
          {SUPPORT.map(([t, d], i) =>
            <Reveal key={t} className="wd-item" delay={i * 120}><span className="wd-n">0{i + 2}</span><div><b>{t}</b><p className="note">{d}</p></div></Reveal>)}
        </div>
      </div>

      <Reveal className="homecta">
        <p>Close the window between a vulnerability found and a vulnerability fixed — a proven, temporary shield stood up in minutes and retired the moment the permanent fix lands.</p>
        <div><Link className="btn" to="/dashboard">Open the Command Center</Link> <Link className="btn ghost" to="/pipeline">Watch the Practice Room</Link></div>
      </Reveal>
    </section>
  </>
}
