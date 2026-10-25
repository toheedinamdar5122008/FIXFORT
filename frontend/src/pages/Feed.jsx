import React, { useEffect, useState } from 'react'
import { useFF } from '../store.jsx'
import { Shield } from '../ui.jsx'

// One event, rendered as an inspectable timeline record. Expands to the full trace.
function EventRow({ e }) {
  const [open, setOpen] = useState(false)
  const tone = e.kind === 'attack' ? (e.ok ? 'g' : 'r') : (e.shield === 'block' ? 'a' : 'u')
  return <li className={'evrow ' + tone}>
    <button className="evrow-head" aria-expanded={open} onClick={() => setOpen(o => !o)}>
      <span className="ev-time mono">{e.time}</span>
      <span className="ev-dot" aria-hidden="true"/>
      <span className="ev-req mono">{e.req}</span>
      <span className="ev-out">{e.ok ? '✓ ' : '⚠ '}{e.outcome}{e.rule && e.shield === 'block' ? ' · ' + e.rule : ''}{e.sim ? ' (sim)' : ''}</span>
    </button>
    {open && <div className="ev-trace">
      <div className="flow"><span className={'node' + (e.kind === 'attack' ? ' hot' : '')}>{e.type}</span><span className="arrow">→</span>
        <span className={'node' + (e.shield === 'block' ? ' stop' : '')}>{e.shield === 'block' ? 'Shield: BLOCK ' + (e.rule || '') : 'Shield: pass'}</span>
        {e.shield !== 'block' && <><span className="arrow">→</span><span className="node">Clinic app{e.status ? ' (' + e.status + ')' : ''}</span></>}</div>
      <div className="note">{e.reason}</div>{e.rule && <div className="mono ev-rule">Rule: {e.rule}</div>}
    </div>}
  </li>
}

export default function Feed() {
  const f = useFF(); const c = f.counts
  useEffect(() => f.watch(true), [])
  const off = !f.ready || f.busy.send
  const [flt, setFlt] = useState('all')
  const FILT = { all:() => true, blocked:e => e.shield === 'block', attacks:e => e.kind === 'attack', legit:e => e.kind !== 'attack' }
  const shown = f.events.filter(FILT[flt])
  const TESTS = [['sqli', 'SQL injection'], ['xss', 'Cross-site scripting'], ['php2shell', 'PHP2Shell exploit (CVE-2026-109618)']]
  const LEGIT = [['obrien', "Log in as O'Brien"], ['comment', 'Submit comment "5 < 6"'], ['upload', 'Legit file upload']]
  return <div className="wrap feedpage">
    <span className="eyebrow">Live Threat Feed</span><h1 className="pt">Before and after, in real time</h1>
    <p className="note">{f.offline ? 'Offline demo: events below are simulated.' : 'Events come from GET /events (polled every second). Buttons send requests through the live shield to the bundled local clinic app only.'}{f.offline && <span className="sim">Simulated</span>}</p>
    <p className="feed-state">Rule: <b className={f.live ? 'on' : ''}>{f.live ? 'live' : 'none active'}</b> · Clinic mode: <b>{f.mode}</b></p>

    <div className="feedgrid">
      {/* control surface */}
      <aside className="console card">
        <div className="console-shield"><Shield state={f.shield} size={92}/></div>
        <h2 className="console-h">Testing console</h2>
        <span className="console-grp rd">Attack simulations</span>
        {TESTS.map(([k, l]) => <button key={k} className="btn ghost tbtn atk" disabled={off} onClick={() => f.send(k)}>{l}</button>)}
        <span className="console-grp gn">Legitimate requests</span>
        {LEGIT.map(([k, l]) => <button key={k} className="btn ghost tbtn leg" disabled={off} onClick={() => f.send(k)}>{l}</button>)}
        <h2 className="console-h">Traffic mix</h2>
        <div className="cmp" role="img" aria-label={`${c.blocked} blocked, ${c.legit} legitimate, ${c.exposed} attacks succeeded`}><i className="b" style={{ flexGrow:c.blocked }}/><i className="l" style={{ flexGrow:c.legit }}/><i className="x" style={{ flexGrow:c.exposed }}/><i style={{ flexGrow:c.blocked + c.legit + c.exposed === 0 ? 1 : 0 }}/></div>
        <div className="legend"><span><i className="dot on"/>{c.blocked} blocked</span><span><i className="dot" style={{ background:'var(--cy)' }}/>{c.legit} legit OK</span><span><i className="dot" style={{ background:'var(--rd)' }}/>{c.exposed} got through</span></div>
      </aside>

      {/* event stream */}
      <section className="stream">
        <div className="streamhead">
          <div className="segctl" role="group" aria-label="Filter events">
            {[['all', 'All'], ['blocked', 'Blocked'], ['attacks', 'Attacks'], ['legit', 'Legitimate']].map(([k, l]) =>
              <button key={k} className={'seg' + (flt === k ? ' on' : '')} aria-pressed={flt === k} onClick={() => setFlt(k)}>{l}</button>)}
          </div>
          <span className="note">{shown.length} of {f.events.length} shown</span>
        </div>
        <ul className="feed" aria-live="polite">
          {f.events.length === 0 && <p className="empty">No requests yet. Use the testing console, or type into the clinic app itself.</p>}
          {f.events.length > 0 && shown.length === 0 && <p className="empty">No events match this filter.</p>}
          {shown.map(e => <EventRow key={e.id} e={e}/>)}
        </ul>
      </section>
    </div>
  </div>
}
