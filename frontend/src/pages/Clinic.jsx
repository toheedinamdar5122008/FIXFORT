import React, { useEffect, useState } from 'react'
import { CLINIC, clinicHealth } from '../api.js'
import { useFF } from '../store.jsx'
import { Badge } from '../ui.jsx'

export default function Clinic() {
  const f = useFF(); const [h, setH] = useState(null)
  useEffect(() => f.watch(true), [])    // watch live traffic so clinic actions show here
  const liveEvents = (f.events || []).filter(e => e.kind === 'attack' || e.kind === 'user').slice(0, 8)
  const check = () => { setH(null); clinicHealth().then(setH) }
  useEffect(check, [])
  const fix = f.fix || { before: '(connect the API for the before/after code)', after: '' }
  const clinicMode = h?.reachable ? h.mode : null
  const stage = f.retired && clinicMode === 'fixed' ? 3 : f.live ? 2 : 1
  const protState = f.offline ? 'simulated' : f.conn !== 'api' ? 'API not connected' : f.live ? 'temporary rule LIVE' : f.retired ? 'rule retired' : 'no rule yet'
  const Stage = ({ n, title, tone, children }) => <div className={'card jstage' + (stage === n ? ' now' : '')} aria-current={stage === n ? 'step' : undefined}><Badge tone={tone}>{n}. {title}</Badge>{children}</div>

  return <div className="wrap">
    <span className="eyebrow">The target</span>
    <h1 className="pt">The website we are attacking</h1>
    <p className="note">This is the <b>real, separate, deliberately-vulnerable website</b> that FixFort protects — a fake clinic portal. The FixFort dashboard is the control panel; <b>this is the actual target</b>. It runs only on this computer, with fake data.</p>

    {/* The attacked site, always visible, plus a live attack guide beside it */}
    <div className="clinicgrid">
      <div className="browserframe">
        <div className="browserbar">
          <span className="bdots"><i/><i/><i/></span>
          <span className="burl mono">{CLINIC}</span>
          <a className="btn sm" href={CLINIC} target="_blank" rel="noreferrer">Open ↗</a>
        </div>
        <iframe title="The clinic website being attacked" src={CLINIC} className="clinicembed"/>
      </div>

      <div className="card attackbox">
        <span className="eyebrow">Attack it live</span>
        <p className="note">Type these straight into the forms in the site on the left (or open it in a new tab). While unprotected they work; after you protect the finding, they are blocked.</p>
        <ol className="attacklist">
          <li><span className="atag rd">SQLi</span> Login username <code>{"' OR 1=1 --"}</code> (any password) → logs in with <b>no password</b>.</li>
          <li><span className="atag rd">XSS</span> Comment <code>{'<script>alert(1)</script>'}</code> → runs in the next visitor's browser.</li>
          <li><span className="atag rd">PHP RCE</span> Upload note <code>{'<?php system($_GET[c]) ?>'}</code> → the PHP2Shell exploit.</li>
        </ol>
        <p className="note">A real customer who must <b>always</b> work: <code>O'Brien</code> / <code>obrienpass</code>. If a rule ever blocks O'Brien, it failed its exam — that is the catch.</p>
        <div className="statline">
          <span className="pill"><i className={'dot' + (h?.reachable ? ' on' : '')}/>Clinic: {h === null ? 'checking…' : h.reachable ? `reachable${h.mode ? ' · ' + h.mode : ''}` : 'open in new tab ↗'}</span>
          <span className="pill"><i className={'dot' + (f.live ? ' on' : '')}/>Protection: {protState}</span>
          <button className="btn sm ghost" onClick={check}>Re-check</button>
        </div>
        {!h?.reachable && h !== null && <p className="note">If the embed is blank, use <b>Open ↗</b> — some setups block embedding, but the site itself is running.</p>}
      </div>
    </div>

    <div className="card livefeed">
      <div className="livehead"><span className="eyebrow">Live traffic — what is hitting the clinic right now</span>
        <span className="pill"><i className={'dot' + (f.live ? ' on' : '')}/>{f.live ? 'rule LIVE' : 'no rule yet'}</span></div>
      {liveEvents.length === 0
        ? <p className="note">Type an attack into the site above — or use the Dashboard’s attack buttons — and every request appears here instantly, shown as <b>blocked</b> or <b>allowed</b>. This is the same feed the judges watch.</p>
        : <ul className="liverows">{liveEvents.map(e => <li key={e.id} className={'liverow ' + (e.ok ? 'good' : 'bad')}>
            <span className={'atag ' + (e.kind === 'attack' ? 'rd' : 'gn')}>{e.kind === 'attack' ? (e.type || 'ATTACK') : 'USER'}</span>
            <span className="mono lr-req">{e.req}</span>
            <span className={'lr-out ' + (e.ok ? 'g' : 'r')}>{e.outcome}</span>
            <span className="lr-time mono">{e.time}</span>
          </li>)}</ul>}
    </div>

    <h3>The three states to show a judge</h3>
    <div className="cmpcode stages">
      <Stage n={1} title="Vulnerable" tone="rd"><p className="note">No rule. The SQLi payload logs in with no password — the site is exposed.</p></Stage>
      <Stage n={2} title="Temporary protection" tone="am"><p className="note">Rule live in the shield. The attack is blocked (403) and O'Brien still logs in. The code is still vulnerable underneath.</p></Stage>
      <Stage n={3} title="Verified permanent fix" tone="gn"><p className="note">Code fixed, re-tested without the rule, attack fails on its own, rule retired. Only this is a real fix.</p></Stage>
    </div>

    <h3>Why the site is vulnerable — and the permanent fix</h3>
    <div className="cmpcode">
      <div><h4 className="minih rd">Vulnerable (SQLi)</h4><pre className="mono">{fix.before}</pre><p className="note">User input is glued into the SQL string, so a quote rewrites the query.</p></div>
      <div><h4 className="minih gn">Fixed</h4><pre className="mono">{fix.after}</pre><p className="note">Values are bound as data and can never change the query's structure.</p></div>
    </div>
    <p className="note">Start the site with <span className="mono">cd mock-backend; python server.py</span> (clinic + shield on {CLINIC}).</p>
  </div>
}
