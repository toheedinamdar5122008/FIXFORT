import React, { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { STATUS_LABEL } from '../api.js'
import { useFF, secs } from '../store.jsx'
import { Count, Badge, sev, STATUS_TONE } from '../ui.jsx'
import Perimeter from '../Perimeter.jsx'
const Chip = ({ tone, label, state }) => <span className={'statuschip ' + tone}><i className="sc-dot"/><span className="sc-k">{label}</span><span className="sc-v">{state}</span></span>
export default function Command() {
  const f = useFF(); const nav = useNavigate()
  useEffect(() => f.watch(true), [])
  const L = f.findings; const done = (x) => ['LIVE', 'RETIRED', 'FIX_VERIFIED'].includes(x.status)
  const open = L.length - L.filter(done).length
  const prot = L.filter(x => x.status === 'LIVE' || x.status === 'RETIRED').length
  const times = L.map(x => x.mttp).filter(x => x != null); const avg = times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : null
  const up = f.conn === 'api' || f.offline, src = f.offline ? 'Simulated' : f.kind === 'stand-in' ? 'Stand-in backend' : 'Live API'
  const sandboxState = f.offline ? 'Simulated' : up ? 'Reachable' : 'Unreachable'
  // Status-chip tone reflects the TRUTH of each service (connected / simulated / pending / down) — never a fake live pulse.
  const shTone = f.offline ? 'sim' : !up ? 'down' : f.live ? 'live' : 'idle'
  const prTone = f.offline ? 'sim' : up ? 'live' : 'down'
  const aiTone = f.offline ? 'sim' : f.kind === 'stand-in' ? 'idle' : up ? 'idle' : 'down'
  return <div className="wrap cmdpage">
    <div className="advisory" role="status">
      <span className="adv-sev"><span className="adv-dot"/>CRITICAL</span>
      <div className="adv-body"><span className="adv-id">CVE-2026-109618 / 109619 · "PHP2Shell"</span>
        <span className="adv-txt">Unauthenticated PHP RCE · <b>CVSS 9.2</b> · disclosed Oct 2026 · ~70% of the web runs PHP</span></div>
    </div>

    <div className="cmdhero">
      <div className="cmdhero-l">
        <span className="eyebrow">Command Center</span>
        <h1 className="pt cmdhero-h">Know what is exposed.<br/>Close the gap.</h1>
        <p className="note">Data source: <b>{src}</b>.{f.offline && <span className="sim">Simulated</span>}</p>
        <div className="statuschips">
          <Chip tone={shTone} label="Live Shield" state={!up ? 'Unreachable' : f.offline ? 'Simulated' : f.live ? 'Protecting' : 'No rule'}/>
          <Chip tone={prTone} label="Practice Room" state={sandboxState}/>
          <Chip tone={aiTone} label="AI Engine" state={f.offline ? 'Simulated' : f.kind === 'stand-in' ? 'Stand-in, no LLM' : up ? 'Via API' : 'Unreachable'}/>
        </div>
        {f.counts.exposed > 0 && !f.live && <div className="alert" role="alert"><Badge tone="rd">Threat</Badge>{f.counts.exposed} attack request{f.counts.exposed > 1 ? 's' : ''} succeeded against the unprotected clinic app.</div>}
        {f.live && <div className="alert gn"><Badge tone="gn">Live</Badge>Rule is protecting {L.find(x => x.id === f.fid)?.target} while the permanent fix is pending.</div>}
      </div>
      <div className="cmdhero-r"><Perimeter state={f.shield}/></div>
    </div>

    <div className="cmdstats">
      <div className={'statlead ' + (open > 0 ? 'hot' : 'calm')}>
        <span className="sl-k">{open > 0 ? 'Open findings' : 'All findings protected'}</span>
        <b className="sl-n"><Count v={open}/></b>
        <span className="sl-sub">{open > 0 ? 'awaiting a proven rule' : 'nothing exposed right now'}</span>
      </div>
      <div className="statrow">
        <div className="statmini gn"><b><Count v={prot}/></b><span>Protected</span><small>live or retired</small></div>
        <div className="statmini"><b>{avg != null ? <><Count v={avg}/><em>s</em></> : 'n/a'}</b><span>Avg MTTP</span><small>approved − created</small></div>
        <div className="statmini gn"><b><Count v={f.counts.blocked}/></b><span>Attacks blocked</span><small>this session</small></div>
      </div>
    </div>
    {!f.scanned ?
      <div className="card scanpanel">
        <span className="eyebrow">Step 1 — Discover</span>
        <h3 className="scanh">Scan the demo website for vulnerabilities</h3>
        <p className="note">FixFort probes the live clinic app the way a scanner would and reports what it finds. Nothing is pre-loaded — the findings below appear only once the scan confirms them.</p>
        {f.scanning ?
          <div className="scanrun">
            <div className="scanbar"><i/></div>
            <ul className="scanlog">{f.scanLog.map((e, i) =>
              <li key={i}><span className="mono">probing {e.target}</span>
                <span className={'scanhit ' + (e.vulnerable ? 'bad' : 'ok')}>{e.vulnerable ? '● VULNERABLE — ' + String(e.type || '').toUpperCase().replace('_', ' ') : '○ clean'}</span></li>)}
            </ul>
          </div> :
          <button className="btn scanbtn" disabled={!f.ready} onClick={f.scan}>▶  Run security scan</button>}
      </div> :
      <>
        <div className="row" style={{ justifyContent:'space-between' }}><span className="eyebrow">Findings · detected by scan</span>
          <button className="btn sm ghost" disabled={!f.ready || f.scanning} onClick={f.scan}>Rescan</button></div>
        {L.length === 0 ? <div className="card empty">No vulnerabilities detected on the last scan.</div> :
        <div className="card scroll"><table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Severity</th><th>Status</th><th>MTTP</th><th>Action</th></tr></thead><tbody>
          {L.map(x => { const st = STATUS_LABEL[x.status] || x.status; return <tr key={x.id}><td className="mono">{x.id}</td><td className="mono">{x.target}</td><td><Badge tone="cy">{x.type}</Badge></td><td>{sev(x.severity)}</td>
            <td><Badge tone={STATUS_TONE[st] || 'mu'}>{st}</Badge></td><td className="mono">{x.mttp != null ? x.mttp + ' s' : 'n/a'}</td>
            <td><button className="btn sm" disabled={!f.ready || (f.offline && x.id !== 'F-001')} title={f.offline && x.id !== 'F-001' ? 'Offline demo covers F-001 only' : ''} onClick={() => { f.select(x.id); nav('/pipeline') }}>{x.status === 'NEW' ? 'Protect' : 'Open'}</button></td></tr> })}
        </tbody></table></div>}
      </>}
  </div>
}
