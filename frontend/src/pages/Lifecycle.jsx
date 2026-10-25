import React, { useEffect } from 'react'
import { useFF, secs } from '../store.jsx'
import { Badge } from '../ui.jsx'
const fmt = (d) => d ? d.toLocaleString() : 'Pending'
const Diff = ({ before, after }) => <div className="diff" role="group" aria-label="Before and after code">
  {before.split('\n').map((l,i) => <div key={'b'+i} className="m">- {l}</div>)}{after.split('\n').map((l,i) => <div key={'a'+i} className="p">+ {l}</div>)}</div>
export default function Lifecycle() {
  const f = useFF(); const best = f.attempts.find(a => a.exam.passed)
  useEffect(() => f.watch(false), [])
  const m = secs(f.t.detected, f.t.protected); const mttp = m != null ? m + ' s' : 'Not yet protected'
  const fx = f.fix || { before:'(no guidance yet)', after:'(no guidance yet)', explanation:'' }
  const src = f.offline ? 'Simulated demo data' : f.kind === 'stand-in' ? 'Stand-in backend data (real exams, regex shield)' : 'FixFort API data'
  const steps = [['Detected', f.t.detected], ['Protected', f.t.protected], ['Fix Verified', f.t.verified], ['Retired', f.t.retired]]
  const rl = [['Generated', f.attempts.length > 0], ['Exam passed', f.passed], ['Approved, live', f.approved || f.retired], ['Code fix verified', f.verified], ['Rule retired', f.retired]]
  const firstOpen = rl.findIndex(r => !r[1])
  const canVerify = f.approved && !f.retired
  const issued = f.live || f.retired   // a certificate is issued only for a deployed or completed protection, never for a failed or incomplete workflow
  const certId = issued ? 'FF-' + f.fid + '-' + (f.t.protected || f.t.detected || new Date()).getTime().toString(36).toUpperCase().slice(-6) : null
  return <div className="wrap">
    <span className="eyebrow">Lifecycle &amp; Certificate</span><h1 className="pt">Temporary by design</h1>
    <ol className="timeline">{steps.map(([n,t]) => <li key={n} className={t ? 'done' : ''}><b>{n}</b><span>{fmt(t)}</span></li>)}</ol>
    <div className="rule-life" aria-label="Temporary rule lifecycle">{rl.map(([n,d],i) => <div key={n} className={'rl ' + (d ? 'done' : i === firstOpen ? 'on' : '')}>{d ? '✓ ' : ''}{n}</div>)}</div>
    <p>MTTP: <b>{mttp}</b> · History: {f.attempts.length ? f.attempts.map(a => `attempt ${a.n} ${a.exam.passed ? 'passed' : 'failed'}`).join(', ') : 'none'}</p>
    <div className="row"><label>Clinic code mode:&nbsp;<select value={f.mode} onChange={e => f.setMode(e.target.value)} disabled={f.retired || !f.canSwitchMode || f.busy.mode}><option value="vulnerable">vulnerable</option><option value="fixed">fixed</option></select></label>
      <button className="btn" onClick={f.verify} disabled={!canVerify || f.busy.verify} title={!f.approved ? 'Approve a rule first' : f.retired ? 'Already retired' : ''}>Verify fix and retire rule</button></div>
    {f.verifyMsg && <p role="status" className={f.verifyOk ? 'okmsg' : 'err'}>{f.verifyMsg}</p>}
    {!f.canSwitchMode && <p className="note">Switch the clinic to MODE=fixed on the servers, then verify.</p>}
    <p className="note">{f.offline ? 'Verification is simulated from the selected mode.' : 'Verify fix removes the rule, re-runs the full exam against the fixed app, and retires the rule only if every attack fails on its own.'}{f.offline && <span className="sim">Simulated</span>}</p>
    <h3>Permanent fix: before and after</h3><Diff before={fx.before} after={fx.after}/>
    <p className="note">{fx.explanation} {fx.source && `Source: ${fx.source}.`}</p>
    <div className="row"><button className="btn ghost" onClick={() => window.print()} disabled={!issued} title={!issued ? 'No certificate until a rule has been approved' : ''}>Print certificate</button>{!issued && <span className="note">No certificate is issued until a rule passes the exam and is approved.</span>}</div>
    <section className={'cert' + (issued ? '' : ' void')} aria-label="Protection certificate">
      <span className={'stamp' + (f.retired ? ' r' : '')}>{f.retired ? 'RETIRED' : f.live ? 'ACTIVE' : 'NOT ISSUED'}</span>
      <div className="cert-head"><svg className="mk" width="26" height="30" viewBox="0 0 22 26" aria-hidden="true"><path d="M11 1 2 4v8c0 6 4 11 9 13 5-2 9-7 9-13V4z" fill="none" stroke="#0e7490" strokeWidth="1.6"/><path d="M8 8h6M8 12h5M8 8v9" stroke="#0e7490" strokeWidth="1.6" fill="none"/></svg>
        <h2>{issued ? 'FixFort Protection Certificate' : 'No certificate issued'}</h2></div>
      {certId && <div className="cert-id">Certificate ID · {certId}</div>}
      <p className="mono">Finding {f.fid} · {f.findings.find(x => x.id === f.fid)?.description || ''} · {src}</p>
      <table><tbody>
        <tr><th>Approved by</th><td>{f.offline ? 'Simulated' : f.cert?.deployment?.approved_by || (f.approved ? 'n/a' : 'No approval')}</td></tr>
        <tr><th>Rule attempts</th><td>{f.attempts.length || 'None'}</td></tr>
        <tr><th>Passing rule</th><td className="mono">{best ? best.rule : 'No passing rule yet'}</td></tr>
        <tr><th>Exam</th><td>{best ? `Attacks blocked ${best.exam.ab}/${best.exam.at}, users OK ${best.exam.uo}/${best.exam.ut}` : 'Not passed'}</td></tr>
        <tr><th>Approved by human</th><td>{f.approved || f.retired ? 'Yes, ' + fmt(f.t.protected) : 'No'}</td></tr>
        <tr><th>MTTP</th><td>{mttp}</td></tr>
        <tr><th>Fix verified</th><td>{f.verified ? 'Yes, ' + fmt(f.t.verified) : 'Not verified'}</td></tr>
        <tr><th>Temporary rule</th><td>{f.retired ? 'Retired, ' + fmt(f.t.retired) : f.live ? 'Active' : f.rolledBack ? 'Rolled back' : 'Not deployed'}</td></tr></tbody></table>
      <p><b>{f.retired ? 'Code fix confirmed. Temporary rule retired.' : f.live ? 'Protected by a temporary rule. This is NOT a permanent fix.' : f.status === 'FAILED' ? 'Workflow failed. Nothing was deployed.' : f.rolledBack ? 'Rule rolled back. The app is exposed.' : 'Unprotected. Workflow incomplete.'}</b></p><p className="note" style={{ color:'#475569' }}>Hackathon prototype evidence. Not a production security certification.</p>
      <svg className="seal" viewBox="0 0 120 140" aria-hidden="true"><path d="M60 8 16 24v42c0 32 20 56 44 66 24-10 44-34 44-66V24z" fill="none" stroke="#0e7490" strokeWidth="3"/><path d="M45 52h30M45 70h24M45 52v36" fill="none" stroke="#0e7490" strokeWidth="3"/></svg>
    </section></div>
}
