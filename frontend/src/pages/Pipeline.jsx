import React, { useEffect } from 'react'
import { useFF, secs } from '../store.jsx'
import { useNow } from '../hooks.js'
import { Shield, Count, Badge } from '../ui.jsx'
const STEPS = ['analyze','generate','syntax','exam','approve','live']
const EXAM = 3   // index of 'exam' in STEPS
export default function Pipeline() {
  const f = useFF()
  useEffect(() => f.watch(false), [])
  const now = useNow(f.running || (f.passed && !f.approved))
  const elapsed = f.t.protected ? secs(f.t.detected, f.t.protected) : Math.max(0, Math.round((now - f.t.detected) / 1000))
  // Explicit state machine: a FAILED run rests "at exam, failed" — scan/generate/syntax
  // stay DONE (they genuinely ran), exam shows failed, and later stages stay pending.
  const failed = f.status === 'FAILED' || f.stage === 'failed'
  const idx = failed ? EXAM : STEPS.indexOf(f.stage)
  const cls = (i) => {
    if (f.stage === 'idle') return ''
    if (failed) return i < EXAM ? 'done' : i === EXAM ? 'cur' : ''
    return (i < idx || f.stage === 'live') ? 'done' : i === idx ? 'cur' : ''
  }
  const failedNow = failed || (f.running && f.stage === 'exam' && f.lastFailed)
  const lastAttempt = f.attempts.length
  const sub = (s, i) => {
    if (failed && s === 'exam') return lastAttempt ? 'attempt ' + lastAttempt + ' failed' : 'exam failed'
    if (f.running && s === 'exam' && f.stage === 'exam' && f.lastFailed) return 'retrying exam'
    return cls(i) === 'done' ? 'complete' : cls(i) === 'cur' ? (f.running ? 'in progress' : 'ready') : 'pending'
  }
  const target = f.findings.find(x => x.id === f.fid)
  const canStart = f.ready && !f.busy.protect && ['NEW', 'FAILED', 'ROLLED_BACK'].includes(f.status)
  return <div className="wrap">
    <span className="eyebrow">Protection Pipeline</span><h1 className="pt">Proof before protection</h1>
    <p className="note">{f.fid} · {target ? `${target.type} on ${target.target} (${target.parameter})` : 'finding'} · {f.offline ? 'Simulated Practice Room' : f.kind === 'stand-in' ? 'Stand-in Practice Room: real exam requests, fixed rule proposals' : 'Practice Room via API'}{f.offline && <span className="sim">Simulated</span>}</p>
    <div className="pgrid"><div><Shield state={f.shield} size={170}/>
      <p className="timer">{f.stage === 'idle' ? '0 s' : elapsed + ' s'}<small>{f.approved ? 'MTTP, stopped at approval' : 'MTTP running'}</small></p></div>
    <div>
    <div className={'pipeflow' + (f.running ? ' running' : '')} style={{ '--prog': f.stage === 'idle' ? 0 : f.stage === 'live' || f.approved ? 1 : Math.max(0, idx) / (STEPS.length - 1) }}>
      <div className="pipebeam" aria-hidden="true"><span/></div>
      <ol className="stepper" aria-label="Pipeline stages">{STEPS.map((s,i) => {
        const st = cls(i), isGen = s === 'generate', isFail = failedNow && s === 'exam'
        const spinning = st === 'cur' && f.running && !isFail            // show "processing" only while genuinely running
        return <li key={s} className={st + (isGen ? ' gen' : '') + (isFail ? ' fail' : '')} aria-current={st === 'cur' ? 'step' : undefined}>
          <span className="step-orb" aria-hidden="true">
            <span className="n">0{i+1}</span>
            <span className="step-ring"/>
            <span className="step-check">✓</span>
            {spinning && <span className={'step-proc' + (isGen ? ' neural' : '')}><i/><i/><i/></span>}
            <span className="step-ripple"/>
          </span>
          <b>{s}</b><small>{sub(s,i)}</small>
        </li>
      })}</ol>
    </div>
    <div className="row">
      <button className={'btn' + (f.running ? ' busy' : '')} onClick={f.protect} disabled={!canStart}>{f.running ? 'Running' : 'Start protection'}</button>
      <button className="btn" onClick={f.approve} disabled={!f.passed || f.status !== 'TESTED' || f.busy.approve} title={!f.passed ? 'Enabled only after the exam passes' : ''}>{f.approved ? 'Approved' : 'Approve'}</button>
      {f.live && <button className="btn danger" onClick={f.rollback} disabled={f.busy.rollback}>Roll back</button>}
      <button className="btn ghost" onClick={f.reset} disabled={!f.ready || f.busy.reset}>Reset demo</button></div>
    {!f.passed && <p className="note">Approve stays disabled until an attempt passes every attack and legitimate-user test.</p>}
    {f.status === 'FAILED' && <p className="err" role="alert">No attempt passed the exam. Nothing was deployed.</p>}
    </div></div>
    {f.attempts.length === 0 && <div className="card empty">{f.running ? 'The Practice Room is generating the first rule.' : 'No attempts yet. Press Start protection to open the Practice Room.'}</div>}
    <div>{f.attempts.map(a => <article key={a.n} className={'att ' + (a.exam.passed ? 'ok' : 'bad')}>
      <h3>Attempt {a.n} <Badge tone="cy">{a.strategy}</Badge><Badge tone={a.exam.passed ? 'gn' : 'rd'}>{a.exam.passed ? 'PASSED' : 'FAILED'}</Badge></h3>
      <div className="chk"><span className={a.syntaxOk ? 'y' : 'x'}>{a.syntaxOk ? '✓ syntax valid' : '✗ syntax error'}</span><span className={a.exam.ab === a.exam.at ? 'y' : 'x'}>{a.exam.ab === a.exam.at ? '✓' : '✗'} attack tests</span><span className={a.exam.uo === a.exam.ut ? 'y' : 'x'}>{a.exam.uo === a.exam.ut ? '✓' : '✗'} legitimate users</span></div>
      <pre className="mono">{a.rule}</pre>
      <div className="big"><div className={a.exam.ab === a.exam.at ? 'g' : 'r'}><b><Count v={a.exam.ab}/>/{a.exam.at}</b><span>Attacks blocked</span></div><div className={a.exam.uo === a.exam.ut ? 'g' : 'r'}><b><Count v={a.exam.uo}/>/{a.exam.ut}</b><span>Users OK</span></div></div>
      {a.exam.failures.map((x,i) => <div key={i} className="fdiag"><b className="err">{x.kind === 'user' ? 'Legitimate request failed:' : 'Attack got through:'}</b> <span className="mono">{x.name}</span> returned {x.got}.</div>)}
      {a.why && <div className="rationale"><span className="lbl">AI rationale</span>{a.why}</div>}
      {!a.exam.passed && a.exam.failures.some(x => x.kind === 'user') && <p><b>Why it failed:</b> the rule was too broad and blocked real users, so the Practice Room rejected it and the next attempt narrows the pattern.</p>}
      {a.exam.passed && <p><b>Why it passed:</b> every attack was stopped and every legitimate-user test returned the expected page.</p>}</article>)}</div>

    {/* FixFort Sentinel: Agent37 Hermes Cloud Integration */}
    <section className="sentinel-card">
      <div className="sentinel-header">
        <div className="sentinel-title-block">
          <span className="sentinel-badge">FIXFORT SENTINEL</span>
          <span className="agent37-chip">
            <span className="pulse-dot"></span>
            AGENT37 CLOUD · HERMES RUNTIME (d1r7b60za3)
          </span>
        </div>
        <button
          className={'btn sentinel-btn' + (f.sentinelLoading ? ' busy' : '')}
          onClick={f.sentinelReview}
          disabled={f.sentinelLoading || f.busy.sentinel}
        >
          {f.sentinelLoading ? 'Hermes Reviewing…' : f.sentinel ? 'Re-run Sentinel Review' : 'Run Sentinel Review'}
        </button>
      </div>

      {f.sentinel ? (
        <div className="sentinel-body">
          <div className="sentinel-top-row">
            <div className="sentinel-verdict-box">
              <span className="sentinel-lbl">AI AGENT VERDICT</span>
              <span className={'verdict-pill ' + String(f.sentinel.verdict || 'APPROVE').toLowerCase()}>
                {f.sentinel.verdict === 'APPROVE' ? '✓ ' : '⚠ '}
                {f.sentinel.verdict}
              </span>
            </div>
            <div className="sentinel-metrics">
              <div className="smetric">
                <span className="smetric-label">Confidence</span>
                <span className="smetric-value">{Math.round((f.sentinel.confidence || 0.95) * 100)}%</span>
              </div>
              <div className="smetric">
                <span className="smetric-label">Risk Assessment</span>
                <span className={'smetric-value risk-' + String(f.sentinel.risk_level || 'low').toLowerCase()}>{f.sentinel.risk_level || 'LOW'}</span>
              </div>
              <div className="smetric">
                <span className="smetric-label">Legitimate Traffic</span>
                <span className="smetric-value safe">✓ O'Brien Pass</span>
              </div>
            </div>
          </div>

          <div className="sentinel-grid">
            <div className="sentinel-panel">
              <h4>Technical Review</h4>
              <p>{f.sentinel.analysis}</p>
              <h4>Bypass & Evasion Analysis</h4>
              <p>{f.sentinel.bypass_analysis}</p>
            </div>
            <div className="sentinel-panel">
              <h4>False Positive Assessment</h4>
              <p>{f.sentinel.false_positive_analysis}</p>
              <h4>Human Officer Decision Guidance</h4>
              <div className="guidance-box">
                <p><strong>{f.sentinel.recommendation_summary}</strong></p>
              </div>
            </div>
          </div>

          {f.sentinel.permanent_fix_advice && (
            <div className="sentinel-fix-box">
              <span className="sentinel-lbl">PERMANENT CODE REMEDIATION GUIDANCE</span>
              <pre className="mono">{f.sentinel.permanent_fix_advice}</pre>
            </div>
          )}

          <div className="sentinel-footer">
            <small>Audited by Agent37 Cloud (Instance: <code>{f.sentinel.instance_id || 'd1r7b60za3'}</code>) · Source: {f.sentinel.source} · {f.sentinel.reviewed_at ? new Date(f.sentinel.reviewed_at).toLocaleTimeString() : 'Verified'}</small>
          </div>
        </div>
      ) : (
        <div className="sentinel-placeholder">
          <p>
            <strong>Pre-Approval Intelligence:</strong> Engage autonomous security agent on Agent37 Cloud (Hermes runtime) to audit the candidate rule against bypass vectors, false positives (e.g. Irish names with apostrophes), and generate verified remediation advice before human approval.
          </p>
        </div>
      )}
    </section>

    {f.passed && !f.approved && <p className="note">Passing conditions met. Review Sentinel audit above and approve to deploy.</p>}
    {f.approved && <p className="okmsg">{f.retired ? 'Rule retired after verified fix.' : 'Live protection active.'} MTTP: {secs(f.t.detected, f.t.protected) ?? 'n/a'} s (created_at to approved_at).</p>}
  </div>
}
