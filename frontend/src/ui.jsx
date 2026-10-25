import React from 'react'
import { Link } from 'react-router-dom'
import { useCountUp, useReveal } from './hooks.js'
export const Logo = () => <Link to="/" className="logo" aria-label="FixFort home"><svg width="22" height="26" viewBox="0 0 22 26" aria-hidden="true"><path d="M11 1 2 4v8c0 6 4 11 9 13 5-2 9-7 9-13V4z" fill="none" stroke="#22D3EE" strokeWidth="1.6"/><path d="M8 8h6M8 12h5M8 8v9" stroke="#22D3EE" strokeWidth="1.6" fill="none"/></svg>FixFort</Link>
export const Count = ({ v, suffix='' }) => { const n = useCountUp(typeof v === 'number' ? v : 0); return <>{typeof v === 'number' ? n : v}{suffix}</> }
export const Reveal = ({ children, className='', as:T='div', delay=0, style={} }) => { const r = useReveal(); return <T ref={r} className={'reveal ' + className} style={{ '--d': delay + 'ms', ...style }}>{children}</T> }
export const Badge = ({ tone='mu', children }) => <span className={'badge ' + tone}>{children}</span>
export const sev = (s) => <Badge tone={s === 'Critical' || s === 'High' ? 'rd' : 'am'}>{s}</Badge>
export const STATUS_TONE = { New:'am', Protecting:'cy', Tested:'gn', Live:'gn', 'Fix verified':'gn', Retired:'mu', 'Rolled back':'am', Failed:'rd' }
const LABEL = { exposed:'Exposed', testing:'Testing rule', failed:'Exam failed, narrowing', verified:'Exam passed', live:'Protected, live', retired:'Rule retired' }
// Living shield: its look is a pure function of the real application state (store.shield).
export function Shield({ state='exposed', size=150 }) {
  return <figure className={'shield ' + state} style={{ width:size }} aria-label={'Shield state: ' + LABEL[state]}>
    <svg viewBox="0 0 120 140" role="img" aria-hidden="true">
      <defs><clipPath id="sc"><path d="M60 8 16 24v42c0 32 20 56 44 66 24-10 44-34 44-66V24z"/></clipPath></defs>
      <path className="sh-fill" d="M60 8 16 24v42c0 32 20 56 44 66 24-10 44-34 44-66V24z"/>
      <g clipPath="url(#sc)"><rect className="sh-scan" x="0" y="0" width="120" height="14"/></g>
      <path className="sh-line" pathLength="1" d="M60 8 16 24v42c0 32 20 56 44 66 24-10 44-34 44-66V24z"/>
      <path className="sh-mark" d="M45 52h30M45 70h24M45 52v36" fill="none"/>
      <path className="sh-hit" d="M6 40l22 10M4 60l22 4M8 80l20-8"/>
    </svg><figcaption>{LABEL[state]}</figcaption></figure>
}

// Connection / data-source banner: always says whether results are real or simulated.
export function ConnBar({ f }) {
  if (f.conn === 'checking') return <div className="connbar" role="status">Connecting to the API at <span className="mono">{f.API}</span></div>
  if (f.conn === 'down') return <div className="connbar bad" role="alert"><span><b>API unreachable</b> at <span className="mono">{f.API}</span>{f.lastError ? ` (${f.lastError})` : ''}. Nothing is being faked. Start the backend, then retry.</span>
    <span className="row"><button className="btn sm ghost" onClick={f.connect}>Retry</button><button className="btn sm ghost" onClick={f.useOffline}>Use offline demo (simulated)</button></span></div>
  if (f.conn === 'offline') return <div className="connbar warn" role="status"><span><b>OFFLINE DEMO.</b> Every result on screen is a simulated fixture, not a security result.</span><button className="btn sm ghost" onClick={f.connect}>Try the API</button></div>
  return <div className="connbar ok" role="status"><span><b>{f.kind === 'stand-in' ? 'Connected to the STAND-IN backend.' : 'Connected to the FixFort API.'}</b> {f.kind === 'stand-in' ? 'Real clinic requests and exams; the shield is a regex filter and proposals are fixed (no LLM, not ModSecurity).' : 'Data shown comes from the API.'}</span><span className="mono">{f.API}</span></div>
}
