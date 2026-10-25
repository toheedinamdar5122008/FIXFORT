// API layer: the ONLY place that talks to the network. Contract = Playbook section 3.4 (implemented routes documented in CONTRACTS.md).
// VITE_API_URL points at Person B's FastAPI (or the bundled stand-in in ../mock-backend). Nothing here fakes a result:
// failures throw, and the store shows them. Offline fixtures below are used only when the user explicitly picks Offline Demo.
export const API = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '')
export const CLINIC = import.meta.env.VITE_CLINIC_URL || 'http://localhost:8080'
async function req(path, opts = {}, ms = 5000) {
  const c = new AbortController(), id = setTimeout(() => c.abort(), ms)
  try {
    const r = await fetch(API + path, { ...opts, signal: c.signal, headers: { 'Content-Type': 'application/json' } })
    let j = null; try { j = await r.json() } catch { /* non-JSON body */ }
    if (!r.ok) throw new Error((j && (j.error || j.detail)) || `HTTP ${r.status} on ${path}`)
    if (j === null) throw new Error(`Malformed response from ${path}`)
    return j
  } catch (e) { throw new Error(e.name === 'AbortError' ? `Timeout calling ${path}` : e.message || 'Network error') } finally { clearTimeout(id) }
}
// Real clinic health check (GET /__health, CORS-enabled). Reports reachability and the code MODE only. It says nothing about protection.
export async function clinicHealth(ms = 2500) {
  // Works against both the stand-in clinic (/__health, greenfield-clinic) and
  // Person B's victim-app (/health). The embedded iframe shows the site either
  // way; this only lights the status dot and reports the code mode when it can.
  const base = CLINIC.replace(/\/$/, '')
  for (const path of ['/__health', '/health']) {
    const c = new AbortController(), id = setTimeout(() => c.abort(), ms)
    try {
      const r = await fetch(base + path, { signal: c.signal })
      clearTimeout(id)
      if (!r.ok) continue
      const j = await r.json().catch(() => ({}))
      const mode = ['vulnerable', 'fixed'].includes(j.mode) ? j.mode : null
      return { reachable: true, mode }
    } catch { clearTimeout(id) }
  }
  return { reachable: false, error: 'not reachable' }
}
export const http = { get: (p) => req(p), post: (p, b) => req(p, { method: 'POST', body: JSON.stringify(b || {}) }) }

export const STATUS_LABEL = { NEW:'New', PROTECTING:'Protecting', TESTED:'Tested', LIVE:'Live', FIX_VERIFIED:'Fix verified', RETIRED:'Retired', ROLLED_BACK:'Rolled back', FAILED:'Failed' }
const cap = (s) => s ? s[0].toUpperCase() + s.slice(1) : ''
const d = (v) => v ? new Date(v) : null
export function normFinding(r) {
  if (!r || !r.id || !r.status) throw new Error('Malformed finding in API response')
  const TYPE_LABEL = { sqli:'SQLi', xss:'XSS', php_rce:'PHP RCE', forbidden_param:'Forbidden Param' }
  const typeLabel = TYPE_LABEL[r.type] || String(r.type || '').toUpperCase()
  return { id:r.id, target:r.target, parameter:r.parameter, kind:r.type, type:typeLabel, severity:cap(r.severity), description:r.description, status:r.status, created:d(r.created_at), mttp:r.mttp_seconds ?? r.mttp ?? null, source:r.source }
}
// Person B may send the failure list as `failures` (array) or `failure_reason` (JSON string). Accept both.
const parseFailures = (x) => { if (Array.isArray(x)) return x; if (typeof x === 'string' && x.trim()) { try { const j = JSON.parse(x); return Array.isArray(j) ? j : [] } catch { return [] } } return [] }
export const normAttempt = (a) => ({ n:a.attempt_no ?? a.attempt ?? 1, strategy:a.strategy, rule:a.rule_text || a.rule || '', syntaxOk:a.syntax_ok !== false, why:a.reason || (a.proposal && a.proposal.reason) || '', failureReason:a.failure_reason || null,
  exam:{ ab:a.attacks_blocked ?? 0, at:a.attacks_total ?? 0, uo:a.users_ok ?? 0, ut:a.users_total ?? 0, passed:!!a.passed, failures:a.failures ? a.failures : parseFailures(a.failure_reason) } })
export function normStatus(r) {
  if (!r || !r.finding || !Array.isArray(r.attempts)) throw new Error('Malformed /status response')
  const dep = r.deployment || null
  const stepVal = (r.step || r.current_step || 'idle').toLowerCase()
  return { finding:normFinding(r.finding), step:stepVal, error:r.error || null, attempts:r.attempts.map(normAttempt), mttp:r.mttp_seconds ?? r.mttp ?? null,
    t:{ detected:d(r.finding.created_at), protected:dep && !dep.rolled_back_at ? d(dep.approved_at) : null, verified:dep && d(dep.fix_verified_at), retired:dep && d(dep.retired_at) } }
}
// Backend event -> one display model. kind: attack | user | request (traffic typed by hand into the clinic).
export function normEvent(e) {
  const blocked = e.outcome === 'blocked' || e.status_code === 403, rule = e.rule_id || null
  const base = { id:e.id, time:e.ts ? new Date(e.ts).toLocaleTimeString() : '?', req:`${e.method} ${e.path}${e.query ? ' ' + e.query : ''}`, rule, status:e.status_code, sim:false, shield:blocked ? 'block' : 'pass', kind:e.kind || 'request', type:e.label || 'Request' }
  if (base.kind === 'attack') {
    if (blocked) return { ...base, ok:true, outcome:'BLOCKED', reason:`Blocked by rule ${rule}. The request never reached the app.` }
    if (e.worked) return { ...base, ok:false, outcome:'ALLOWED, ATTACK SUCCEEDED', reason:'No rule stopped it and the app is vulnerable: the attack worked.' }
    return { ...base, ok:true, outcome:'NO EFFECT', reason:'The request reached the app but the attack failed: the code is safe (permanent fix).' }
  }
  if (base.kind === 'user') return e.ok_user ? { ...base, ok:true, outcome:'ALLOWED', reason:'Legitimate request succeeded.' } : { ...base, ok:false, outcome:blocked ? 'LEGITIMATE USER BLOCKED' : 'FAILED', reason:blocked ? `Rule ${rule} blocked a legitimate user.` : 'Legitimate request did not return the expected page.' }
  return { ...base, ok:true, outcome:blocked ? 'BLOCKED' : 'ALLOWED', reason:blocked ? `Blocked by rule ${rule}.` : 'Passed through the shield.', kind:'request' }
}
// ---- Offline demo fixtures: SIMULATED. Only used after the user chooses "Use offline demo". ----
export const OFFLINE_FINDINGS = [
 { id:'F-001', target:'/login', parameter:'username', kind:'sqli', type:'SQLi', severity:'High', description:'Login query built by string concatenation', source:'offline-fixture' },
 { id:'F-002', target:'/comment', parameter:'text', kind:'xss', type:'XSS', severity:'Medium', description:'Comments rendered without escaping', source:'offline-fixture' }]
export const OFFLINE_ATTEMPTS = [
 { n:1, strategy:'strict', syntaxOk:true, rule:`SecRule REQUEST_FILENAME "@streq /login" "id:100001,phase:2,deny,status:403,chain"\n  SecRule ARGS:username "@rx (?i)'|--|;"`,
   exam:{ ab:5, at:5, uo:17, ut:20, passed:false, failures:[{kind:'user',name:"login as O'Brien",got:403}] }, why:'Fixture: strict pattern blocks every apostrophe.', failureReason:"user login as O'Brien (got 403)" },
 { n:2, strategy:'precise', syntaxOk:true, rule:`SecRule REQUEST_FILENAME "@streq /login" "id:100002,phase:2,deny,status:403,chain"\n  SecRule ARGS:username "@rx (?i)'\\s*(or|and)\\s+['\\d]|--|;|union\\s+select"`,
   exam:{ ab:5, at:5, uo:20, ut:20, passed:true, failures:[] }, why:'Fixture: precise pattern matches injection structures only.', failureReason:null }]
export const OFFLINE_FIX = { before:`query = f"SELECT id, username, password FROM users WHERE username='{u}' AND password='{p}'"`, after:`query = "SELECT id, username, password FROM users WHERE username=? AND password=?"\ndb.execute(query, (u, p))`, explanation:'Bind values as parameters so input is never parsed as SQL.', source:'offline fixture' }
export const OFFLINE_SENTINEL = {
  finding_id: 'F-001',
  instance_id: 'd1r7b60za3',
  engine: 'agent37-hermes',
  verdict: 'APPROVE',
  confidence: 0.96,
  risk_level: 'LOW',
  analysis: 'Agent37 Hermes evaluated candidate rule #100002 for /login (username). Strategy "precise" demonstrates exact boundary control against SQL syntax injection.',
  bypass_analysis: 'Verified defense across 5 attack vectors including boolean tautology, comment syntax, and union select injection.',
  false_positive_analysis: "Practice Room verified 20 legitimate user cases. Surnames with valid apostrophes (such as O'Brien) execute cleanly without false positive rejection.",
  recommendation_summary: 'RECOMMEND APPROVAL: Rule successfully passed exploit negation and user preservation criteria. Ready for Live Shield deployment.',
  permanent_fix_advice: 'Refactor login authentication to use parameterized prepared statements: db.execute("SELECT id FROM users WHERE username = ? AND password = ?", (user, pwd))',
  source: 'agent37-hermes-cloud (Offline Simulation Fixture)',
  reviewed_at: new Date().toISOString()
}
