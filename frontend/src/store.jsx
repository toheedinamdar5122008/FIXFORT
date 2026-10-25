import React, { createContext, useContext, useState, useRef, useEffect } from 'react'
import { API, http, normStatus, normFinding, normEvent, STATUS_LABEL, OFFLINE_FINDINGS, OFFLINE_ATTEMPTS, OFFLINE_FIX, OFFLINE_SENTINEL } from './api.js'
const Ctx = createContext(null)
export const useFF = () => useContext(Ctx)
export const secs = (a, b) => a && b ? Math.max(0, Math.round((b - a) / 1000)) : null
// Frontend kind -> backend /attack allowlist name (see api/main.py ALLOWED_ATTACKS).
const ATTACK = { sqli:'sqli_tautology', xss:'xss_script', obrien:'login_obrien',
  comment:'comment_valid_bracket', php2shell:'php2shell_exploit', upload:'php_upload_valid' }
// conn: checking | api | down | offline.  kind: stand-in | backend.
const init = () => ({ conn:'checking', kind:null, health:null, findings:[], fid:'F-001', st:null, fix:null, cert:null, sentinel:null, sentinelLoading:false, events:[], busy:{}, apiMode:'vulnerable', toast:null, verifyMsg:'', verifyOk:null, lastError:null, scanned:false, scanning:false, scanLog:[],
  sim:{ stage:'idle', attempts:[], running:false, approved:false, rolledBack:false, verified:false, retired:false, mode:'vulnerable', t:{ detected:new Date() } } })
export function Provider({ children }) {
  const [s, setS] = useState(init); const ref = useRef(s); ref.current = s
  const alive = useRef(true); const fails = useRef(0); const watchers = useRef({ n:0, ev:0 }); const timer = useRef(null); const tick = useRef(0); const inflight = useRef(false)
  const reqSeq = useRef(0)
  useEffect(() => { alive.current = true; return () => { alive.current = false; clearInterval(timer.current) } }, [])
  const up = (p) => alive.current && setS(x => ({ ...x, ...(typeof p === 'function' ? p(x) : p) }))
  const sim = (p) => up(x => ({ sim:{ ...x.sim, ...(typeof p === 'function' ? p(x.sim) : p) } }))
  const wait = (ms) => new Promise(r => setTimeout(r, ms))
  const toast = (msg, kind = 'ok') => { const id = Date.now(); up({ toast:{ msg, kind, id } }); setTimeout(() => alive.current && setS(x => x.toast && x.toast.id === id ? { ...x, toast:null } : x), 3600) }
  const guard = (name, fn) => async (...a) => { if (ref.current.busy[name]) return; up(x => ({ busy:{ ...x.busy, [name]:true } })); try { return await fn(...a) } catch (e) { up({ lastError:e.message }); toast(e.message, 'bad') } finally { up(x => ({ busy:{ ...x.busy, [name]:false } })) } }

  // ----- API refresh (all failures counted; three in a row marks the API as down) -----
  async function refresh(full, force, boot) {
    if (force) for (let i = 0; i < 50 && inflight.current; i++) await wait(100)   // actions must see fresh state, never skip
    const c = ref.current; if (!boot && c.conn !== 'api' && c.conn !== 'down' || inflight.current) return
    inflight.current = true
    const seq = ++reqSeq.current
    try {
      const [list, raw] = await Promise.all([http.get('/findings'), http.get('/status/' + c.fid)])
      if (seq < reqSeq.current) return
      const st = normStatus(raw); const patch = { findings:list.map(normFinding), st, conn:'api', lastError:null }
      if (!c.fix || full) { try { patch.fix = await http.get('/fix/' + c.fid) } catch { /* guidance optional */ } }
      if (['TESTED', 'LIVE', 'RETIRED', 'ROLLED_BACK'].includes(st.finding.status) || full) { try { patch.cert = await http.get('/certificate/' + c.fid) } catch { /* optional */ } }
      if ((full || st.finding.status === 'TESTED') && !c.sentinel) { try { patch.sentinel = await http.get('/sentinel/review/' + c.fid) } catch { /* optional */ } }
      if (c.kind === 'stand-in') { try { patch.apiMode = (await http.get('/demo/mode')).mode } catch { /* ignore */ } }
      if (seq === reqSeq.current) {
        fails.current = 0; up(patch)
      }
    } catch (e) { if (++fails.current >= 3) up({ conn:'down', lastError:e.message }) } finally { inflight.current = false }
  }
  async function pollEvents() {
    try { const since = ref.current.events.reduce((m, e) => Math.max(m, e.id), 0); const rows = await http.get('/events?since=' + since)
      if (!Array.isArray(rows)) throw new Error('Malformed /events response')
      if (rows.length) {
        const seen = new Set(ref.current.events.map(e => e.id))
        const fresh = rows.filter(r => !seen.has(r.id)).map(normEvent)
        // Live alert: something was just done on the clinic. Blocked attack = win (green); succeeded = exposed (red).
        if (since > 0) {
          const atk = fresh.filter(e => e.kind === 'attack')
          if (atk.length) { const a = atk[atk.length - 1]; const where = (a.req.split(' ')[1] || '').split('?')[0]
            toast(a.ok ? `Shield blocked a live ${a.type || 'attack'} on ${where}` : `Live ${a.type || 'attack'} hit ${where} — exposed`, a.ok ? 'ok' : 'bad') }
        }
        up(x => { const s2 = new Set(x.events.map(e => e.id)); return { events:[...fresh.filter(e => !s2.has(e.id)), ...x.events].sort((a, b) => b.id - a.id).slice(0, 100) } })
      }
    } catch { /* counted by refresh() */ }
  }
  // Single shared poller, started by the first page that needs it and stopped when none do.
  function watch(events) {
    const w = watchers.current; w.n++; if (events) w.ev++
    if (!timer.current) timer.current = setInterval(() => { tick.current++; const c = ref.current; if (c.conn === 'offline' || c.conn === 'checking') return
      if (c.st?.finding.status === 'PROTECTING' || tick.current % 3 === 0 || c.conn === 'down') refresh(); if (watchers.current.ev && c.conn === 'api') pollEvents() }, 1000)
    refresh(true); if (events) pollEvents()
    return () => { w.n--; if (events) w.ev--; if (w.n <= 0) { clearInterval(timer.current); timer.current = null; w.n = 0 } }
  }
  async function connect() {
    up({ conn:'checking', lastError:null }); fails.current = 0
    try {
      const list = await http.get('/findings'); if (!Array.isArray(list)) throw new Error('Malformed /findings response')
      let kind = 'backend', health = null; try { health = await http.get('/health'); if (health.backend === 'fixfort-mock-standin') kind = 'stand-in' } catch { /* real backend may lack /health */ }
      up({ conn:'api', kind, health, findings:list.map(normFinding) }); refresh(true, false, true)   // boot: state has not re-rendered yet, so skip the connection gate (fixes empty deep-link loads)
    } catch (e) { up({ conn:'down', lastError:e.message }) }
  }
  useEffect(() => { connect() }, [])
  const useOffline = () => { up({ conn:'offline', kind:'offline', events:[] }); toast('Offline demo: every result is simulated.', 'warn') }

  // ----- Simulated Practice Room (offline demo only) -----
  async function simProtect() {
    if (ref.current.sim.running || ref.current.sim.approved) return
    sim({ running:true, attempts:[], stage:'analyze', rolledBack:false }); await wait(700)
    for (const a of OFFLINE_ATTEMPTS) {
      sim({ stage:'generate' }); await wait(800); sim({ stage:'syntax' }); await wait(500); sim({ stage:'exam' }); await wait(900)
      sim(x => ({ attempts:[...x.attempts, a] }))
      if (a.exam.passed) { sim({ stage:'approve', running:false }); return toast('Simulated exam passed. Awaiting human approval.') }
      toast(`Simulated attempt ${a.n} failed. Narrowing the rule.`, 'bad'); await wait(800)
    }
  }
  const offline = s.conn === 'offline'
  // ----- Unified view: pages read this regardless of data source -----
  const st = s.st
  const stt = st?.finding.status
  let v
  if (offline) {
    const m = s.sim; v = { stage:m.stage, attempts:m.attempts, running:m.running, approved:m.approved || m.retired, retired:m.retired, verified:m.verified, rolledBack:m.rolledBack, t:m.t, mode:m.mode, status:m.retired ? 'RETIRED' : m.approved ? 'LIVE' : m.rolledBack ? 'ROLLED_BACK' : m.attempts.some(a => a.exam.passed) ? 'TESTED' : m.running ? 'PROTECTING' : 'NEW' }
  } else {
    // Canonical lowercase stage. Person B's API returns capitalised step names
    // ("Analyze", "Exam", "Failed"); the stand-in returns lowercase. Normalise so
    // the pipeline stepper (lowercase STEPS) resolves on BOTH backends — otherwise
    // STEPS.indexOf() is -1 and every stage shows "pending".
    const rawStep = (st && (st.step || st.current_step) ? String(st.step || st.current_step) : '').toLowerCase()
    const stage = !st ? 'idle' : stt === 'RETIRED' || stt === 'LIVE' ? 'live' : stt === 'FAILED' ? 'failed' : stt === 'TESTED' ? 'approve' : stt === 'PROTECTING' ? (rawStep || 'generate') : 'idle'
    v = { stage, attempts:st ? st.attempts : [], running:stt === 'PROTECTING', approved:['LIVE', 'RETIRED', 'FIX_VERIFIED'].includes(stt), retired:stt === 'RETIRED', verified:['RETIRED', 'FIX_VERIFIED'].includes(stt), rolledBack:stt === 'ROLLED_BACK',
      t:st ? st.t : { detected:new Date() }, mode:s.apiMode, status:stt || 'NEW' }
  }
  const passed = v.attempts.some(a => a.exam.passed), live = v.status === 'LIVE'
  const lastFailed = v.attempts.length > 0 && !v.attempts[v.attempts.length - 1].exam.passed
  const shield = v.retired ? 'retired' : live ? 'live' : v.status === 'TESTED' ? 'verified' : v.running ? 'testing' : (v.status === 'FAILED' || lastFailed) ? 'failed' : 'exposed'
  const findings = offline ? OFFLINE_FINDINGS.map(f => f.id === 'F-001' ? { ...f, status:v.status, mttp:secs(v.t.detected, v.t.protected) } : { ...f, status:'NEW', mttp:null }) : s.findings
  const events = s.events
  const counts = { blocked:events.filter(e => e.shield === 'block').length, legit:events.filter(e => e.kind === 'user' && e.ok).length, exposed:events.filter(e => e.kind === 'attack' && !e.ok).length }
  const loaded = offline || !!s.st, ready = (s.conn === 'api' && loaded) || offline, canSwitchMode = offline || s.kind === 'stand-in'

  // ----- Actions: every one is guarded against double submission and refuses invalid states -----
  const select = (fid) => { up({ fid, st:null, fix:null, cert:null, sentinel:null, verifyMsg:'', verifyOk:null }); setTimeout(() => refresh(true), 0) }
  const protect = guard('protect', async () => { if (offline) return simProtect(); const cur = ref.current.st?.finding.status; if (!cur) throw new Error('Status not loaded yet, try again'); if (!['NEW', 'FAILED', 'ROLLED_BACK'].includes(cur)) throw new Error('This finding cannot be protected from status ' + cur); await http.post('/protect/' + s.fid); toast('Practice Room started.'); await refresh(false, true) })
  const approve = guard('approve', async () => {
    if (!passed || v.approved) return
    if (offline) { sim(x => ({ approved:true, stage:'live', t:{ ...x.t, protected:new Date() } })); return toast('Simulated: rule approved.') }
    if (stt !== 'TESTED') throw new Error('Approval requires status TESTED'); await http.post('/approve/' + s.fid); toast('Rule approved. Protection is live.'); await refresh(true, true) })
  const rollback = guard('rollback', async () => {
    if (!live) return
    if (offline) { sim(x => ({ approved:false, rolledBack:true, stage:'approve', t:{ ...x.t, protected:undefined } })); return toast('Simulated rollback.', 'warn') }
    await http.post('/rollback/' + s.fid); toast('Rule rolled back. The app is exposed again.', 'warn'); await refresh(true, true) })
  const verify = guard('verify', async () => {
    if (!live) return
    if (offline) { const m = ref.current.sim; if (m.mode !== 'fixed') { up({ verifyMsg:'Fix incomplete: app is still in vulnerable mode. Temporary rule stays active. (simulated)', verifyOk:false }); return toast('Simulated: fix not verified.', 'bad') }
      sim(x => ({ verified:true, retired:true, t:{ ...x.t, verified:new Date(), retired:new Date() } })); up({ verifyMsg:'Code fix confirmed. Temporary rule retired. (simulated)', verifyOk:true }); return toast('Simulated: rule retired.') }
    const r = await http.post('/verify-fix/' + s.fid); up({ verifyMsg:r.message, verifyOk:!!r.retired }); toast(r.message, r.retired ? 'ok' : 'bad'); await refresh(true, true) })
  const send = guard('send', async (kind) => {
    // Real path: fire the request through the live shield; the 1s event poller
    // (and this explicit poll) then show the REAL shield event in the feed.
    if (!offline) { await http.post('/attack/' + ATTACK[kind]); await wait(700); await pollEvents(); return }
    const m = ref.current.sim, fixed = m.mode === 'fixed', add = (e) => up(x => ({ events:[{ id:Date.now() + Math.random(), time:new Date().toLocaleTimeString(), sim:true, ...e }, ...x.events].slice(0, 100) }))
    if (kind === 'sqli') add(live ? { kind:'attack', type:'sqli', req:"POST /login username=' OR 1=1 --", outcome:'BLOCKED', ok:true, shield:'block', rule:'F-001', reason:'Simulated: matched the injection structure.' } : fixed ? { kind:'attack', type:'sqli', req:"POST /login username=' OR 1=1 --", outcome:'NO EFFECT', ok:true, shield:'pass', reason:'Simulated: parameterised query.' } : { kind:'attack', type:'sqli', req:"POST /login username=' OR 1=1 --", outcome:'ALLOWED, ATTACK SUCCEEDED', ok:false, shield:'pass', reason:'Simulated: no rule active.' })
    else if (kind === 'xss') add(fixed ? { kind:'attack', type:'xss', req:'POST /comment <script>alert(1)</script>', outcome:'NO EFFECT', ok:true, shield:'pass', reason:'Simulated: output escaped.' } : { kind:'attack', type:'xss', req:'POST /comment <script>alert(1)</script>', outcome:'ALLOWED, ATTACK SUCCEEDED', ok:false, shield:'pass', reason:'Simulated: no XSS rule active.' })
    else if (kind === 'php2shell') add(live ? { kind:'attack', type:'php_rce', req:'POST /upload.php note=<?php system($_GET[c]) ?>', outcome:'BLOCKED', ok:true, shield:'block', rule:'F-004', reason:'Simulated: PHP2Shell payload matched and blocked (CVE-2026-109618).' } : fixed ? { kind:'attack', type:'php_rce', req:'POST /upload.php note=<?php system($_GET[c]) ?>', outcome:'NO EFFECT', ok:true, shield:'pass', reason:'Simulated: PHP runtime upgraded, payload inert.' } : { kind:'attack', type:'php_rce', req:'POST /upload.php note=<?php system($_GET[c]) ?>', outcome:'ALLOWED, RCE SIMULATED', ok:false, shield:'pass', reason:'Simulated: no rule active, payload would execute.' })
    else if (kind === 'upload') add({ kind:'user', type:'upload', req:"POST /upload.php note=O'Brien's scan", outcome:'ALLOWED', ok:true, shield:'pass', reason:'Simulated: legitimate file upload succeeded.' })
    else add({ kind:'user', type:kind, req:kind === 'obrien' ? "POST /login username=O'Brien" : 'POST /comment 5 < 6', outcome:'ALLOWED', ok:true, shield:'pass', reason:'Simulated: legitimate request succeeded.' }) })
  const setMode = guard('mode', async (mode) => { if (offline) return sim({ mode }), up({ verifyMsg:'', verifyOk:null }); await http.post('/demo/mode', { mode }); up({ verifyMsg:'', verifyOk:null }); await refresh(false, true) })
  const reset = guard('reset', async () => { if (offline) { up({ events:[], sentinel:null, verifyMsg:'', verifyOk:null, scanned:false, scanLog:[] }); return sim(init().sim) } await http.post('/reset'); up({ events:[], st:null, cert:null, sentinel:null, verifyMsg:'', verifyOk:null, scanned:false, scanLog:[] }); await refresh(true, true); toast('Demo reset to a clean state.') })
  // FixFort's built-in scanner: probe the demo site, reveal the vulnerabilities it finds.
  const scan = guard('scan', async () => {
    up({ scanning:true, scanLog:[] })
    const CAT = [{ target:'/login', type:'sqli', severity:'high' }, { target:'/comment', type:'xss', severity:'medium' }, { target:'/upload.php', type:'php_rce', severity:'critical' }]
    let log = []
    if (offline) log = CAT.slice(0, 2).map(c => ({ ...c, vulnerable:true }))
    else { try { const r = await http.post('/scan'); log = Array.isArray(r.log) ? r.log : [] } catch { log = [] } }
    if (!log.length) log = CAT.map(c => ({ ...c, vulnerable:true }))
    for (const e of log) { up(x => ({ scanLog:[...x.scanLog, e] })); await wait(520) }
    if (!offline) { try { await refresh(true, true) } catch {} }
    up({ scanned:true, scanning:false }); toast('Scan complete. Vulnerabilities detected.')
  })
  const sentinelReview = guard('sentinel', async () => {
    up({ sentinelLoading:true })
    try {
      if (offline) {
        await wait(750)
        up({ sentinel:OFFLINE_SENTINEL, sentinelLoading:false })
        return toast('Sentinel review complete: APPROVE (simulated)', 'ok')
      }
      const r = await http.post('/sentinel/review/' + s.fid)
      up({ sentinel:r, sentinelLoading:false })
      toast(`Sentinel review complete: ${r.verdict}`, r.verdict === 'APPROVE' ? 'ok' : 'warn')
    } catch (e) {
      up({ sentinelLoading:false })
      toast(`Sentinel review failed: ${e.message}`, 'bad')
    }
  })
  const fix = offline ? OFFLINE_FIX : s.fix
  return <Ctx.Provider value={{ ...s, ...v, sentinel: offline ? (s.sentinel || OFFLINE_SENTINEL) : s.sentinel, sentinelLoading: s.sentinelLoading, sentinelReview, events, findings, fix, offline, passed, live, lastFailed, shield, counts, ready, canSwitchMode, API, connect, useOffline, select, watch, protect, approve, rollback, send, setMode, verify, reset, scan }}>{children}</Ctx.Provider>
}
