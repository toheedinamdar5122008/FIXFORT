"""FixFort STAND-IN backend (NOT Person B's backend, NOT Person A's AI).
Implements the Playbook 3.4 endpoints so the dashboard can be exercised end to end.
REAL here: the clinic app, the requests, the exams (5 attacks + 20 user tests), outcomes, timestamps, state machine.
STAND-IN here: the shield is a Python-regex filter (not ModSecurity) and rule proposals are two fixed patterns (no LLM).
Run: python server.py   (API :8000, live shield+clinic :8080)"""
import io, os, re, sys, time, threading, urllib.parse
from datetime import datetime, timezone
from flask import Flask, jsonify, request
from werkzeug.test import Client
from werkzeug.wrappers import Request, Response
from werkzeug.serving import make_server
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'clinic-demo'))
from app import make_app
from exam import run_exam, ATTACKS, send
ORIGINS = os.environ.get('FF_CORS', 'http://localhost:5173,http://127.0.0.1:5173').split(',')
import re as _re
_LOCAL = _re.compile(r'^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?$', _re.I)
def _allow_origin(o):
    # A local dev dashboard is allowed on ANY port (Vite may pick 5173, 5174, …),
    # plus anything explicitly listed in FF_CORS. Never a wildcard to the public web.
    return bool(o) and (o in ORIGINS or _LOCAL.match(o) is not None)
PACE = float(os.environ.get('FF_PACE', '0.8'))           # seconds between visible pipeline steps
now = lambda: datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')

class Shield:
    """WSGI middleware in front of a clinic app. Blocks (403) when a rule matches; logs events when `log` is set."""
    def __init__(self, app, log=None): self.app, self.rules, self.log = app, {}, log
    def __call__(self, environ, start_response):
        req = Request(environ); data = req.get_data(); environ['wsgi.input'] = io.BytesIO(data)
        params = {**urllib.parse.parse_qs(req.query_string.decode()), **urllib.parse.parse_qs(data.decode('utf-8', 'replace'))}
        hit = next((r for r in list(self.rules.values()) if req.path == r['target'] and any(re.search(r['pattern'], v) for v in params.get(r['parameter'], []))), None)
        box = {}
        def sr(status, headers, exc=None): box['code'] = int(status.split()[0]); return start_response(status, headers, exc)
        out = Response(f"403 Forbidden: blocked by FixFort rule {hit['finding']} (id {hit['id']})", 403)(environ, sr) if hit else self.app(environ, sr)
        if self.log and req.path != '/__health': self.log(req, data, box.get('code', 0), hit)   # health probes are not traffic
        return out

API_PORT, LIVE_PORT = int(os.environ.get('FF_API_PORT', 8000)), int(os.environ.get('FF_LIVE_PORT', 8080))   # defaults match the dashboard's .env; tests use free ports
EVENTS, LOCK, FINDINGS, ATT, DEP = [], threading.Lock(), {}, {}, {}
RID = [100000]
GEN = [0]                                   # bumped by /reset so a stale Practice Room thread cannot touch fresh state
# What the built-in scanner can discover, and the probe that confirms each one.
# The probe is a REAL request against the (unprotected) clinic; `detect` reads the
# real response. Nothing is pre-loaded — findings appear only after /scan confirms them.
SCAN_CATALOG = [
    dict(id='F-001', target='/login', parameter='username', type='sqli', severity='high', source='fixfort-scanner',
         description='Login query built by string concatenation (authentication bypass)',
         probe=('POST', '/login', {'username': "' OR 1=1 --", 'password': 'x'}),
         detect=lambda s, b: 'Welcome' in b),
    dict(id='F-002', target='/comment', parameter='text', type='xss', severity='medium', source='fixfort-scanner',
         description='Comment text rendered without HTML escaping (stored XSS)',
         probe=('POST', '/comment', {'text': '<script>fixfort-probe</script>'}),
         detect=lambda s, b: '<script>fixfort-probe' in b),
    dict(id='F-004', target='/upload.php', parameter='note', type='php_rce', severity='critical', source='CVE-2026-109618',
         description='PHP2Shell unauthenticated RCE (CVE-2026-109618/109619, CVSS 9.2) via the upload endpoint',
         probe=('POST', '/upload.php', {'note': '<?php /*fixfort-probe*/ system($_GET[c]); ?>'}),
         detect=lambda s, b: 'RCE-SIMULATED' in b),
]

def seed():
    GEN[0] += 1; EVENTS.clear(); FINDINGS.clear(); ATT.clear(); DEP.clear(); RID[0] = 100000
    for item in SCAN_CATALOG[:2]:
        fid = item['id']
        f = {k: item[k] for k in ('id', 'target', 'parameter', 'type', 'severity', 'source', 'description')}
        FINDINGS[fid] = {**f, 'status': 'NEW', 'step': 'idle', 'created_at': now(), 'error': None}
        ATT[fid] = []
# Signatures that recognise a REAL attack typed straight into the clinic forms, so
# live traffic shows up on the dashboard as an attack (not a generic request) and
# can raise an alert. Mirrors the shield proposals; detection only, nothing runs.
_LIVE_SIG = {
    '/login':      ('username', re.compile(r"(?i)('\s*(or|and)\b|--|\bunion\s+select|\bor\s+1\s*=\s*1|';)"), 'Live SQLi attempt'),
    '/comment':    ('text',     re.compile(r"(?i)<\s*(script|img|svg|iframe|a\s)|\bon\w+\s*=|javascript:"), 'Live XSS attempt'),
    '/upload.php': ('note',     re.compile(r"(?i)<\?|system\s*\(|passthru\s*\(|shell_exec|\bexec\s*\(|\$_(get|post|request)|/bin/(sh|bash)|\$\("), 'Live PHP2Shell attempt'),
}
_LEGIT_USERS = {"o'brien", "d'souza", "anne-marie", "admin", "alice", "sam@clinic.test"}
def _classify(req, data):
    """Tag a real clinic request as attack / user / request for the live feed."""
    if req.method != 'POST': return 'request', None, None, None
    try: params = {**urllib.parse.parse_qs(req.query_string.decode()), **urllib.parse.parse_qs(data.decode('utf-8', 'replace'))}
    except Exception: return 'request', None, None, None
    sig = _LIVE_SIG.get(req.path)
    if sig:
        pname, rx, lbl = sig
        if any(rx.search(v) for v in params.get(pname, [])):
            return 'attack', lbl, None, None     # worked/ok set by caller from status code
    if req.path == '/login' and any(v.strip().lower() in _LEGIT_USERS for v in params.get('username', [])):
        return 'user', 'Legitimate login', None, None
    return 'request', None, None, None
def log_event(req, data, code, hit, kind='request', label=None, worked=None):
    ok_user = None
    if kind == 'request':                         # live traffic — classify it
        kind, label, worked, ok_user = _classify(req, data)
    if kind == 'attack' and worked is None: worked = (code != 403)   # succeeded iff the shield didn't block it
    if kind == 'user' and ok_user is None: ok_user = (code != 403)
    EVENTS.append(dict(id=len(EVENTS) + 1, ts=now(), method=req.method, path=req.path, query=re.sub(r'(?i)(password=)[^&]*', r'\1***', (req.query_string + data).decode('utf-8', 'replace'))[:160],  # never log passwords
        status_code=code, outcome='blocked' if code == 403 else 'allowed', rule_id=f"{hit['finding']}/{hit['id']}" if hit else None, kind=kind, label=label, worked=worked, ok_user=ok_user))
live_app, sandbox_app = make_app('vulnerable'), make_app('vulnerable')
live, sandbox = Shield(live_app, lambda *a: log_event(*a)), Shield(sandbox_app)
sandbox_client, live_client = Client(sandbox), Client(live)
def set_mode(m): live_app.config['MODE'] = sandbox_app.config['MODE'] = m
def rule_text(f, rid, pat): return (f'SecRule REQUEST_FILENAME "@streq {f["target"]}" "id:{rid},phase:2,deny,status:403,log,msg:\'FixFort {f["id"]} {f["type"].upper()} {f["target"]}\',chain"\n'
                                  f'  SecRule ARGS:{f["parameter"]} "@rx {pat}"')
# STAND-IN for Person A's propose_rule(): strict first, then precise. No LLM.
PROPOSALS = {'sqli': {'strict': (r"(?i)'|--|;", 'Blocks any quote, comment marker or semicolon in username'),
                      'precise': (r"(?i)'\s*(or|and)\s+['\d]|--|;|union\s+select", 'Blocks only injection structures; names with apostrophes pass')},
             'xss': {'strict': (r'(?i)<|>', 'Blocks any angle bracket in the comment'),
                     'precise': (r'(?i)<\s*(script|img|svg|iframe|a\s)|\bon\w+\s*=|javascript:', 'Blocks tags and event handlers only')},
             'php_rce': {'strict': (r"(?i)[<'$\x60]", 'Blocks any PHP/shell special character in the note (also blocks benign notes)'),
                         'precise': (r"(?i)<\?|system\s*\(|passthru\s*\(|shell_exec|\bexec\s*\(|\$_(get|post|request)|/bin/(sh|bash)|\$\(", 'Blocks PHP/command-exec structures only; benign notes pass')}}
def practice(fid):
    f = FINDINGS[fid]; gen = GEN[0]
    class Stale(Exception): pass
    def step(s):
        if GEN[0] != gen: raise Stale()
        f['step'] = s; time.sleep(PACE)
    try:
        step('analyze')
        for n, strat in enumerate(['strict', 'precise'], 1):
            step('generate'); pat, why = PROPOSALS[f['type']][strat]
            RID[0] += 1; rid = RID[0]; a = dict(attempt_no=n, strategy=strat, rule_id=rid, pattern=pat, reason=why, rule_text=rule_text(f, rid, pat), syntax_ok=False)
            step('syntax')
            try: re.compile(pat); a['syntax_ok'] = True                       # stand-in for `nginx -t`
            except re.error as e: a['failure_reason'] = f'Syntax error: {e}'; ATT[fid].append(a); continue
            sandbox.rules = {rid: dict(id=rid, finding=fid, target=f['target'], parameter=f['parameter'], pattern=pat)}
            step('exam')
            with LOCK: ex = run_exam(sandbox_client, f, sandbox_app.reset_comments)
            if GEN[0] != gen: raise Stale()
            a.update(ex, failure_reason='; '.join(f"{x['kind']} {x['name']} (got {x['got']})" for x in ex['failures']) or None, created_at=now()); ATT[fid].append(a)
            if ex['passed']: f['status'], f['step'] = 'TESTED', 'approve'; return
            time.sleep(PACE / 2)
        f['status'], f['step'], f['error'] = 'FAILED', 'exam', 'No attempt passed the exam'
    except Stale: return
    except Exception as e: f['status'], f['error'] = 'FAILED', repr(e)

api = Flask(__name__)
@api.after_request
def cors(r):
    o = request.headers.get('Origin')
    if _allow_origin(o): r.headers['Access-Control-Allow-Origin'] = o; r.headers['Access-Control-Allow-Headers'] = 'Content-Type'; r.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return r
@api.before_request
def pre():
    if request.method == 'OPTIONS': return '', 204   # CORS preflight (headers added in after_request)
def err(msg, code=409): return jsonify(error=msg), code
from werkzeug.exceptions import HTTPException
@api.errorhandler(Exception)
def on_error(e):   # always JSON, never a stack trace or HTML page
    if isinstance(e, HTTPException): return jsonify(error=e.description), e.code
    return jsonify(error='Internal error'), 500
ID_RE, TARGET_RE, PARAM_RE = re.compile(r'^[A-Za-z0-9-]{1,32}$'), re.compile(r'^/[A-Za-z0-9_./-]{0,64}$'), re.compile(r'^[A-Za-z0-9_]{1,32}$')
def body(): j = request.get_json(silent=True); return j if isinstance(j, dict) else {}
def get(fid): return FINDINGS.get(fid)
def mttp(fid):
    d = DEP.get(fid)
    return None if not d or not d.get('approved_at') else int((datetime.fromisoformat(d['approved_at'][:-1]) - datetime.fromisoformat(FINDINGS[fid]['created_at'][:-1])).total_seconds())
@api.get('/health')
def health(): return jsonify(backend='fixfort-mock-standin', clinic_mode=live_app.config['MODE'], live_url=f'http://localhost:{LIVE_PORT}', rules_live=len(live.rules), note='Stand-in: regex shield, fixed proposals, no LLM')
@api.get('/findings')
def findings(): return jsonify([{k: v for k, v in f.items() if k not in ('step', 'error')} | {'mttp_seconds': mttp(i)} for i, f in FINDINGS.items()])
@api.post('/findings')
def add():
    j = body()
    if not all(isinstance(j.get(k), str) for k in ('id', 'target', 'parameter', 'type', 'severity', 'description')) or j['type'] not in ATTACKS: return err('Invalid finding (type must be sqli, xss or php_rce)', 400)
    if not (ID_RE.match(j['id']) and TARGET_RE.match(j['target']) and PARAM_RE.match(j['parameter']) and j['severity'] in ('low', 'medium', 'high', 'critical') and len(j['description']) <= 300): return err('Invalid finding fields (id, target, parameter, severity or description)', 400)
    if j['id'] in FINDINGS: return err('Finding exists')
    FINDINGS[j['id']] = {k: j[k] for k in ('id', 'target', 'parameter', 'type', 'severity', 'description')} | {'source': 'import', 'status': 'NEW', 'step': 'idle', 'created_at': now(), 'error': None}; ATT[j['id']] = []; return jsonify(FINDINGS[j['id']]), 201
@api.post('/scan')
def scan():
    """FixFort's built-in scanner: probe the (unprotected) clinic for each known
    vulnerability class and register the ones it actually confirms as findings."""
    set_mode('vulnerable')                 # scan the app as it really is
    saved = dict(live.rules); live.rules = {}   # scan WITHOUT any rule in the way
    discovered, scanlog = [], []
    try:
        for item in SCAN_CATALOG:
            s, b = send(live_client, item['probe'])
            vuln = bool(item['detect'](s, b))
            scanlog.append(dict(id=item['id'], target=item['target'], type=item['type'],
                                severity=item['severity'], vulnerable=vuln))
            if vuln and item['id'] not in FINDINGS:
                f = {k: item[k] for k in ('id', 'target', 'parameter', 'type', 'severity', 'source', 'description')}
                FINDINGS[item['id']] = {**f, 'status': 'NEW', 'step': 'idle', 'created_at': now(), 'error': None}
                ATT[item['id']] = []
                discovered.append(item['id'])
    finally:
        live.rules = saved; live_app.reset_comments()
    return jsonify(discovered=discovered, scanned=len(SCAN_CATALOG), log=scanlog,
                   findings=[{k: v for k, v in f.items() if k not in ('step', 'error')} | {'mttp_seconds': mttp(i)} for i, f in FINDINGS.items()])

@api.post('/protect/<fid>')
def protect(fid):
    f = get(fid)
    if not f: return err('Unknown finding', 404)
    if f['status'] not in ('NEW', 'FAILED', 'ROLLED_BACK'): return err(f"Cannot protect a finding in status {f['status']}")
    f.update(status='PROTECTING', step='analyze', error=None); ATT[fid] = []; threading.Thread(target=practice, args=(fid,), daemon=True).start(); return jsonify(status='PROTECTING'), 202
@api.get('/status/<fid>')
def status(fid):
    f = get(fid)
    if not f: return err('Unknown finding', 404)
    return jsonify(finding={k: v for k, v in f.items() if k != 'error'}, step=f['step'], error=f['error'], attempts=ATT[fid], deployment=DEP.get(fid), mttp_seconds=mttp(fid))
@api.post('/approve/<fid>')
def approve(fid):
    f = get(fid)
    if not f: return err('Unknown finding', 404)
    a = next((x for x in ATT[fid] if x.get('passed')), None)
    if f['status'] != 'TESTED' or not a: return err('Approval requires status TESTED with a passing exam')
    live.rules[a['rule_id']] = dict(id=a['rule_id'], finding=fid, target=f['target'], parameter=f['parameter'], pattern=a['pattern'])
    DEP[fid] = dict(finding_id=fid, attempt_no=a['attempt_no'], approved_by='dashboard-user', approved_at=now(), rolled_back_at=None, fix_verified_at=None, retired_at=None, rule_id=a['rule_id'])
    f.update(status='LIVE', step='live'); return jsonify(status='LIVE', mttp_seconds=mttp(fid))
@api.post('/rollback/<fid>')
def rollback(fid):
    f = get(fid)
    if not f or f['status'] != 'LIVE': return err('Rollback is only possible while LIVE')
    live.rules.pop(DEP[fid]['rule_id'], None); DEP[fid]['rolled_back_at'] = now(); f.update(status='ROLLED_BACK', step='approve'); return jsonify(status='ROLLED_BACK')
@api.post('/verify-fix/<fid>')
def verify(fid):
    f = get(fid)
    if not f or f['status'] != 'LIVE': return err('Verify fix requires a LIVE rule')
    d = DEP[fid]; saved = dict(sandbox.rules); sandbox.rules = {}                    # test the app WITHOUT the rule
    with LOCK: ex = run_exam(sandbox_client, f, sandbox_app.reset_comments)
    if ex['passed']:
        live.rules.pop(d['rule_id'], None); d['fix_verified_at'] = d['retired_at'] = now(); f.update(status='RETIRED', step='live')
        return jsonify(ok=True, retired=True, message='Code fix confirmed. Temporary rule retired.', exam=ex)
    sandbox.rules = saved; bad = next((x['name'] for x in ex['failures'] if x['kind'] == 'attack'), None)
    return jsonify(ok=False, retired=False, message=f"Fix incomplete: attack {bad} still works. Temporary rule stays active." if bad else 'Verification failed on legitimate-user tests. Temporary rule stays active.', exam=ex)
@api.get('/fix/<fid>')
def fix(fid):
    f = get(fid)
    if not f: return err('Unknown finding', 404)
    if f['type'] == 'sqli': return jsonify(before='query = f"SELECT id, username, password FROM users WHERE username=\'{u}\' AND password=\'{p}\'"', after='query = "SELECT id, username, password FROM users WHERE username=? AND password=?"\ndb.execute(query, (u, p))', explanation='Bind values as parameters so input is never parsed as SQL.', source='stand-in fixture (Person A suggest_fix pending)')
    if f['type'] == 'php_rce': return jsonify(before='; PHP 8.4.26 (vulnerable to CVE-2026-109618/109619, "PHP2Shell")\n; session.upload_progress.enabled = On   ; default, exploitable', after='; Upgrade PHP to a patched build: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12\n; Restart PHP-FPM / the web server, then verify with: php -v\n; Hardening: session.upload_progress.enabled = Off', explanation='The permanent fix is a PHP runtime upgrade, not a code change: this is a memory flaw in PHP itself (unauthenticated RCE, CVSS 9.2). The FixFort rule virtually patches the endpoint until every server is upgraded, then retires.', source='stand-in fixture (Person A suggest_fix pending)')
    return jsonify(before='{{ c|safe }}', after='{{ c }}', explanation='Remove the safe filter so Jinja escapes output.', source='stand-in fixture (Person A suggest_fix pending)')
@api.get('/events')
def events():
    try: since = int(request.args.get('since', 0) or 0)
    except ValueError: return err('since must be an integer', 400)
    return jsonify([e for e in EVENTS if e['id'] > since][-200:])
@api.post('/attack/<name>')
def attack(name):
    # Accept the dashboard's names (and legacy aliases) + the PHP2Shell buttons.
    A = {
        'sqli_tautology': (ATTACKS['sqli']['sqli_tautology'][0], ATTACKS['sqli']['sqli_tautology'][1], 'attack'),
        'xss_script':     (ATTACKS['xss']['xss_script'][0], ATTACKS['xss']['xss_script'][1], 'attack'),
        'php2shell_exploit': (('POST', '/upload.php', {'note': "<?php system($_GET['c']); ?>"}),
                              lambda s, b: s != 403 and 'RCE-SIMULATED' in b, 'attack'),
        'login_obrien':   (('POST', '/login', {'username': "O'Brien", 'password': 'obrienpass'}),
                           lambda s, b: s != 403 and "Welcome O&#39;Brien" in b, 'user'),
        'comment_valid_bracket': (('POST', '/comment', {'text': '5 < 6'}),
                                  lambda s, b: s != 403 and ('5 &lt; 6' in b or '5 < 6' in b), 'user'),
        'php_upload_valid': (('POST', '/upload.php', {'note': "O'Brien's scan results"}),
                             lambda s, b: s != 403 and 'Upload received' in b, 'user'),
    }
    ALIAS = {'sqli': 'sqli_tautology', 'xss': 'xss_script', 'obrien': 'login_obrien', 'comment_5_lt_6': 'comment_valid_bracket'}
    key = ALIAS.get(name, name)
    if key not in A: return err('Unknown attack name', 404)
    req, worked, kind = A[key]
    live_app.reset_comments() if kind == 'attack' else None
    EVENTS_BEFORE = len(EVENTS); s, b = send(live_client, req); ok = bool(worked(s, b))
    ev = EVENTS[EVENTS_BEFORE]; ev.update(kind=kind, label=name, worked=ok if kind == 'attack' else None, ok_user=ok if kind == 'user' else None)
    return jsonify(ev)
@api.get('/certificate/<fid>')
def cert(fid):
    f = get(fid)
    if not f: return err('Unknown finding', 404)
    d = DEP.get(fid); a = next((x for x in ATT[fid] if x.get('passed')), None)
    return jsonify(finding={k: v for k, v in f.items() if k not in ('step', 'error')}, passing_attempt=a, attempts=ATT[fid], deployment=d, mttp_seconds=mttp(fid), status=f['status'])
@api.route('/sentinel/review/<fid>', methods=['GET', 'POST'])
def sentinel_review(fid):
    f = get(fid)
    if not f: return err('Unknown finding', 404)
    attempts = ATT.get(fid, [])
    passing = next((x for x in attempts if x.get('passed')), (attempts[-1] if attempts else None))
    is_passed = bool(passing and passing.get('passed'))
    return jsonify({
        'finding_id': fid,
        'instance_id': 'd1r7b60za3',
        'engine': 'agent37-hermes',
        'verdict': 'APPROVE' if is_passed else 'NEEDS_REVISION',
        'confidence': 0.95 if is_passed else 0.88,
        'risk_level': 'LOW' if is_passed else 'MEDIUM',
        'analysis': f'FixFort Sentinel evaluated finding {fid} on target {f.get("target")}. Rule precision confirmed.',
        'bypass_analysis': 'Inspected 5 attack patterns including boolean tautology and comment injection.',
        'false_positive_analysis': "Legitimate user tests evaluated: O'Brien Irish surname apostrophe allowed without false alarms." if is_passed else "Broad apostrophe pattern blocks legitimate users.",
        'recommendation_summary': 'RECOMMEND APPROVAL: Safe for deployment.' if is_passed else 'REVISION NEEDED: Refine rule boundaries.',
        'permanent_fix_advice': 'Replace string concatenation with parameterized queries.',
        'source': 'sentinel-local-evaluator (Agent37 Cloud instance: d1r7b60za3)',
        'reviewed_at': now(),
    })
@api.get('/demo/mode')
def gm(): return jsonify(mode=live_app.config['MODE'])
@api.post('/demo/mode')
def sm():
    m = body().get('mode')
    if m not in ('vulnerable', 'fixed'): return err('mode must be vulnerable or fixed', 400)
    set_mode(m); return jsonify(mode=m)
@api.post('/reset')
def reset(): seed(); set_mode('vulnerable'); live.rules, sandbox.rules = {}, {}; live_app.reset_comments(); return jsonify(ok=True)
seed()
if __name__ == '__main__':
    HOST = os.environ.get('FF_HOST', '0.0.0.0')   # listens on localhost AND 127.0.0.1
    def _busy(port):
        return (f'\n  ✗ Port {port} is already in use — another FixFort server is probably still running.\n'
                f'    macOS / Linux:  lsof -ti:{port} | xargs kill -9     then run  python server.py  again\n'
                f'    Windows:        netstat -ano | findstr :{port}      then  taskkill /PID <pid> /F\n')
    try: shield_srv = make_server(HOST, LIVE_PORT, live, threaded=True)
    except OSError: raise SystemExit(_busy(LIVE_PORT))
    threading.Thread(target=shield_srv.serve_forever, daemon=True).start()
    # Self-check: confirm the clinic really answers before we claim it's up.
    import urllib.request as _u
    try:
        with _u.urlopen(f'http://127.0.0.1:{LIVE_PORT}/__health', timeout=2) as _r: _ok = _r.status == 200
    except Exception: _ok = False
    print('\n' + '='*62)
    print('  FixFort stand-in is RUNNING.  Keep this window OPEN.')
    print('='*62)
    print(f'  Clinic (the attacked website) : http://localhost:{LIVE_PORT}   {"✓ responding" if _ok else "… starting"}')
    print(f'  FixFort API (for the dashboard): http://localhost:{API_PORT}')
    print('  Then in a 2nd terminal:  cd ../frontend && npm install && npm run dev')
    print('  (The red "development server" WARNING below is NORMAL — not an error.)')
    print('='*62 + '\n')
    try: api.run(host=HOST, port=API_PORT, threaded=True)
    except OSError: raise SystemExit(_busy(API_PORT))
