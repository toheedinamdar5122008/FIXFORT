"""End-to-end test of the stand-in backend + clinic. Run: python test_backend.py  (exits non-zero on failure)."""
import os, time; os.environ['FF_PACE'] = '0'
import server as S
c = S.api.test_client(); fails = []
def check(name, cond): print(('PASS ' if cond else 'FAIL ') + name); cond or fails.append(name)
def wait(fid):
    for _ in range(100):
        s = c.get(f'/status/{fid}').json
        if s['finding']['status'] != 'PROTECTING': return s
        time.sleep(.1)
c.post('/reset')
check('approve blocked before protect', c.post('/approve/F-001').status_code == 409)
a = c.post('/attack/sqli').json; check('SQLi works on unprotected vulnerable app', a['worked'] is True and a['outcome'] == 'allowed')
c.post('/protect/F-001'); check('duplicate protect rejected', c.post('/protect/F-001').status_code == 409)
s = wait('F-001'); at = s['attempts']
check('two attempts', len(at) == 2 and s['finding']['status'] == 'TESTED')
check('attempt 1 (strict) failed and blocked O\'Brien', not at[0]['passed'] and any("O'Brien" in f['name'] or 'Brien' in f['name'] for f in at[0]['failures']) and at[0]['attacks_blocked'] == 5)
check('attempt 2 (precise) passed 5/5 and 20/20', at[1]['passed'] and (at[1]['attacks_blocked'], at[1]['users_ok'], at[1]['users_total']) == (5, 20, 20))
print('  attempt1 users_ok =', at[0]['users_ok'], '/', at[0]['users_total'])
check('approve works once passed', c.post('/approve/F-001').status_code == 200)
b = c.post('/attack/sqli').json; check('SQLi blocked after approval', b['outcome'] == 'blocked' and b['rule_id'])
o = c.post('/attack/obrien').json; check("O'Brien still logs in through the shield", o['outcome'] == 'allowed' and o['ok_user'])
v = c.post('/verify-fix/F-001').json; check('verify fails while app is vulnerable, rule stays', v['ok'] is False and c.get('/status/F-001').json['finding']['status'] == 'LIVE' and 'still works' in v['message'])
check('SQLi still blocked after failed verify', c.post('/attack/sqli').json['outcome'] == 'blocked')
c.post('/demo/mode', json={'mode': 'fixed'}); v = c.post('/verify-fix/F-001').json
check('verify passes in fixed mode and retires', v['ok'] and v['retired'] and c.get('/status/F-001').json['finding']['status'] == 'RETIRED')
check('fixed app: SQLi has no effect', c.post('/attack/sqli').json['worked'] is False)
cert = c.get('/certificate/F-001').json; check('certificate has timestamps + mttp', cert['deployment']['retired_at'] and cert['mttp_seconds'] is not None)
check('events recorded', len(c.get('/events').json) >= 5 and len(c.get('/events?since=3').json) == len(S.EVENTS) - 3)
c.post('/reset'); c.post('/protect/F-002'); s = wait('F-002'); at = s['attempts']
check('XSS: strict fails on "5 < 6", precise passes 5/5 20/20', not at[0]['passed'] and at[1]['passed'] and at[1]['users_ok'] == 20)
check('rollback only when LIVE', c.post('/rollback/F-002').status_code == 409); c.post('/approve/F-002')
check('XSS blocked live, "5 < 6" allowed', c.post('/attack/xss').json['outcome'] == 'blocked' and c.post('/attack/comment_5_lt_6').json['outcome'] == 'allowed')
check('rollback re-exposes', c.post('/rollback/F-002').status_code == 200 and c.post('/attack/xss').json['worked'] is True)

# ---- added: validation, safety, health, reset-race cases ----
c.post('/reset')
check('clinic health endpoint reports mode', S.live_app.test_client().get('/__health').json == {'app': 'greenfield-clinic', 'mode': 'vulnerable'})
n = len(S.EVENTS); import werkzeug.test as _wt; _wt.Client(S.live).get('/__health'); check('health probes are not logged as traffic', len(S.EVENTS) == n)
check('unknown finding -> 404', c.get('/status/F-999').status_code == 404 and c.post('/protect/F-999').status_code == 404 and c.get('/certificate/F-999').status_code == 404)
check('unknown attack name -> 404', c.post('/attack/nope').status_code == 404)
check('invalid mode -> 400', c.post('/demo/mode', json={'mode': 'evil'}).status_code == 400)
check('invalid finding rejected (bad type, missing fields)', c.post('/findings', json={'id': 'X'}).status_code == 400 and c.post('/findings', json=dict(id='F-009', target='/login', parameter='u', type='rce', severity='high', description='x')).status_code == 400)
check('duplicate finding rejected', c.post('/findings', json=dict(id='F-001', target='/login', parameter='username', type='sqli', severity='high', description='x')).status_code == 409)
check('valid finding imported', c.post('/findings', json=dict(id='F-003', target='/login', parameter='username', type='sqli', severity='low', description='imported')).status_code == 201)
check('verify/rollback refused when not LIVE', c.post('/verify-fix/F-001').status_code == 409 and c.post('/rollback/F-001').status_code == 409)
cert0 = c.get('/certificate/F-001').json; check('certificate for an unprotected finding has no deployment and no MTTP', cert0['deployment'] is None and cert0['mttp_seconds'] is None and cert0['status'] == 'NEW')
c.post('/attack/sqli'); c.post('/login-probe') ; r = S.live_client.post('/login', data={'username': 'alice', 'password': 'alicepass'})
check('passwords never appear in the event log', not any('alicepass' in str(e) for e in S.EVENTS))
c.post('/protect/F-001'); c.post('/reset'); time.sleep(.5)
check('reset during a running Practice Room leaves a clean state', c.get('/status/F-001').json['attempts'] == [] and c.get('/status/F-001').json['finding']['status'] == 'NEW')
c.post('/protect/F-001'); wait('F-001'); c.post('/approve/F-001'); c.post('/rollback/F-001'); c.post('/protect/F-001'); s2 = wait('F-001')
check('re-protect after rollback works and passes again', s2['finding']['status'] == 'TESTED' and s2['attempts'][-1]['passed'])
c.post('/reset')

# ---- added in final verification: malformed input must give JSON 4xx, never a 500/HTML page ----
c.post('/reset')
check('events?since=abc -> 400 JSON', c.get('/events?since=abc').status_code == 400 and 'error' in c.get('/events?since=abc').json)
check('non-object JSON bodies are rejected cleanly', c.post('/demo/mode', json=['fixed']).status_code == 400 and c.post('/findings', json=[1, 2]).status_code == 400)
check('malformed JSON body -> 400', c.post('/demo/mode', data='{not json', content_type='application/json').status_code == 400)
bad = dict(id='F-010', target='/login', parameter='username', type='sqli', severity='high', description='x')
check('finding with quote/injection in parameter rejected', c.post('/findings', json={**bad, 'parameter': 'u" chain,id:1'}).status_code == 400)
check('finding with non-path target rejected', c.post('/findings', json={**bad, 'target': 'login'}).status_code == 400 and c.post('/findings', json={**bad, 'id': 'F 10'}).status_code == 400)
check('finding with bad severity or non-string field rejected', c.post('/findings', json={**bad, 'severity': 'urgent'}).status_code == 400 and c.post('/findings', json={**bad, 'description': 5}).status_code == 400)
pf = c.open('/findings', method='OPTIONS', headers={'Origin': 'http://localhost:5173'}); check('CORS preflight allows the dashboard origin only', pf.status_code == 204 and pf.headers.get('Access-Control-Allow-Origin') == 'http://localhost:5173' and 'Access-Control-Allow-Origin' not in c.open('/findings', method='OPTIONS', headers={'Origin': 'http://evil.example'}).headers)
check('unknown route -> JSON 404', c.get('/nope').status_code == 404 and c.get('/nope').is_json)
check('imported finding keeps only whitelisted fields', 'evil' not in c.post('/findings', json={**bad, 'evil': '<x>'}).json)
c.post('/reset')
print('\n%d failure(s)' % len(fails)); raise SystemExit(1 if fails else 0)
