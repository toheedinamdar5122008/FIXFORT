"""STAND-IN for Person A's tests/attacks.py + exam.py. Runs REAL requests against the clinic app through the stand-in shield."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'clinic-demo'))
from tests.users import TESTS as _RAW_USER_TESTS, passes, name as user_name
USER_TESTS = _RAW_USER_TESTS[:20]
P = lambda t: ('POST', '/comment', {'text': t})
L = lambda u, p='x': ('POST', '/login', {'username': u, 'password': p})
U = lambda note: ('POST', '/upload.php', {'note': note})
# name -> (request, worked(status, body))
ATTACKS = {
 'sqli': {
  'sqli_tautology': (L("' OR 1=1 --"), lambda s, b: s != 403 and 'Welcome' in b),
  'sqli_admin_comment': (L("admin'--"), lambda s, b: s != 403 and 'Welcome admin' in b),
  'sqli_string_true': (L("' OR 'a'='a", "' OR 'a'='a"), lambda s, b: s != 403 and 'Welcome' in b),
  'sqli_union': (L("' UNION SELECT 1,'admin','x' --"), lambda s, b: s != 403 and 'Welcome' in b),
  'sqli_stacked': (L("x'; DROP TABLE users; --"), lambda s, b: s == 500)},
 'xss': {k: (P(t), (lambda t: lambda s, b: s != 403 and t in b)(t)) for k, t in [
  ('xss_script', '<script>alert(1)</script>'), ('xss_img', '<img src=x onerror=alert(1)>'), ('xss_svg', '<svg onload=alert(1)>'),
  ('xss_js_link', '<a href="javascript:alert(1)">hi</a>'), ('xss_event_case', '<IMG SRC=x OnError=alert(1)>')]},
 # PHP2Shell (CVE-2026-109618/109619): the upload endpoint reports RCE-SIMULATED if a payload would execute.
 'php_rce': {k: (U(n), lambda s, b: s != 403 and 'RCE-SIMULATED' in b) for k, n in [
  ('php_webshell', "<?php system($_GET['c']); ?>"), ('php_passthru', "<?= passthru($_REQUEST['x']) ?>"),
  ('php_shell_exec', "'; echo shell_exec('id'); //"), ('php_cmd_subst', "$(/bin/sh -c id)"),
  ('php_backtick', "`/bin/bash -c id`")]}}
def send(client, req):
    m, path, data = req
    r = client.post(path, data=data) if m == 'POST' else client.get(path)
    return r.status_code, r.get_data(as_text=True)
def run_exam(client, finding, reset):
    """Returns the exam-result contract from Playbook 3.2. Attack counts as blocked if 403 or the 'worked' condition is false."""
    atk = ATTACKS[finding['type']]; failures = []; blocked = 0; ok = 0
    for n, (req, worked) in atk.items():
        reset(); s, b = send(client, req)
        if s == 403 or not worked(s, b): blocked += 1
        else: failures.append({'kind': 'attack', 'name': n, 'got': s})
    for t in USER_TESTS:                                   # all 20 legitimate-user tests run for every exam
        reset(); m, path, data, expect = t
        s, b = send(client, (m, path, data))
        if passes(s, b, expect): ok += 1
        else: failures.append({'kind': 'user', 'name': user_name(t), 'got': s})
    reset()
    return {'attacks_blocked': blocked, 'attacks_total': len(atk), 'users_ok': ok, 'users_total': len(USER_TESTS),
            'passed': blocked == len(atk) and ok == len(USER_TESTS), 'failures': failures}
