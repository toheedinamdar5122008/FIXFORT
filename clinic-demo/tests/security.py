"""Checks that the intentional vulnerabilities exist ONLY in vulnerable mode and that fixed mode really fixes them. Run: python tests/security.py"""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import make_app
fails = []
def check(n, c): print(('PASS ' if c else 'FAIL ') + n); c or fails.append(n)
v, f = make_app('vulnerable').test_client(), make_app('fixed').test_client()
sqli = {'username': "' OR 1=1 --", 'password': 'x'}
check('vulnerable: SQLi bypass works (intended demo flaw)', 'Welcome' in v.post('/login', data=sqli).get_data(as_text=True))
check('fixed: SQLi bypass has no effect', 'Welcome' not in f.post('/login', data=sqli).get_data(as_text=True))
check('fixed: stacked-query attempt does not error', f.post('/login', data={'username': "x'; DROP TABLE users; --", 'password': 'x'}).status_code == 200)
xss = '<script>alert(1)</script>'
check('vulnerable: XSS rendered unescaped (intended demo flaw)', xss in v.post('/comment', data={'text': xss}).get_data(as_text=True))
check('fixed: XSS payload is escaped', xss not in f.post('/comment', data={'text': xss}).get_data(as_text=True) and '&lt;script&gt;' in f.get('/comment').get_data(as_text=True))
check("fixed: O'Brien still logs in", "Welcome O&#39;Brien" in f.post('/login', data={'username': "O'Brien", 'password': 'obrienpass'}).get_data(as_text=True))
check('health endpoint reports mode and no secrets', v.get('/__health').json == {'app': 'greenfield-clinic', 'mode': 'vulnerable'} and f.get('/__health').json['mode'] == 'fixed')
check('health CORS only for the dashboard origin', v.get('/__health', headers={'Origin': 'http://localhost:5173'}).headers.get('Access-Control-Allow-Origin') == 'http://localhost:5173' and 'Access-Control-Allow-Origin' not in v.get('/__health', headers={'Origin': 'http://evil.example'}).headers and 'Access-Control-Allow-Origin' not in v.get('/', headers={'Origin': 'http://localhost:5173'}).headers)
try: make_app('Fixed'); bad_mode = False
except ValueError: bad_mode = True
check('invalid MODE is rejected instead of running unlabelled', bad_mode)
check('oversized request body is refused (413)', f.post('/comment', data={'text': 'x' * 70000}).status_code == 413)
check('a long legitimate comment (2000 chars) still works', f.post('/comment', data={'text': 'long ' * 400}).status_code == 200)
print('%d failure(s)' % len(fails)); sys.exit(1 if fails else 0)
