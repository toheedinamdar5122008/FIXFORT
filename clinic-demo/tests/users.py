"""20 deterministic legitimate-user tests. Run: python tests/users.py  (from clinic-demo/). Exits non-zero on any failure."""
import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import make_app
def login(u, p, expect): return ('POST', '/login', {'username':u,'password':p}, expect)
def com(t, expect): return ('POST', '/comment', {'text':t}, expect)
TESTS = [login('alice','alicepass','Welcome alice'), login('admin','adminpass','Welcome admin'), login("O'Brien",'obrienpass',"Welcome O&#39;Brien"),
 login("D'Souza",'dsouzapass',"Welcome D&#39;Souza"), login('Anne-Marie','annepass','Welcome Anne-Marie'), login('sam@clinic.test','sampass','Welcome sam@clinic.test'),
 login('alice','wrong','Invalid'), login("O'Brien",'wrong','Invalid'), login('nobody','x','Invalid'),
 com('Great service!','Great service!'), com('5 < 6, loved it','5 &lt; 6, loved it'), com('Use the 2nd floor -- entrance B','2nd floor -- entrance B'),
 com("It's fine",'fine'), com("Dr. O'Brien was kind",'was kind'), com('Lovely staff 😊','Lovely staff'), com('Long text. '*40,'Long text.'),
 ('GET','/',None,'Welcome to the clinic'), ('GET','/comment',None,'Comments'), ('GET','/about',None,'About'), ('GET','/login',None,'Login'),
 ('POST','/upload.php',{'note':'Monthly report attached'},'Upload received'),
 ('POST','/upload.php',{'note':"O'Brien's scan results"},'Upload received'),
 ('POST','/upload.php',{'note':'Costs: 5 < 6 under budget'},'Upload received')]
def name(t): m,path,data,expect=t; return f"{m} {path} {list(data.values())[0][:30] if data else ''}".strip()
def passes(status, body, expect): return status != 403 and (expect in body or expect.replace('&lt;','<') in body)
def run(mode):
    c = make_app(mode).test_client(); ok = 0
    for m, path, data, expect in TESTS:
        r = c.post(path, data=data) if m == 'POST' else c.get(path)
        body = r.get_data(as_text=True)
        # vulnerable mode does not escape comments, so accept the raw form for '<'
        good = passes(r.status_code, body, expect)
        ok += good
        if not good: print('FAIL', m, path, data)
    print(f'{mode}: {ok}/{len(TESTS)} legitimate-user tests passed'); return ok == len(TESTS)
if __name__ == '__main__': sys.exit(0 if all([run('vulnerable'), run('fixed')]) else 1)
