"""Intentionally vulnerable clinic portal. LOCAL EDUCATIONAL DEMO ONLY. Demo data, no real people.
Run: MODE=vulnerable python app.py   or   MODE=fixed python app.py"""
import os, re, sqlite3
from flask import Flask, request, render_template, jsonify
MODE = os.environ.get('MODE', 'vulnerable')
# PHP2Shell (CVE-2026-109618/109619) exploit payloads. Detection only; nothing runs.
_PHP_RCE = re.compile(r"(<\?)|(system\s*\()|(passthru\s*\()|(shell_exec)|(\bexec\s*\()"
                      r"|(popen\s*\()|(\$_(get|post|request|server|files))|(/bin/(sh|bash))"
                      r"|(\$\()|(\x60[^\x60]*\x60)", re.IGNORECASE)
ORIGINS = os.environ.get('FF_CORS', 'http://localhost:5173,http://127.0.0.1:5173').split(',')
_LOCAL_ORIGIN = re.compile(r'^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?$', re.IGNORECASE)
def _allow_origin(o):
    return bool(o) and (o in ORIGINS or _LOCAL_ORIGIN.match(o) is not None)
USERS = [('admin','adminpass'),('alice','alicepass'),("O'Brien",'obrienpass'),("D'Souza",'dsouzapass'),('Anne-Marie','annepass'),('sam@clinic.test','sampass')]

def make_app(mode=None):
    mode = mode or MODE
    if mode not in ('vulnerable', 'fixed'): raise ValueError(f"MODE must be 'vulnerable' or 'fixed', got {mode!r}")   # a typo must not silently run as 'fixed' while the label says otherwise
    app = Flask(__name__); app.config['MODE'] = mode; app.config['MAX_CONTENT_LENGTH'] = 64 * 1024   # oversize request bodies get 413
    db = sqlite3.connect(':memory:', check_same_thread=False)
    db.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    db.execute('CREATE TABLE comments(id INTEGER PRIMARY KEY, text TEXT)')
    db.executemany('INSERT INTO users(username,password) VALUES(?,?)', USERS); db.commit()
    ctx = lambda **k: dict(mode=app.config['MODE'], **k)
    def _upload_page(result=None, tone=None): return render_template('upload.html', **ctx(result=result, tone=tone))

    @app.get('/__health')
    def health(): return jsonify(app='greenfield-clinic', mode=app.config['MODE'])   # real health check for the dashboard (reports the code mode, NOT protection status)
    @app.after_request
    def cors(r):   # lets the dashboard read /__health only; no credentials are ever shared
        o = request.headers.get('Origin')
        if _allow_origin(o) and request.path == '/__health': r.headers['Access-Control-Allow-Origin'] = o
        return r

    @app.get('/')
    def home(): return render_template('home.html', **ctx())
    @app.get('/about')
    def about(): return render_template('about.html', **ctx())
    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'GET': return render_template('login.html', **ctx(msg=''))
        u_raw, p = request.form.get('username',''), request.form.get('password','')
        u = u_raw
        try:
            if app.config['MODE'] == 'vulnerable':   # VULNERABLE: string concatenation (intentional)
                # Exact legitimate names (e.g. O'Brien) are quoted so they work; any other input is concatenated raw.
                if u in [x[0] for x in USERS]: u = u.replace("'", "''")
                row = db.execute(f"SELECT id, username, password FROM users WHERE username='{u}' AND password='{p}'").fetchone()
            else:                                    # FIXED: parameterised query
                row = db.execute("SELECT id, username, password FROM users WHERE username=? AND password=?", (u, p)).fetchone()
        except sqlite3.Error: return render_template('login.html', **ctx(msg='Server error')), 500
        if row:
            legit = (u_raw, p) in USERS                       # a real credential pair?
            # A login that succeeds without a valid pair is an injection bypass — show it.
            return render_template('login.html', **ctx(user=row[1], breach=(not legit), msg=''))
        return render_template('login.html', **ctx(msg='Invalid username or password'))
    @app.route('/comment', methods=['GET','POST'])
    def comment():
        if request.method == 'POST':
            db.execute('INSERT INTO comments(text) VALUES(?)', (request.form.get('text',''),)); db.commit()
        rows = [r[0] for r in db.execute('SELECT text FROM comments ORDER BY id DESC')]
        return render_template('comments.html', **ctx(comments=rows))
    @app.route('/upload.php', methods=['GET','POST'])
    def upload_php():
        # Stand-in for a PHP upload endpoint vulnerable to PHP2Shell. SAFE: nothing
        # is executed. Vulnerable mode reports an exploit WOULD run; fixed does not.
        if request.method == 'POST':
            note = request.form.get('note', '')
            is_exploit = bool(_PHP_RCE.search(note))
            if app.config['MODE'] == 'vulnerable':
                if is_exploit:
                    return _upload_page('RCE-SIMULATED: this payload would execute on the server — PHP2Shell (CVE-2026-109618). Nothing was actually run.', 'breach')
                return _upload_page(f'Upload received: {note}', 'ok')
            if is_exploit:
                return _upload_page('Upload rejected: unsafe content blocked by the patched runtime.', 'warn')
            return _upload_page(f'Upload received: {note}', 'ok')
        return _upload_page()
    app.reset_comments = lambda: (db.execute('DELETE FROM comments'), db.commit())  # used by the exam to isolate tests
    return app

if __name__ == '__main__':
    # Intentionally vulnerable in MODE=vulnerable: bind to loopback ONLY. Never expose this app to a network.
    host = os.environ.get('FF_HOST', '127.0.0.1')
    if MODE == 'vulnerable' and host not in ('127.0.0.1', 'localhost', '::1'): raise SystemExit('Refusing to serve the vulnerable clinic on a non-loopback address.')
    if MODE == 'vulnerable': print('WARNING: intentionally vulnerable demo app, local use only.')
    try: application = make_app()
    except ValueError as e: raise SystemExit(str(e))
    application.run(host=host, port=5000)
