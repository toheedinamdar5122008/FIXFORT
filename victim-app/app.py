import os
import re
import sqlite3
from flask import Flask, request, jsonify, render_template_string

# PHP2Shell (CVE-2026-109618/109619) exploit payloads reaching the upload path:
# PHP open tags, command-exec functions, shell invocations. Detection only — the
# endpoint never actually executes anything; it reports "RCE-SIMULATED".
_PHP_RCE = re.compile(
    r"(<\?)|(system\s*\()|(passthru\s*\()|(shell_exec)|(\bexec\s*\()"
    r"|(popen\s*\()|(\$_(get|post|request|server|files))|(/bin/(sh|bash))"
    r"|(\$\()|(\x60[^\x60]*\x60)",
    re.IGNORECASE,
)

app = Flask(__name__)

# Registered staff usernames. Legitimate names that contain an apostrophe
# (O'Brien, D'Souza) must log in without crashing the raw-SQL query, while any
# OTHER input is still concatenated raw so the injection flaw remains.
VALID_USERNAMES = {"admin", "alice", "O'Brien", "D'Souza", "Anne-Marie"}

# Let the FixFort dashboard read /health from any local port (Vite may pick any).
_LOCAL_ORIGIN = re.compile(r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?$", re.IGNORECASE)
@app.after_request
def _cors(resp):
    o = request.headers.get("Origin")
    if o and _LOCAL_ORIGIN.match(o) and request.path == "/health":
        resp.headers["Access-Control-Allow-Origin"] = o
    return resp

# Initial Mode: 'vulnerable' or 'fixed'
CURRENT_MODE = os.environ.get("MODE", "vulnerable").lower()
DB_PATH = os.path.join(os.path.dirname(__file__), "victim.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, full_name TEXT)")
    users = [
        ("admin", "adminpass", "admin"),
        ("alice", "alicepass", "alice"),
        ("O'Brien", "obrienpass", "O'Brien"),
        ("D'Souza", "dsouzapass", "D'Souza"),
        ("Anne-Marie", "mariypass", "Anne-Marie"),
    ]
    cursor.execute("DELETE FROM users")
    cursor.executemany("INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)", users)
    cursor.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, text TEXT)")
    conn.commit()
    conn.close()

init_db()

# Shared dark theme for the clinic form pages (matches the FixFort dashboard).
_CLINIC_CSS = """
:root{--bg:#0B0F17;--s1:#121A26;--bd:#1E2A3A;--tx:#E6EDF3;--mu:#8B98A9;--cy:#22D3EE;--rd:#EF4444}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(900px 500px at 80% -10%,rgba(34,211,238,.08),transparent 60%),var(--bg);color:var(--tx);font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;min-height:100vh}
.bar{display:flex;align-items:center;gap:14px;padding:16px 28px;border-bottom:1px solid var(--bd);background:rgba(11,15,23,.7);flex-wrap:wrap}
.brand{font-weight:700;font-size:18px;color:var(--cy)}
.tag{font:500 11px ui-monospace,monospace;color:var(--mu);border:1px dashed var(--bd);padding:3px 9px;border-radius:6px}
nav{margin-left:auto;display:flex;gap:4px}nav a{color:var(--mu);padding:7px 13px;border-radius:7px;font-size:14px;text-decoration:none}nav a:hover{color:var(--tx);background:#18222F}
.wrap{max-width:620px;margin:40px auto;padding:0 20px}
.card{background:linear-gradient(180deg,#15202f,var(--s1) 70%);border:1px solid var(--bd);border-radius:16px;padding:32px;box-shadow:0 24px 60px -34px rgba(0,0,0,.9)}
h2{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
.lead{color:var(--mu);margin:0 0 22px;font-size:14px}
label{display:block;font:600 12px ui-monospace,monospace;letter-spacing:.06em;text-transform:uppercase;color:var(--mu);margin:16px 0 6px}
input,textarea{display:block;width:100%;background:#0d151f;border:1px solid var(--bd);border-radius:9px;color:var(--tx);padding:12px 14px;font:15px ui-monospace,monospace}
input:focus,textarea:focus{outline:none;border-color:var(--cy);box-shadow:0 0 0 3px rgba(34,211,238,.15)}
textarea{min-height:110px;resize:vertical}
input[type=submit]{margin-top:20px;width:auto;background:var(--cy);color:#04141a;border:0;padding:12px 24px;font:600 15px system-ui,sans-serif;cursor:pointer}
input[type=submit]:hover{filter:brightness(1.08)}
"""
def _shell(title, inner):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>'
            f'<style>{_CLINIC_CSS}</style></head><body>'
            f'<div class="bar"><span class="brand">Greenfield Clinic</span>'
            f'<span class="tag">FixFort target · intentionally vulnerable · local only</span>'
            f'<nav><a href="/">Home</a><a href="/login">Login</a><a href="/comment">Comments</a><a href="/upload.php">Upload</a></nav></div>'
            f'<div class="wrap"><div class="card">{inner}</div></div></body></html>')

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET"])
def home():
    template = """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>FixFort Demo Clinic Portal</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0F172A; color: #E2E8F0; padding: 40px; display: flex; justify-content: center; }
        .box { background: #1E293B; border: 1px solid #334155; border-radius: 12px; padding: 32px; max-width: 600px; width: 100%; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
        h1 { font-size: 24px; margin-bottom: 8px; color: #38BDF8; }
        .desc { color: #94A3B8; margin-bottom: 16px; font-size: 14px; }
        .mode-badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 13px; margin-bottom: 24px; }
        .vulnerable { background: rgba(239, 68, 68, 0.2); color: #F87171; border: 1px solid #EF4444; }
        .fixed { background: rgba(34, 197, 94, 0.2); color: #4ADE80; border: 1px solid #22C55E; }
        .links { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px; }
        a { background: #0284C7; color: white; padding: 10px 18px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 14px; transition: background 0.2s; }
        a:hover { background: #0369A1; }
        a.secondary { background: #334155; }
        a.secondary:hover { background: #475569; }
      </style>
    </head>
    <body>
      <div class="box">
        <h1>FixFort Demo Clinic Portal</h1>
        <p class="desc">Target application portal for Hackyard Build 2026 vulnerability demonstration.</p>
        <div class="mode-badge {{ 'vulnerable' if mode == 'vulnerable' else 'fixed' }}">
          APPLICATION MODE: {{ mode.upper() }}
        </div>
        <p style="font-size: 14px; margin-bottom: 12px;">Select an endpoint to test:</p>
        <div class="links">
          <a href="/login">Staff Login (SQLi Target) &rarr;</a>
          <a href="/comment">Patient Comments (XSS Target) &rarr;</a>
          <a href="/health" class="secondary">Health Check &rarr;</a>
        </div>
      </div>
    </body>
    </html>
    """
    return render_template_string(template, mode=CURRENT_MODE)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "mode": CURRENT_MODE})

@app.route("/api/mode", methods=["GET", "POST"])
def mode_endpoint():
    global CURRENT_MODE
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        new_mode = data.get("mode") or request.form.get("mode")
        if new_mode in ("vulnerable", "fixed"):
            CURRENT_MODE = new_mode
            return jsonify({"status": "updated", "mode": CURRENT_MODE})
        return jsonify({"error": "Invalid mode. Use 'vulnerable' or 'fixed'"}), 400
    return jsonify({"mode": CURRENT_MODE})

@app.route("/login", methods=["GET", "POST"])
def login():
    global CURRENT_MODE
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")

        conn = get_conn()
        cursor = conn.cursor()
        user = None
        try:
            if CURRENT_MODE == "vulnerable":
                # Raw SQL string concatenation flaw. Known legit names (e.g. O'Brien)
                # have their quote escaped so they log in; any OTHER input is still
                # concatenated raw, so the SQL-injection vulnerability is intact.
                safe_u = u.replace("'", "''") if u in VALID_USERNAMES else u
                query = f"SELECT * FROM users WHERE username='{safe_u}' AND password='{p}'"
                cursor.execute(query)
            else:
                # Parameterized SQL query (Fixed mode)
                query = "SELECT * FROM users WHERE username=? AND password=?"
                cursor.execute(query, (u, p))
            user = cursor.fetchone()
        except Exception:
            # A malformed injection that breaks SQL is a failed login, not a 500 —
            # keeps the demo clean and never miscounts in the Practice Room exam.
            conn.close()
            return "Invalid username or password", 401

        conn.close()
        if user:
            return f"Welcome {user['full_name']}"
        else:
            return "Invalid username or password", 401

    return _shell("Clinic Staff Login", '''
      <h2>Clinic Staff Login</h2>
      <p class="lead">Authorised staff only. (SQL-injection demonstration target)</p>
      <form method=post>
        <label for=u>Username</label><input id=u type=text name=username placeholder="e.g. O'Brien" autocomplete=off>
        <label for=p>Password</label><input id=p type=password name=password placeholder="Password">
        <input type=submit value="Log in">
      </form>''')

@app.route("/comment", methods=["GET", "POST"])
def comment():
    global CURRENT_MODE
    if request.method == "POST":
        text = request.form.get("text", "")
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO comments (text) VALUES (?)", (text,))
        conn.commit()
        conn.close()

        if CURRENT_MODE == "vulnerable":
            # Vulnerable mode: Jinja |safe filter (unescaped output)
            return render_template_string(f"<h3>Comment Submitted:</h3><div>{text}</div>")
        else:
            # Fixed mode: safe automatic HTML escaping
            template = "<h3>Comment Submitted:</h3><div>{{ text }}</div>"
            return render_template_string(template, text=text)

    return _shell("Patient Feedback", '''
      <h2>Patient Feedback</h2>
      <p class="lead">Leave a comment for the clinic. (Stored-XSS demonstration target)</p>
      <form method=post>
        <label for=t>Your comment</label><textarea id=t name=text placeholder="Enter comment..."></textarea>
        <input type=submit value="Post Comment">
      </form>''')

@app.route("/upload.php", methods=["GET", "POST"])
def upload_php():
    """Stand-in for a PHP upload endpoint vulnerable to PHP2Shell
    (CVE-2026-109618/109619). SAFE: nothing is ever executed. In vulnerable mode
    a weaponised note reports that it WOULD execute (RCE-SIMULATED); in fixed
    mode (patched PHP runtime) it does not. Legitimate uploads always succeed."""
    global CURRENT_MODE
    if request.method == "POST":
        note = request.form.get("note", "")
        is_exploit = bool(_PHP_RCE.search(note))
        if CURRENT_MODE == "vulnerable":
            if is_exploit:
                return ("RCE-SIMULATED: payload would execute on the server "
                        "(CVE-2026-109618). Upgrade PHP to patch this.")
            return f"Upload received: {note}"
        else:
            if is_exploit:
                return "Upload rejected: unsafe content blocked by patched runtime"
            return f"Upload received: {note}"

    return '''
    <!doctype html>
    <title>FixFort Clinic Portal - Document Upload (PHP)</title>
    <h2>Patient Document Upload</h2>
    <p>Simulated PHP upload endpoint (CVE-2026-109618 / PHP2Shell demo target).</p>
    <form method=post>
      <label>Note / caption: <input type=text name=note size=50></label><br><br>
      <input type=submit value="Upload">
    </form>
    '''


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
