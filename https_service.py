from flask import Flask, request, render_template, redirect, url_for, session, g
import ssl, os, socket
from datetime import datetime

# Setup Flask app with proper template/static paths
app = Flask(__name__,
            static_folder="https_data/static",
            template_folder="https_data/templates")
app.secret_key = 'supersecretkey'  # For session handling

# Logging path
LOG_FILE = "logs/https_log.log"

# Server metadata for Apache-style logging
SERVER_HOSTNAME = socket.gethostname()
APP_NAME = "Apache"
APP_PID = os.getpid()

# Timestamp formatters
def apache_ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def syslog_ts(dt):
    return dt.strftime("%b %d %H:%M:%S")

# Access log - before request
@app.before_request
def log_http_request_start():
    g.start_time = datetime.now()
    g.client_ip = request.remote_addr
    g.user = session.get('username', '-')
    g.method = request.method
    g.path = request.full_path.rstrip('?')
    g.ua = request.headers.get("User-Agent", "-")
    g.referer = request.headers.get("Referer", "-")

# Access log - after request
@app.after_request
def log_http_request_end(response):
    dt = g.start_time
    content_length = response.content_length or 0
    log_line = (
        f"<150>{syslog_ts(dt)} {SERVER_HOSTNAME} {APP_NAME}[{APP_PID}]: "
        f"{g.client_ip} - - [{apache_ts(dt)}] "
        f'"{g.method} {g.path} HTTP/1.1" {response.status_code} {content_length} '
        f'"{g.referer}" "{g.ua}"'
    )
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + '\n')
    return response

# Optional error logger (Apache style)
def log_apache_error(message, client_ip="-"):
    now = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    error_line = f"[{now}] [error] [client {client_ip}] {message}"
    with open(LOG_FILE, 'a') as f:
        f.write(error_line + '\n')

# -----------------------------------
# Fake users
# -----------------------------------
VALID_USERS = {
    "admin": "admin123",
    "alice": "helpdesk2024",
    "bob": "readonly"
}

# -----------------------------------
# Utility loggers
# -----------------------------------
def log_login_attempt(user, pwd, ip):
    with open(LOG_FILE, 'a') as f:
        f.write(f"[LOGIN] {datetime.now()} - IP: {ip} - Username: {user}, Password: {pwd}\n")

def log_access(ip, user, page):
    with open(LOG_FILE, 'a') as f:
        f.write(f"[ACCESS] {datetime.now()} - IP: {ip} - User: {user} - Visited: {page}\n")

# -----------------------------------
# ROUTES
# -----------------------------------

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        log_login_attempt(username, password, request.remote_addr)

        if VALID_USERS.get(username) == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template("login.html", error=True)
    return render_template("login.html", error=False)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    log_access(request.remote_addr, session['username'], "/dashboard")
    return render_template("dashboard.html", user=session['username'])

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    log_access(request.remote_addr, session['username'], "/profile")
    return render_template("profile.html", user=session['username'])

@app.route('/tickets')
def tickets():
    if 'username' not in session:
        return redirect(url_for('login'))

    query = request.args.get('q')
    status = request.args.get('status')
    simulated_results = []
    sqli_detected = False

    keywords = ["'", "--", "1=1", "<script", ";", " or ", "select", "union", "drop", "insert"]
    if query and any(k in query.lower() for k in keywords):
        sqli_detected = True
        with open(LOG_FILE, 'a') as f:
            f.write(f"[ALERT] {datetime.now()} - IP: {request.remote_addr} - User: {session['username']} - Suspicious search query: {query}\n")

        simulated_results = [
            {"ticket_id": "101", "subject": "Payroll DB Credentials Leak", "status": "Open"},
            {"ticket_id": "102", "subject": "VPN Access Escalation", "status": "Closed"},
            {"ticket_id": "103", "subject": "Suspicious Access to Finance DB", "status": "Pending"},
        ]

    log_access(request.remote_addr, session['username'], f"/tickets?q={query}&status={status}")
    return render_template("tickets.html", user=session['username'], query=query, results=simulated_results, sqli=sqli_detected)

@app.route('/ticket/<ticket_id>')
def ticket_detail(ticket_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    log_access(request.remote_addr, session['username'], f"/ticket/{ticket_id}")

    fake_ticket = {
        "id": ticket_id,
        "subject": "Network share not accessible",
        "status": "Open",
        "priority": "High",
        "requested_by": "alice.hall@corp.local",
        "assigned_to": "Admin",
        "last_updated": "Today 08:32",
        "description": "User reports that the HR department share is no longer accessible from VPN. Possible ACL issue.",
        "updates": [
            "[08:33] Ticket created by alice.hall",
            "[08:41] Assigned to Admin",
            "[08:56] Investigating ACL entries on \\\\fileshare\\HR"
        ],
        "attachments": [
            ("logs_eventvwr.txt", "4.3 KB"),
            ("net_use_screenshot.png", "180 KB")
        ]
    }
    return render_template("ticket_detail.html", ticket=fake_ticket)

@app.route('/admin')
def admin():
    if 'username' not in session or session['username'] != 'admin':
        log_access(request.remote_addr, session.get('username', 'anonymous'), "/admin (403)")
        return "403 Forbidden - Unauthorized", 403
    log_access(request.remote_addr, session['username'], "/admin")
    return render_template("admin.html", user=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/redirect')
def fake_redirect():
    target = request.args.get('url', '')
    log_access(request.remote_addr, session.get('username', 'anonymous'), f"/redirect?url={target}")

    if any(s in target.lower() for s in ["http://", "https://", "evil", "phish", ".ru", "callback"]):
        with open(LOG_FILE, 'a') as f:
            f.write(f"[ALERT] {datetime.now()} - IP: {request.remote_addr} - Open Redirect Attempt to: {target}\n")

    return f"""
        <html><body>
        <p>Redirecting to: <a href="{target}">{target}</a></p>
        <script>
            setTimeout(() => window.location = "{target}", 2000);
        </script>
        </body></html>
    """

@app.route('/documents')
def documents():
    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.args.get('file', '')
    user = session['username']
    log_access(request.remote_addr, user, f"/documents?file={file}")

    if file:
        is_traversal = "../" in file or file.startswith("/")
        fake_dirs = {
            "../": ["conf/", "docs/", "logs/", "admin/", "debug/"],
            "../../": ["etc/", "var/", "home/", "tmp/", "opt/", "bin/", "usr/"],
            "../../etc/": ["passwd", "shadow", "hostname", "resolv.conf", "ssh/", "ssl/"],
        }

        if is_traversal:
            with open(LOG_FILE, 'a') as f:
                f.write(f"[ALERT] {datetime.now()} - IP: {request.remote_addr} - User: {user} - Directory traversal via /documents: {file}\n")

            for path, files in fake_dirs.items():
                if file == path:
                    html = "<h5>Index of " + path + "</h5><ul>"
                    for f_ in files:
                        href = url_for('documents') + "?file=" + path + f_
                        html += f'<li><a href="{href}">{f_}</a></li>'
                    html += "</ul>"
                    return html, 200

            leaks = {
                "passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User:/home/user:/bin/bash",
                "shadow": "root:$6$salty$hash:19133:0:99999:7:::",
                "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEPRIVATEKEYDATA\n-----END OPENSSH PRIVATE KEY-----",
                "passwords.txt": "alice:password123\nbob:qwerty\ncarol:letmein"
            }

            for keyword, content in leaks.items():
                if keyword in file:
                    return f"<pre>{content}</pre>", 200

            return f"<pre>403 Forbidden - Directory traversal attempt: {file}</pre>", 403

        return f"<p>Downloading: {file}</p>", 200

    return render_template("documents.html", user=user)

@app.route('/download')
def fake_download():
    file = request.args.get('file', '')
    user = session.get('username', 'anonymous')
    log_access(request.remote_addr, user, f"/download?file={file}")

    if "../" in file or file.startswith("/"):
        if "passwd" in file:
            content = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User:/home/user:/bin/bash"
        else:
            content = "403 Forbidden - Directory traversal attempt detected."

        with open(LOG_FILE, 'a') as f:
            f.write(f"[ALERT] {datetime.now()} - IP: {request.remote_addr} - Directory traversal attempt: {file}\n")

        return f"<pre>{content}</pre>", 200

    return f"<p>Requested file: {file}</p>", 200

# -----------------------------------
# Start HTTPS honeypot
# -----------------------------------

def start_https():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    print("[HTTPS] HelpDeskX HTTPS honeypot started on port 443")
    app.run(host='0.0.0.0', port=443, ssl_context=context)

if __name__ == "__main__":
    start_https()
