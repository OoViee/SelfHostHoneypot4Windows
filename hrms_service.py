from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, send_from_directory, g
import os
import csv
from io import StringIO
import subprocess
import time
import socket
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Logging setup
LOG_PATH = os.path.join("logs", "hrms_service.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# Apache/syslog style request metadata collection
@app.before_request
def log_request():
    g.start_time = datetime.now()
    g.client_ip = request.remote_addr
    g.method = request.method
    g.path = request.full_path.rstrip('?')
    g.ua = request.headers.get("User-Agent", "-")
    g.referer = request.headers.get("Referer", "-")

# Apache/syslog style request logging
@app.after_request
def apache_style_log(response):
    PRIORITY = 142
    HOSTNAME = "NBGYWEBP2"  # Or socket.gethostname()
    TAG = "nginx-access"

    dt = g.start_time
    syslog_time = dt.strftime("%b %d %H:%M:%S")
    apache_time = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

    log_line = (
        f"<{PRIORITY}>{syslog_time} {HOSTNAME} {TAG}: "
        f"{g.client_ip} - - [{apache_time}] "
        f'"{g.method} {g.path} HTTP/1.1" {response.status_code} {response.content_length or 0} '
        f'"{g.referer}" "{g.ua}"'
    )

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(log_line + "\n")

    return response

# Data folders
UPLOAD_FOLDER = 'uploads'
DOCS_FOLDER = 'docs'
FINANCE_FOLDER = 'finance'
for folder in [UPLOAD_FOLDER, DOCS_FOLDER, FINANCE_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Fake users and data
users = {
    'admin': 'admin123',
    'hruser': 'hr@123'
}

dummy_employees = [
    {"id": 1, "name": "Alice Johnson", "dob": "1990-05-10", "dept": "Finance", "salary": "$70,000", "ssn": "XXX-45-6789", "phone": "555-1234", "email": "alice@corpmail.local"},
    {"id": 2, "name": "Bob Smith", "dob": "1988-11-22", "dept": "Engineering", "salary": "$90,000", "ssn": "XXX-66-7890", "phone": "555-5678", "email": "bob@corpmail.local"},
    {"id": 3, "name": "Charlie Brown", "dob": "1992-03-15", "dept": "HR", "salary": "$65,000", "ssn": "XXX-12-3456", "phone": "555-8765", "email": "charlie@corpmail.local"}
]

inbox_emails = [
    {"from": "it-support@corpmail.local", "subject": "VPN Credentials", "body": "Your VPN password is: `vpnaccess2024!`"},
    {"from": "ceo@corpmail.local", "subject": "Confidential HR Policy", "body": "Attached draft contains staff evaluation metrics."},
    {"from": "alerts@security.local", "subject": "Suspicious Activity", "body": "A user attempted access to /internal-docs without permissions."}
]

timesheets = [
    {"id": 101, "name": "Alice Johnson", "project": "Budget Review", "hours": 32, "rate": "$50/hr"},
    {"id": 102, "name": "Bob Smith", "project": "App Dev", "hours": 40, "rate": "$60/hr", "token": "api_key=abc123_secure_token"},
    {"id": 103, "name": "Charlie Brown", "project": "Onboarding", "hours": 38, "rate": "$45/hr"}
]

attendance_data = [
    {"date": "2025-04-01", "status": "Present"},
    {"date": "2025-04-02", "status": "Absent"},
    {"date": "2025-04-03", "status": "Remote"},
    {"date": "2025-04-04", "status": "Present"},
    {"date": "2025-04-05", "status": "Present"},
]

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[LOGIN] {time.strftime('%Y-%m-%d %H:%M:%S')} - Attempted login: {user}, Password: {pw}, IP: {request.remote_addr}\n")
        if user in users and users[user] == pw:
            session['user'] = user
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/hr-profiles')
def hr_profiles():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('hr_profiles.html', employees=dummy_employees)

@app.route('/download-hr-data')
def download_hr_data():
    if 'user' not in session:
        return redirect(url_for('login'))
    csv_data = StringIO()
    writer = csv.writer(csv_data)
    writer.writerow(["Name", "DOB", "Dept", "Salary", "SSN", "Phone", "Email"])
    for emp in dummy_employees:
        writer.writerow([emp["name"], emp["dob"], emp["dept"], emp["salary"], emp["ssn"], emp["phone"], emp["email"]])
    csv_data.seek(0)
    return send_file(csv_data, mimetype="text/csv", as_attachment=True, download_name="employee_data.csv")

@app.route('/inbox')
def inbox():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('inbox.html', emails=inbox_emails)

@app.route('/timesheets')
def timesheet():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('timesheets.html', timesheets=timesheets)

@app.route('/timesheet-detail')
def timesheet_detail():
    if 'user' not in session:
        return redirect(url_for('login'))
    tid = request.args.get('id')
    for t in timesheets:
        if str(t['id']) == tid:
            return render_template('timesheet_detail.html', t=t)
    return "Timesheet not found", 404

@app.route('/attendance')
def attendance():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('attendance.html', attendance=attendance_data)

@app.route('/internal-docs')
def internal_docs():
    return render_template('internal_docs.html')

@app.route('/docs/<path:filename>')
def serve_doc(filename):
    return send_from_directory('docs', filename)

@app.route('/finance/<path:filename>')
def serve_finance_file(filename):
    return send_from_directory('finance', filename)

@app.route('/finance')
def finance_home():
    if 'user' not in session:
        return redirect(url_for('login'))
    files = os.listdir('finance')
    return render_template('finance.html', files=files)

@app.route('/logout')
def logout():
    user = session.get('user', 'unknown')
    with open(LOG_PATH, 'a') as f:
        f.write(f"[LOGOUT] {time.strftime('%Y-%m-%d %H:%M:%S')} - {user} logged out\n")
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file.save(os.path.join('uploads', file.filename))
            with open(LOG_PATH, 'a') as f:
                f.write(f"[UPLOAD] {time.strftime('%Y-%m-%d %H:%M:%S')} - {session['user']} uploaded {file.filename}\n")
            return "Upload successful"
    return render_template('upload.html')

@app.route('/admin-tool', methods=['GET', 'POST'])
def admin_tool():
    if request.method == 'POST':
        cmd = request.form['cmd']
        with open(LOG_PATH, 'a') as f:
            f.write(f"[ADMIN TOOL] {time.strftime('%Y-%m-%d %H:%M:%S')} - {session.get('user', 'anon')} ran: {cmd}\n")
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except Exception as e:
            output = str(e).encode()
        return f"<pre>{output.decode()}</pre>"
    return render_template('admin_tool.html')

@app.route('/admin')
def admin_panel():
    return render_template('admin_panel.html', secrets=["DB_PASS=SuperSecret!", "JWT_SECRET=secretkey", "api_key=123xyz"])

def start_hrms():
    app.run(host="0.0.0.0", port=80, debug=False)

if __name__ == '__main__':
    start_hrms()
