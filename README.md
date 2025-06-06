SelfHostHoneyPot
Overview
SelfHostHoneyPot is a high-interaction honeypot suite designed for Windows environments. It simulates vulnerable and realistic versions of commonly targeted services—SSH, HTTP, HTTPS, FTP, and SQL—to attract and monitor malicious activity from attackers. All services run locally without the need for Docker, WSL, or third-party emulators, making deployment and integration seamless.
Features
✅ Multi-Protocol Emulation:


Fake SSH with interactive shell and limited command execution


Fake HTTP/HTTPS with a realistic HRMS web interface (mimicking enterprise apps)


Fake FTP server with simulated file access and upload functionality


Stub SQL interface to mimic common database ports and attract SQL scanners


🔐 Windows-Native Deployment:


Built entirely in Python and PowerShell


Compatible with Windows 10/11 or Server environments


Uses built-in logging (e.g., Event Logs, flat log files)


📈 Full Activity Logging:


Captures login attempts, credentials, commands, file uploads, and HTTP interactions


Output is written to structured logs like honeypot_commands.log, ftp_honeypot.log


🎭 Realistic Interfaces:


HRMS-like web app with fake users, files, inbox, timesheets, and vulnerable routes


Fake FTP and SSH shells simulate real file system and shell behavior



Folder Structure
pgsql
CopyEdit
SelfHostHoneyPot/

├── controller.py              # Main controller to launch all services

├── ftp_service.py             # FTP honeypot using pyftpdlib
├── http_service.py            # HTTP honeypot using Flask
├── https_service.py           # HTTPS service with SSL wrapper
├── hrms_service.py            # Realistic HRMS web interface
├── command_handler.py         # Handles simulated shell/terminal commands
├── generate_cert.py           # Self-signed SSL certificate generator
├── cert.pem / key.pem         # SSL certificate and key
├── ftp_honeypot.log           # FTP log file
├── honeypot_commands.log      # Logs commands from SSH/FTP


Installation
Install Requirements:

 bash
CopyEdit
pip install -r requirements.txt


Generate SSL Certificate (Optional):

 bash
CopyEdit
python generate_cert.py


Run the Honeypot:

 bash
CopyEdit
python controller.py


Services will start on the following default ports:


HTTP: 8080


HTTPS: 8443


FTP: 2121


SSH: 2222


SQL (stub): 1433


Ensure these ports are open and not blocked by a firewall.

Logging & Monitoring
All activity is logged in flat files for post-incident analysis.


You can add integrations with:


Windows Event Viewer (via PowerShell)


Sysmon or ELK stack for richer telemetry



Example Use Cases
Research and capture attack techniques


Honeynet or deception layer in enterprise network


Cybersecurity awareness and red team baiting


Custom threat intelligence generation



Known Limitations
SQL service is a stub and may not respond to full SQL queries yet


SSH/FTP only simulate command/file interaction; no real file system changes occur


Not suitable for production use — meant for research and monitoring



🧠 Project Briefing
Objective
To build a modular, believable honeypot for Windows that attracts attackers with fake enterprise services, logs their activity, and simulates vulnerabilities in a safe and controlled environment.
Architecture
Language: Python 3.x (PowerShell wrappers optional)


Execution Model: Multi-service via controller.py using subprocesses or threads


Interface: Localhost access via browser, terminal, and file clients


Attack Surface:


Fake HRMS portal with known web vulnerabilities (e.g., SQLi, file upload, command injection)


Simulated login shells for FTP and SSH


Open ports mimicking real enterprise services


Attack Logging & Intelligence
Logs credentials, IPs, and commands


Useful for pattern recognition, behavior mapping, and TTP analysis

