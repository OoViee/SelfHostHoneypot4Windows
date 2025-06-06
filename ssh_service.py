import asyncio
import asyncssh
import os
import random
import json
import uuid
import platform
from datetime import datetime

VALID_USERS = {'root': 'toor', 'admin': '123456'}
MAX_ATTEMPTS = 3

VIRTUAL_FS = {
    "C:\\Users\\root": ["Documents", "Downloads", "notes.txt"],
    "C:\\Users\\root\\Documents": ["report.docx", "passwords.csv"],
    "C:\\Users\\root\\Downloads": ["malware.exe", "setup.zip"]
}

FILE_CONTENT = {
    "C:\\Users\\root\\notes.txt": "TODO: patch the firewall\nKeepass DB in C:\\vault\n",
    "C:\\Users\\root\\Documents\\report.docx": "[Encrypted]",
    "C:\\Users\\root\\Documents\\passwords.csv": "admin,Admin@123\nsvc_acc,s3cr3t!\n",
    "C:\\Users\\root\\Downloads\\malware.exe": "[PE32 binary]",
    "C:\\Users\\root\\Downloads\\setup.zip": "[ZIP archive]",
}

LOG_PATH = os.path.join("logs", "ssh_service.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

def log_entry(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    print(full_msg)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(full_msg + "\n")

def log_sysmon_event(event):
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        # Use separators to avoid adding unnecessary spaces in the JSON output
        f.write(json.dumps(event, separators=(',', ':')) + "\n")


class SSHServer(asyncssh.SSHServer):
    def __init__(self):
        self.failed_attempts = {}
        self.username = None
        self.client_ip = None

    def connection_made(self, conn):
        peername = conn.get_extra_info('peername')
        self.client_ip = peername[0] if peername else 'unknown'
        log_entry(f"[+] New SSH connection from {self.client_ip}")

    def begin_auth(self, username):
        self.failed_attempts[username] = 0
        self.username = username
        return True

    def password_auth_supported(self): return True

    def validate_password(self, username, password):
        log_entry(f"[AUTH] Attempt from {self.client_ip} - Username: {username}, Password: {password}")
        success = VALID_USERS.get(username) == password

        event = {
            "EventTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "Hostname": platform.node(),
            "Keywords": -9214364837600034816,
            "EventType": "AUDIT_SUCCESS" if success else "AUDIT_FAILURE",
            "SeverityValue": 2,
            "Severity": "INFO",
            "EventID": 4624 if success else 4625,
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
            "Version": 1,
            "Task": 12544,
            "OpcodeValue": 0,
            "RecordNumber": random.randint(1000000, 9999999),
            "ProcessID": 0,
            "ThreadID": 0,
            "Channel": "Security",
            "Message": f"{'Successful' if success else 'Failed'} SSH login for {username} from {self.client_ip}",
            "TargetUserName": username,
            "TargetDomainName": "FAKEDOMAIN",
            "TargetLogonId": hex(random.randint(100000000, 999999999)),
            "LogonType": 3,
            "LogonProcessName": "sshd",
            "AuthenticationPackageName": "SSH",
            "IpAddress": self.client_ip,
            "IpPort": str(random.randint(1000, 65000)),
            "LogonGuid": str(uuid.uuid4()),
            "ImpersonationLevel": "%%1833",
            "WorkstationName": platform.node()
        }
        log_sysmon_event(event)

        if success:
            return True

        self.failed_attempts[username] += 1
        if self.failed_attempts[username] >= MAX_ATTEMPTS:
            log_entry(f"[AUTH] {username} exceeded max login attempts from {self.client_ip}")
        return False

    def session_requested(self): return True

async def handle_client(process):
    username = process.get_extra_info('username')
    ip = process.get_extra_info('peername')[0] if process.get_extra_info('peername') else 'unknown'
    cwd = f"C:\\Users\\{username}"
    shell_mode = 'cmd'

    def prompt():
        return f"PS {cwd}> " if shell_mode == 'powershell' else f"{cwd}> "

    process.stdout.write(prompt())

    while not process.stdin.at_eof():
        try:
            cmdline = await process.stdin.readline()
            if not cmdline: break
            cmdline = cmdline.strip()
            if not cmdline:
                process.stdout.write(prompt())
                continue

            log_entry(f"[COMMAND] {username}@{ip}: {cmdline}")

            sysmon_event = {
                "EventTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "Hostname": platform.node(),
                "Keywords": -9223372036854775808,
                "EventType": "INFO",
                "SeverityValue": 2,
                "Severity": "INFO",
                "EventID": 1,
                "SourceName": "Microsoft-Windows-Sysmon",
                "ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                "Version": 5,
                "Task": 1,
                "OpcodeValue": 0,
                "RecordNumber": random.randint(1000000, 9999999),
                "ProcessID": random.randint(1000, 9999),
                "ThreadID": random.randint(1000, 9999),
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Domain": "NT AUTHORITY",
                "AccountName": username,
                "UserID": "S-1-5-18",
                "AccountType": "User",
                "Message": f"Executed SSH command: {cmdline}",
                "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "ProcessGuid": str(uuid.uuid4()),
                "ProcessId": random.randint(3000, 9999),
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)",
                "Description": "Windows Command Processor",
                "Product": "Microsoft Windows Operating System",
                "Company": "Microsoft Corporation",
                "OriginalFileName": "Cmd.Exe",
                "CommandLine": f"cmd.exe /c \"{cmdline}\"",
                "CurrentDirectory": cwd,
                "LogonGuid": str(uuid.uuid4()),
                "LogonId": hex(random.randint(100000, 999999)),
                "TerminalSessionId": 0,
                "IntegrityLevel": "High",
                "Hashes": "SHA1=FAKE1234567890ABCDEF,MD5=ABCDEF1234567890",
                "ParentProcessGuid": str(uuid.uuid4()),
                "ParentProcessId": random.randint(1000, 9999),
                "ParentImage": "C:\\Windows\\System32\\sshd.exe",
                "ParentCommandLine": "sshd -d"
            }
            log_sysmon_event(sysmon_event)

            # --- Continue original script logic below (unchanged) ---
            tokens = cmdline.strip().split()
            base = tokens[0].lower() if tokens else ''
            args = tokens[1:] if len(tokens) > 1 else []

            if base == 'exit':
                if shell_mode == 'powershell':
                    shell_mode = 'cmd'
                    process.stdout.write(f"\n{cwd}> ")
                    continue
                else:
                    process.stdout.write("Logging off...\n")
                    break

            if base == 'powershell':
                shell_mode = 'powershell'
                process.stdout.write("Windows PowerShell\nCopyright (C) Microsoft Corporation\n\n")
                process.stdout.write(prompt())
                continue

            if shell_mode == 'powershell':
                if base == 'get-process':
                    process.stdout.write("""
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  ProcessName
-------  ------    -----      -----     ------     --  -----------
    132     10     2000       6000       0.08    1088  explorer
     64      6     1500       4000       0.01    2084  cmd
    180     15     3100       9200       0.14     872  lsass
""")
                elif base == 'get-service':
                    process.stdout.write("""
Status   Name               DisplayName
------   ----               -----------
Running  WinDefend          Windows Defender
Running  W32Time            Windows Time
Stopped  BITS               Background Intelligent Transfer
""")
                elif base == 'get-localuser':
                    process.stdout.write("""
Name          Enabled Description
----          ------- -----------
Administrator   True   Built-in admin account
Guest           False  Built-in guest account
svc_acc         True   Service account
""")
                elif base == 'get-nettcpconnection':
                    process.stdout.write("""
LocalAddress  LocalPort  RemoteAddress   RemotePort  State
------------  ---------  -------------   ----------  -----
0.0.0.0       22         172.16.85.143   50223       Established
""")
                elif base == 'whoami':
                    process.stdout.write(f"{username}\n")
                elif base == 'get-childitem':
                    for i in VIRTUAL_FS.get(cwd, []):
                        process.stdout.write(f"Directory: {cwd}\\{i}\n")
                elif base == 'cd' or base == 'set-location':
                    if args:
                        new = os.path.normpath(os.path.join(cwd, args[0]))
                        if new in VIRTUAL_FS:
                            cwd = new
                        else:
                            process.stdout.write("The system cannot find the path specified.\n")
                elif base == 'invoke-webrequest':
                    process.stdout.write("StatusCode : 200\nContent : <html>FakeSite</html>\n")
                else:
                    process.stdout.write(f"{cmdline}: The term is not recognized as the name of a cmdlet...\n")
                process.stdout.write(prompt())
                continue

            if base == 'cd':
                if args:
                    new = os.path.normpath(os.path.join(cwd, args[0]))
                    if new in VIRTUAL_FS:
                        cwd = new
                    else:
                        process.stdout.write("The system cannot find the path specified.\n")
            elif base == 'dir':
                items = VIRTUAL_FS.get(cwd, [])
                process.stdout.write(f"\n Directory of {cwd}\n\n")
                for i in items:
                    path = os.path.join(cwd, i)
                    if path in VIRTUAL_FS:
                        process.stdout.write(f"04/22/2025  10:00 AM    <DIR>          {i}\n")
                    else:
                        size = len(FILE_CONTENT.get(path, "")) + random.randint(100, 900)
                        process.stdout.write(f"04/22/2025  10:00 AM             {size} {i}\n")
            elif base == 'type' and args:
                f = os.path.normpath(os.path.join(cwd, args[0]))
                process.stdout.write(FILE_CONTENT.get(f, f"The system cannot find the file {args[0]}.\n"))
            elif base == 'echo':
                if '>' in args:
                    idx = args.index('>')
                    val, target = ' '.join(args[:idx]), args[idx+1]
                    path = os.path.normpath(os.path.join(cwd, target))
                    FILE_CONTENT[path] = val + "\n"
                    VIRTUAL_FS.setdefault(cwd, []).append(target)
                else:
                    process.stdout.write(' '.join(args) + "\n")
            elif base == 'tasklist':
                process.stdout.write("""
Image Name                     PID Session Name        Mem Usage
========================= ======== ================ ============
explorer.exe                  1088 Console             55,000 K
cmd.exe                      2084 Console              3,000 K
lsass.exe                     872 Services            12,345 K
""")
            elif base == 'systeminfo':
                process.stdout.write("""
OS Name: Microsoft Windows Server 2019 Datacenter
OS Version: 10.0.17763 Build 17763
System Manufacturer: Honeypot Corp
Total Physical Memory: 4,096 MB
""")
            elif base == 'ipconfig':
                process.stdout.write(f"""
Windows IP Configuration

Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : {ip}
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : {ip[:-1]}1
""")
            elif base == 'whoami':
                process.stdout.write(f"{username}\n")
            elif base == 'hostname':
                process.stdout.write(f"WIN-{ip.replace('.', '')[-4:]}\n")
            elif base == 'net' and 'user' in args:
                process.stdout.write("Administrator  Guest  svc_acc\n")
            elif base == 'reg' and 'query' in args:
                process.stdout.write("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n")
            elif base == 'route' and 'print' in args:
                process.stdout.write("0.0.0.0        0.0.0.0    172.16.85.1\n")
            elif base == 'ping':
                process.stdout.write("Reply from 8.8.8.8: bytes=32 time<1ms TTL=128\n")
            else:
                process.stdout.write(f"'{cmdline}' is not recognized as an internal or external command,\noperable program or batch file.\n")

            process.stdout.write(prompt())

        except Exception as e:
            log_entry(f"[!] Error in shell: {e}")
            break

    process.exit(0)
    log_entry(f"[SESSION CLOSED] {username}@{ip}")

async def start_async_ssh(port=22):
    try:
        await asyncssh.create_server(
            SSHServer, '', port,
            server_host_keys=['ssh_host_key'],
            process_factory=handle_client,
            encoding='utf-8'
        )
        log_entry(f"[+] SSH honeypot listening on port {port}")
        await asyncio.Future()
    except Exception as e:
        log_entry(f"[!] Failed to start SSH honeypot: {e}")

def start_ssh(port=22):
    if not os.path.exists("ssh_host_key"):
        log_entry("[!] SSH private key does not exist. Please generate it using ssh-keygen.")
        return
    asyncio.run(start_async_ssh(port))
