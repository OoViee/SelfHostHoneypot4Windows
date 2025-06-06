import socket
import threading
import os
import subprocess
import time

LOG_FILE = "logs/rdp_log.txt"
ALLOWED_USERS = {
    "root": "toor",
    "admin": "admin123"
}

# Fake RDP Response when client connects
FAKE_RDP_RESPONSE = (
    b"Cookie: mstshash=RDPUser\r\n"
    b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00"
)

# Fake directory structure
FAKE_FS = {
    "C:\\": ["Users", "Program Files", "Windows"],
    "C:\\Users": ["root", "admin"],
    "C:\\Users\\root": ["Documents", "Downloads", "Desktop", "AppData"],
    "C:\\Users\\admin": ["Documents", "Downloads", "Desktop", "AppData"]
}

# Simulating some internal network hosts
INTERNAL_NETWORK = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

# Simple Active Directory emulation for user info
ACTIVE_DIRECTORY = {
    "root": {"Full Name": "Root User", "Group": "Admins", "Last Login": "2025-04-18 09:00"},
    "admin": {"Full Name": "Administrator", "Group": "Admins", "Last Login": "2025-04-18 08:30"}
}

def log(message):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")
    print(message)

def recv_line(conn, hide_input=False):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            return None
        if hide_input:
            conn.sendall(b"*")  # Simulate hiding the password input with asterisks
        else:
            conn.sendall(chunk)  # Echo only if not hiding input
        data += chunk
    return data.decode(errors='ignore').strip()

def simulate_command(cmd):
    """ Simulate Windows command execution output. """
    if cmd.lower() == "exit":
        return "Exiting RDP session."
    elif cmd.lower() == "dir" or cmd.lower() == "ls":
        return simulate_dir_listing()
    elif cmd.lower() == "pwd":
        return "C:\\Users\\admin"  # Simulating current directory
    elif cmd.lower() == "ipconfig":
        return simulate_ipconfig()
    elif cmd.lower() == "systeminfo":
        return simulate_systeminfo()
    elif cmd.lower().startswith("net user"):
        return simulate_net_user()
    elif cmd.lower().startswith("ping"):
        return "Pinging 192.168.1.1 with 32 bytes of data: Reply from 192.168.1.1: bytes=32 time<1ms TTL=64"
    else:
        return f"' {cmd} ' is not recognized as an internal or external command."

def simulate_dir_listing():
    """ Simulate directory listing for the user's home directory. """
    return "\n".join(["Documents", "Downloads", "Desktop", "AppData"])

def simulate_ipconfig():
    """ Simulate output of 'ipconfig' command. """
    return """
Windows IP Configuration

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::d4f6:937c:44d1:9a3a%3
   IPv4 Address. . . . . . . . . . : 192.168.1.10
   Subnet Mask . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . : 192.168.1.1
    """

def simulate_systeminfo():
    """ Simulate output of 'systeminfo' command. """
    return """
Host Name:                 WIN-HOST
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.19041 N/A Build 19041
Manufacturer:              Dell Inc.
Product Type:              Laptop
System Type:               x64-based PC
"""

def simulate_net_user():
    """ Simulate the output of 'net user' command. """
    return """
User accounts for \\WIN-HOST
-------------------------------------------------------------------------------
admin               Root User             Admins
"""

def simulate_file_upload(conn):
    """ Simulate a file upload from the attacker. """
    conn.sendall(b"\nSimulating file upload... \nFile saved as: C:\\Users\\admin\\Downloads\\malware.exe")
    log("Malware file uploaded: malware.exe")

def simulate_internal_network_scan():
    """ Simulate a network scan for internal IP addresses. """
    conn.sendall(b"\nScanning internal network...\n")
    for ip in INTERNAL_NETWORK:
        conn.sendall(f"Host found: {ip}\n".encode())
    log("Internal network scan complete.")

def simulate_active_directory_lookup(user):
    """ Simulate Active Directory lookup for a given user. """
    if user in ACTIVE_DIRECTORY:
        info = ACTIVE_DIRECTORY[user]
        return f"\nUser: {user}\nFull Name: {info['Full Name']}\nGroup: {info['Group']}\nLast Login: {info['Last Login']}"
    else:
        return f"\nUser '{user}' not found in Active Directory."

def handle_client(conn, addr):
    try:
        log(f"Connection from {addr[0]}:{addr[1]}")
        conn.sendall(b"RDP Shell\nUsername: ")
        username = recv_line(conn)
        if username is None:
            return

        conn.sendall(b"Password: ")
        password = recv_line(conn, hide_input=True)
        conn.sendall(b"\n")  # Move to next line after password entry

        if username in ALLOWED_USERS and ALLOWED_USERS[username] == password:
            log(f"Successful login from {addr[0]} as {username}")
            conn.sendall(b"\nLogin successful.\nWelcome to Windows 10 Enterprise\n\n")
            rdp_shell(conn, addr, username)
        else:
            log(f"Failed login from {addr[0]} with username '{username}'")
            conn.sendall(b"\nLogin failed. Access Denied.\n")
    except Exception as e:
        log(f"Error with {addr[0]}: {e}")
    finally:
        conn.close()

def rdp_shell(conn, addr, username):
    while True:
        conn.sendall(f"C:\\Users\\{username}> ".encode())
        cmd = recv_line(conn)
        if cmd is None:
            break
        if cmd.strip() == "":
            continue  # Empty command, just prompt again
        log(f"{addr[0]} ran command: {cmd}")
        output = simulate_command(cmd)
        conn.sendall(output.encode() + b"\n")
        if cmd.lower() == "exit":
            break
        elif cmd.lower() == "upload":
            simulate_file_upload(conn)
        elif cmd.lower() == "scan network":
            simulate_internal_network_scan()
        elif cmd.lower().startswith("net user"):
            user = cmd.split()[2]
            output = simulate_active_directory_lookup(user)
            conn.sendall(output.encode() + b"\n")

def start_rdp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 3389))
    server.listen(5)
    print("[RDP] Fake honeypot listening on port 3389")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_rdp()
