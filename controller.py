import threading
from ssh_service import start_ssh
from hrms_service import start_hrms  # ✅ HRMS replaces HTTP
from https_service import start_https
from ftp_service import start_ftp
from telnet_service import start_telnet
from rdp_service import start_rdp
from mysql_service import start_mysql
# from smb_service import start_smb  # Placeholder

def run_services():
    threading.Thread(target=start_ssh, daemon=True).start()
    threading.Thread(target=start_hrms, daemon=True).start()  # ✅ HRMS web interface
    threading.Thread(target=start_https, daemon=True).start()
    threading.Thread(target=start_ftp, daemon=True).start()
    threading.Thread(target=start_telnet, daemon=True).start()
    threading.Thread(target=start_mysql, daemon=True).start()
    threading.Thread(target=start_rdp, daemon=True).start()
    # threading.Thread(target=start_smb, daemon=True).start()  # Placeholder

if __name__ == "__main__":
    run_services()
    print("All honeypot services are running. Press Ctrl+C to stop.")
    while True:
        pass
