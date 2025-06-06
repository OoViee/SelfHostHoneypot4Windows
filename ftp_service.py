from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import os

LOG_FILE = "logs/ftp_log.txt"
FTP_ROOT = os.path.join(os.path.dirname(__file__), "ftp_files")

class HoneypotFTPHandler(FTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_failed_timeout = 5  # Avoid instant disconnects on failure

    def on_connect(self):
        print(f"[FTP] Connection from {self.remote_ip}:{self.remote_port}")

    def on_login(self, username):
        self.log_attempt(username, "<hidden>", success=True)

    def on_login_failed(self, username, password):
        self.log_attempt(username, password, success=False)

    def on_file_received(self, file):
        with open(LOG_FILE, "a") as f:
            f.write(f"{self.remote_ip}:{self.remote_port} - Uploaded: {file}\n")

    def on_file_sent(self, file):
        with open(LOG_FILE, "a") as f:
            f.write(f"{self.remote_ip}:{self.remote_port} - Downloaded: {file}\n")

    def on_command(self, cmd, arg):
        with open(LOG_FILE, "a") as f:
            f.write(f"{self.remote_ip}:{self.remote_port} - Command: {cmd} {arg if arg else ''}\n")

    def log_attempt(self, username, password, success):
        try:
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            with open(LOG_FILE, "a") as f:
                status = "SUCCESS" if success else "FAILED"
                f.write(f"{self.remote_ip}:{self.remote_port} - {status} - Username: {username} Password: {password}\n")
        except Exception as e:
            print(f"[FTP] Logging failed: {e}")

def start_ftp():
    # Set the FTP root directory
    ftp_dir = FTP_ROOT if os.path.exists(FTP_ROOT) else "."

    # Create the FTP user list
    authorizer = DummyAuthorizer()
    authorizer.add_user("root", "toor", ftp_dir, perm="elradfmwMT")
    authorizer.add_user("admin", "admin123", ftp_dir, perm="elradfmwMT")
    authorizer.add_anonymous(ftp_dir, perm="elr")  # Optional: allow anonymous read access

    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.banner = "220 Welcome to enterprise FTP service."

    print(f"[FTP] FTP honeypot started on port 2121 using root dir: {ftp_dir}")
    server = FTPServer(("0.0.0.0", 21), handler)  # Change to 21 if needed
    server.serve_forever()

if __name__ == "__main__":
    start_ftp()
