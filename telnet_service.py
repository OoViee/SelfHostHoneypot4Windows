import socket
import threading

def handle_client(conn, addr):
    try:
        conn.send(b"Login: ")
        username = conn.recv(1024).decode(errors="ignore").strip()
        conn.send(b"Password: ")
        password = conn.recv(1024).decode(errors="ignore").strip()
        with open("logs/telnet_log.txt", "a") as f:
            f.write(f"{addr} - Username: {username}, Password: {password}\n")
        conn.send(b"Login incorrect\n")
    except:
        pass
    finally:
        conn.close()

def start_telnet():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 23))
    server.listen(5)
    print("[Telnet] Telnet honeypot started on port 23")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
