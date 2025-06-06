import socket
import threading
import struct

# MySQL constants
SERVER_VERSION = b"5.7.39"
PROTOCOL_VERSION = 10
DEFAULT_USERNAME = "root"
EXPECTED_PASSWORD = "pass123"

def build_handshake_packet(connection_id):
    scramble = b"aaaaaaaaaa"  # dummy scramble
    packet = struct.pack("<B", PROTOCOL_VERSION)
    packet += SERVER_VERSION + b"\x00"
    packet += struct.pack("<I", connection_id)
    packet += scramble + b"\x00" * 13
    return build_packet(packet, 0)

def build_ok_packet():
    packet = b"\x00"  # OK header
    packet += b"\x00"  # affected rows
    packet += b"\x00"  # last insert ID
    packet += b"\x02\x00"  # status flags
    packet += b"\x00\x00"  # warnings
    return build_packet(packet, 2)

def build_packet(payload, seq_id):
    packet_len = struct.pack("<I", len(payload))[:3]
    return packet_len + bytes([seq_id]) + payload

def handle_client(conn, addr):
    print(f"[MySQL] Connection from {addr}")
    try:
        connection_id = 1234
        # Step 1: Send handshake
        conn.sendall(build_handshake_packet(connection_id))

        # Step 2: Receive login request
        login_packet = conn.recv(4096)

        # (Optional) extract username from login_packet here

        # Step 3: Send OK packet to simulate successful login
        conn.sendall(build_ok_packet())

        # Step 4: Wait for first query (or exit)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"[MySQL] Received query (hex): {data.hex()}")
            conn.sendall(build_ok_packet())  # fake OK for every command

    except Exception as e:
        print(f"[MySQL] Error: {e}")
    finally:
        conn.close()
        print(f"[MySQL] Connection with {addr} closed")

def start_mysql_honeypot(host="0.0.0.0", port=3306):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[MySQL] Honeypot listening on {host}:{port}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_mysql_honeypot()
