import socket
import threading
import struct
import os
import time

# Logging setup
LOG_PATH = os.path.join("logs", "mysql_service.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

def log_entry(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    print(full_msg)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(full_msg + "\n")

# Packet builders
def build_packet(payload, seq_id):
    packet_len = struct.pack("<I", len(payload))[:3]
    return packet_len + bytes([seq_id]) + payload

def build_handshake_packet():
    protocol_version = 10
    server_version = b"5.7.39-fake\x00"
    conn_id = 1234
    auth_plugin_data_part_1 = b"abcdefgh"
    filler = b"\x00"
    capability_flags = 0xa685
    character_set = 0x21
    status_flags = 0x0002
    auth_plugin_data_part_2 = b"ijklmnopqrstuvwxyz"
    auth_plugin_name = b"mysql_native_password\x00"

    payload = struct.pack("<B", protocol_version)
    payload += server_version
    payload += struct.pack("<I", conn_id)
    payload += auth_plugin_data_part_1
    payload += filler
    payload += struct.pack("<H", capability_flags & 0xFFFF)
    payload += struct.pack("B", character_set)
    payload += struct.pack("<H", status_flags)
    payload += struct.pack("<H", (capability_flags >> 16) & 0xFFFF)
    payload += struct.pack("B", len(auth_plugin_data_part_1 + auth_plugin_data_part_2) + 1)
    payload += b"\x00" * 10
    payload += auth_plugin_data_part_2 + b"\x00"
    payload += auth_plugin_name

    return build_packet(payload, 0)

def build_ok_packet(seq_id=2):
    payload = b"\x00" + b"\x00" + b"\x00"
    payload += struct.pack("<H", 0x0002)
    payload += struct.pack("<H", 0x0000)
    return build_packet(payload, seq_id)

def build_column_count_packet(count, seq_id):
    return build_packet(struct.pack("B", count), seq_id)

def build_column_definition_packet(name, seq_id):
    name_bytes = name.encode("utf-8")
    payload = b"\x03def" + b"\x00" * 3
    payload += struct.pack("B", len(name_bytes)) + name_bytes
    payload += struct.pack("B", len(name_bytes)) + name_bytes
    payload += b"\x0c" + b"\x21\x00" + b"\xff\xff\xff\xff" + b"\xfd" + b"\x00\x00" + b"\x00" + b"\x00\x00"
    return build_packet(payload, seq_id)

def build_row_packet(row_data, seq_id):
    payload = b""
    for val in row_data:
        val_bytes = str(val).encode("utf-8")
        payload += struct.pack("B", len(val_bytes)) + val_bytes
    return build_packet(payload, seq_id)

def build_eof_packet(seq_id):
    return build_packet(b"\xfe\x00\x00\x02\x00\x00", seq_id)

def send_query_result(conn, columns, rows):
    seq = 1
    conn.sendall(build_column_count_packet(len(columns), seq)); seq += 1
    for col in columns:
        conn.sendall(build_column_definition_packet(col, seq)); seq += 1
    conn.sendall(build_eof_packet(seq)); seq += 1
    for row in rows:
        conn.sendall(build_row_packet(row, seq)); seq += 1
    conn.sendall(build_eof_packet(seq))

# Client handler
def handle_client(conn, addr):
    log_entry(f"[MySQL] Connection from {addr}")
    try:
        conn.sendall(build_handshake_packet())
        conn.recv(4096)
        conn.sendall(build_ok_packet())

        while True:
            data = conn.recv(4096)
            if not data:
                break

            payload = data[4:]
            if not payload:
                break

            command = payload[0]
            if command == 0x03:  # COM_QUERY
                query = payload[1:].decode(errors="ignore").strip().lower()
                log_entry(f"[MySQL] Query from {addr[0]}: {query}")

                if query.startswith("show databases"):
                    send_query_result(conn, ["Database"], [["hrms"], ["finance"]])

                elif query.startswith("show tables"):
                    send_query_result(conn, ["Tables_in_hrms"], [["users"], ["employees"]])

                elif query.startswith("describe users") or query.startswith("desc users"):
                    send_query_result(conn, ["Field"], [["username"], ["password_hash"], ["role"]])

                elif query.startswith("select * from users"):
                    rows = [
                        ["admin", "5f4dcc3b5aa765d61d8327deb882cf99", "HR"],
                        ["jdoe", "e99a18c428cb38d5f260853678922e03", "Staff"]
                    ]
                    send_query_result(conn, ["username", "password_hash", "role"], rows)

                elif query.startswith("use "):
                    conn.sendall(build_ok_packet(1))  # Always "OK"

                else:
                    conn.sendall(build_ok_packet(1))  # Pretend success
                    log_entry(f"[MySQL] Unhandled query from {addr[0]}: {query}")
            else:
                conn.sendall(build_ok_packet(1))  # Non-query command
    except Exception as e:
        log_entry(f"[MySQL] Error with {addr}: {e}")
    finally:
        conn.close()
        log_entry(f"[MySQL] Connection closed for {addr}")

# Server launcher
def start_mysql(host="0.0.0.0", port=3306):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    log_entry(f"[MySQL] Fake honeypot listening on {host}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
