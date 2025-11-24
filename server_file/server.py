#!/usr/bin/env python3
import socket
import os
import threading
import shutil
import json
import logging
from securehash import verify_password
 
HOST = "0.0.0.0"
PORT = 5001
BUF = 4096
MAX_LOGIN_ATTEMPTS = 5
 
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(ROOT_DIR, "users.json")
LOG_FILE = os.path.join(ROOT_DIR, "logs.txt")
 
# ----- logging -----
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
 
def log(msg):
    print(msg)
    logging.info(msg)
 
# ----- helpers -----
def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r") as f:
        return json.load(f)
 
def find_user(username):
    for u in load_users():
        if u["username"] == username:
            return u
    return None
 
def safe_path(rel_path: str) -> str:
    """
    Join with ROOT_DIR and prevent path traversal.
    """
    if rel_path.startswith("/") or rel_path.startswith("\\"):
        raise PermissionError("absolute paths not allowed")
    if ".." in rel_path:
        raise PermissionError("path traversal blocked")
 
    candidate = os.path.abspath(os.path.join(ROOT_DIR, rel_path))
    if not candidate.startswith(ROOT_DIR):
        raise PermissionError("outside root dir")
    return candidate
 
def send_line(conn, text: str):
    conn.sendall((text + "\n").encode())
 
def recv_line(conn):
    data = b""
    while True:
        ch = conn.recv(1)
        if not ch:
            return None
        if ch == b"\n":
            break
        data += ch
    return data.decode()
 
def is_admin(session):
    return session.get("auth") and session.get("role") == "admin"
 
# ----- per-client handler -----
def handle_client(conn, addr):
    log(f"[NEW CLIENT] {addr}")
    session = {"auth": False, "user": None, "role": None}
    attempts = 0
 
    try:
        send_line(conn, "WELCOME - login <user> <pass> to continue")
 
        while True:
            line = recv_line(conn)
            if line is None:
                break
            cmdline = line.strip()
            if not cmdline:
                continue
            parts = cmdline.split()
            cmd = parts[0].lower()
 
            # -------- LOGIN --------
            if cmd == "login":
                if len(parts) != 3:
                    send_line(conn, "ERR usage: login <user> <pass>")
                    continue
                username, pwd = parts[1], parts[2]
                u = find_user(username)
                if not u or not verify_password(pwd, u["password"]):
                    attempts += 1
                    send_line(conn, "ERR bad credentials")
                    log(f"[LOGIN FAIL] user={username} from={addr}")
                    if attempts >= MAX_LOGIN_ATTEMPTS:
                        send_line(conn, "ERR too many attempts")
                        break
                    continue
                if u.get("locked"):
                    send_line(conn, "ERR account locked")
                    continue
                session["auth"] = True
                session["user"] = username
                session["role"] = u.get("role", "user")
                send_line(conn, f"OK logged in as {username} ({session['role']})")
                log(f"[LOGIN OK] user={username} from={addr}")
                continue
 
            # everything after this needs auth
            if not session["auth"]:
                send_line(conn, "ERR not authenticated")
                continue
 
            username = session["user"]
 
            # -------- LS --------
            if cmd == "ls":
                try:
                    items = os.listdir(ROOT_DIR)
                    body = "\n".join(items)
                    send_line(conn, f"OK {len(body.encode())}")
                    if body:
                        conn.sendall(body.encode())
                    log(f"[CMD ls] user={username}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR ls] {e}")
                continue
 
            # -------- GET --------
            if cmd == "get":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: get <file>")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    if not os.path.isfile(path):
                        send_line(conn, "ERR not found")
                    else:
                        size = os.path.getsize(path)
                        send_line(conn, "OK")
                        send_line(conn, str(size))
                        with open(path, "rb") as f:
                            while True:
                                chunk = f.read(BUF)
                                if not chunk:
                                    break
                                conn.sendall(chunk)
                        log(f"[CMD get] user={username} file={rel} size={size}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR get] user={username} file={rel} err={e}")
                continue
 
            # -------- PUT --------
            if cmd == "put":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: put <file>")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    send_line(conn, "OK")
                    size_line = recv_line(conn)
                    if not size_line:
                        send_line(conn, "ERR missing size")
                        continue
                    size = int(size_line.strip())
                    remaining = size
                    with open(path, "wb") as f:
                        while remaining > 0:
                            chunk = conn.recv(min(BUF, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            remaining -= len(chunk)
                    send_line(conn, "OK")
                    log(f"[CMD put] user={username} file={rel} size={size}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR put] user={username} file={rel} err={e}")
                continue
 
            # -------- CREATE --------
            if cmd == "create":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: create <file>")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    if os.path.exists(path):
                        send_line(conn, "ERR exists")
                    else:
                        open(path, "w").close()
                        send_line(conn, "OK")
                        log(f"[CMD create] user={username} file={rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR create] user={username} file={rel} err={e}")
                continue
 
            # -------- READ --------
            if cmd == "read":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: read <file>")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    if not os.path.isfile(path):
                        send_line(conn, "ERR not found")
                    else:
                        with open(path, "r", errors="ignore") as f:
                            data = f.read().encode()
                        send_line(conn, str(len(data)))
                        if data:
                            conn.sendall(data)
                        log(f"[CMD read] user={username} file={rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR read] user={username} file={rel} err={e}")
                continue
 
            # -------- UPDATE (multi-line) --------
            if cmd == "update":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: update <file>")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    if not os.path.isfile(path):
                        send_line(conn, "ERR not found")
                    else:
                        send_line(conn, "READY")
                        size_line = recv_line(conn)
                        if not size_line:
                            send_line(conn, "ERR missing size")
                            continue
                        size = int(size_line.strip())
                        data = b""
                        while len(data) < size:
                            chunk = conn.recv(min(BUF, size - len(data)))
                            if not chunk:
                                break
                            data += chunk
                        with open(path, "w", errors="ignore") as f:
                            f.write(data.decode(errors="ignore"))
                        send_line(conn, "OK")
                        log(f"[CMD update] user={username} file={rel} size={size}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR update] user={username} file={rel} err={e}")
                continue
 
            # -------- DELETE (admin) --------
            if cmd == "delete":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: delete <file>")
                    continue
                if not is_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    if not os.path.isfile(path):
                        send_line(conn, "ERR not found")
                    else:
                        os.remove(path)
                        send_line(conn, "OK")
                        log(f"[CMD delete] admin={username} file={rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR delete] admin={username} file={rel} err={e}")
                continue
            
            # -------- MKDIR (admin) --------
            if cmd == "mkdir":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: mkdir <dir>")
                    continue
                if not is_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    os.mkdir(path)
                    send_line(conn, "OK")
                    log(f"[CMD mkdir] admin={username} dir={rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR mkdir] admin={username} dir={rel} err={e}")
                continue
 
            # -------- RMDIR (admin) --------
            if cmd == "rmdir":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: rmdir <dir>")
                    continue
                if not is_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                rel = parts[1]
                try:
                    path = safe_path(rel)
                    os.rmdir(path)
                    send_line(conn, "OK")
                    log(f"[CMD rmdir] admin={username} dir={rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR rmdir] admin={username} dir={rel} err={e}")
                continue
 
            # -------- RENAME (admin) --------
            if cmd == "rename":
                if len(parts) < 3:
                    send_line(conn, "ERR usage: rename <old> <new>")
                    continue
                if not is_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                old_rel, new_rel = parts[1], parts[2]
                try:
                    old_path = safe_path(old_rel)
                    new_path = safe_path(new_rel)
                    os.rename(old_path, new_path)
                    send_line(conn, "OK")
                    log(f"[CMD rename] admin={username} {old_rel}->{new_rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR rename] admin={username} err={e}")
                continue
 
            # -------- MOVE / COPY (admin) --------
            if cmd == "move":
                if len(parts) < 3:
                    send_line(conn, "ERR usage: move <src> <dst>")
                    continue
                if not is_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                src_rel, dst_rel = parts[1], parts[2]
                try:
                    src = safe_path(src_rel)
                    dst = safe_path(dst_rel)
                    shutil.move(src, dst)
                    send_line(conn, "OK")
                    log(f"[CMD move] admin={username} {src_rel}->{dst_rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR move] admin={username} err={e}")
                continue
 
            if cmd == "copy":
                if len(parts) < 3:
                    send_line(conn, "ERR usage: copy <src> <dst>")
                    continue
                if not is_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                src_rel, dst_rel = parts[1], parts[2]
                try:
                    src = safe_path(src_rel)
                    dst = safe_path(dst_rel)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
                    send_line(conn, "OK")
                    log(f"[CMD copy] admin={username} {src_rel}->{dst_rel}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR copy] admin={username} err={e}")
                continue
 
            # -------- SEARCH --------
            if cmd == "search":
                if len(parts) < 3:
                    send_line(conn, "ERR usage: search <name|content> <pattern>")
                    continue
                mode = parts[1]
                pattern = " ".join(parts[2:])
                matches = []
                try:
                    for root, _, files in os.walk(ROOT_DIR):
                        for f in files:
                            full = os.path.join(root, f)
                            rel_path = os.path.relpath(full, ROOT_DIR)
                            if mode == "name":
                                if pattern in f:
                                    matches.append(rel_path)
                            elif mode == "content":
                                try:
                                    with open(full, "r", errors="ignore") as fh:
                                        if pattern in fh.read():
                                            matches.append(rel_path)
                                except:
                                    pass
                            else:
                                send_line(conn, "ERR unknown mode")
                                matches = None
                                break
                    if matches is None:
                        continue
                    body = "\n".join(matches)
                    send_line(conn, f"OK {len(body.encode())}")
                    if body:
                        conn.sendall(body.encode())
                    log(f"[CMD search] user={username} mode={mode} pattern={pattern}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR search] user={username} err={e}")
                continue
 
            # -------- QUIT --------
            if cmd == "quit":
                send_line(conn, "BYE")
                log(f"[QUIT] user={username}")
                break
 
            # -------- UNKNOWN --------
            send_line(conn, "ERR unknown command")
            log(f"[UNKNOWN CMD] user={username} cmd={cmdline}")
 
    except Exception as e:
        log(f"[CLIENT ERROR] {addr} err={e}")
 
    log(f"[CLIENT DISCONNECTED] {addr}")
    conn.close()
 
def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    log(f"[SERVER STARTED] {HOST}:{PORT} root={ROOT_DIR}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
 
if __name__ == "__main__":
    main()