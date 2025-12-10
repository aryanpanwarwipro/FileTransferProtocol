

import os
import socket
import ssl
import threading
import json
import logging
import shutil
import time
from securehash import verify_password  
 
# ---------------- Configuration ----------------
HOST = "0.0.0.0"
PORT = 5001
BUF = 8192
MAX_LOGIN_ATTEMPTS = 5
 
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(ROOT_DIR, "users.json")
LOG_FILE = os.path.join(ROOT_DIR, "server.log")
 
PUBLIC_DIR = os.path.join(ROOT_DIR, "shared")
USER_DATA_DIR = os.path.join(ROOT_DIR, "user_data")
os.makedirs(PUBLIC_DIR, exist_ok=True)
os.makedirs(USER_DATA_DIR, exist_ok=True)
 
# TLS certificate files expected in same folder as server.py
CERT_FILE = os.path.join(ROOT_DIR, "server.crt")
KEY_FILE = os.path.join(ROOT_DIR, "server.key")
 
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
 
 
def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"{ts} {msg}"
    print(formatted)
    logging.info(msg)
 
 
# ---------------- Utility functions ----------------
def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r") as f:
        return json.load(f)
 
 
def find_user_record(username):
    for u in load_users():
        if u.get("username") == username:
            return u
    return None
 
 
def user_home(username):
    p = os.path.join(USER_DATA_DIR, username)
    os.makedirs(p, exist_ok=True)
    return p
 
 
def is_shared_path(abs_path):
    abs_public = os.path.abspath(PUBLIC_DIR) + os.sep
    return os.path.abspath(abs_path).startswith(abs_public)
 
 
def is_user_owned_path(abs_path, username):
    abs_home = os.path.abspath(user_home(username)) + os.sep
    return os.path.abspath(abs_path).startswith(abs_home)
 
 
def safe_join(base, rel):
    """
    Join and ensure result stays inside base directory.
    Rejects when rel tries directory traversal or absolute paths.
    """
    if not rel:
        raise PermissionError("empty path")
    if os.path.isabs(rel):
        raise PermissionError("absolute paths not allowed")
    # disallow upward traversal tokens explicitly
    if ".." in rel.replace("\\", "/").split("/"):
        raise PermissionError("parent traversal not allowed")
    final = os.path.abspath(os.path.join(base, rel))
    base_abs = os.path.abspath(base) + os.sep
    if not final.startswith(base_abs):
        raise PermissionError("outside allowed folder")
    return final
 
 
# ---------------- Network helpers ----------------
def send_line(conn, msg):
    try:
        conn.sendall((msg + "\n").encode())
    except Exception:
        # connection may be closed by client
        pass
 
 
def recv_line(conn):
    data = b""
    while True:
        try:
            ch = conn.recv(1)
        except Exception:
            return None
        if not ch:
            return None
        if ch == b"\n":
            break
        data += ch
    try:
        return data.decode()
    except Exception:
        return None
 
 
# ---------------- Path resolver ----------------
def resolve_path_for_read(username, rel, is_admin):
    """
    Resolve a path for reading (get/read/search). For non-admins:
      - Only allow simple filenames (no subdirs)
      - Prefer user's private file, then shared file
    For admin: allow paths relative to ROOT_DIR but sanitize.
    Returns absolute path.
    """
    if is_admin:
        # For admin reading: if they provided explicit shared/ or user_data/ prefix,
        # resolve relative to ROOT_DIR. If they provided a simple filename, prefer shared first.
        rel = rel.strip()
        if rel.startswith("shared/") or rel.startswith("user_data/"):
            return safe_join(ROOT_DIR, rel)
        # simple filename -> prefer shared then user_data (consistent)
        candidate_shared = os.path.join(PUBLIC_DIR, rel)
        if os.path.exists(candidate_shared):
            return os.path.abspath(candidate_shared)
        candidate_user_any = None
        # if an admin provided a filename that exists in any user folder, allow it by resolving to that absolute path
        for d in os.listdir(USER_DATA_DIR):
            candidate = os.path.join(USER_DATA_DIR, d, rel)
            if os.path.exists(candidate):
                candidate_user_any = candidate
                break
        if candidate_user_any:
            return os.path.abspath(candidate_user_any)
        # fallback to resolving relative to root
        return safe_join(ROOT_DIR, rel)
    else:
        # non-admin: no subdirs allowed, only plain filename
        if "/" in rel or "\\" in rel:
            raise PermissionError("subdirectories not allowed for regular users")
        user_path = os.path.join(user_home(username), rel)
        shared_path = os.path.join(PUBLIC_DIR, rel)
        if os.path.exists(user_path):
            return os.path.abspath(user_path)
        if os.path.exists(shared_path):
            return os.path.abspath(shared_path)
        raise FileNotFoundError("not found")
 
 
def resolve_path_for_write(username, rel, is_admin):
    """
    Resolve a path for creating / putting / updating. For non-admins:
      - Writes always go to user's private folder.
    For admin:
      - If explicit shared/ or user_data/ prefix provided, honor (sanitized)
      - Otherwise default to shared/
    Returns absolute path (parent directories are NOT auto-created except user_home).
    """
    if is_admin:
        rel = rel.strip()
        if rel.startswith("shared/") or rel.startswith("user_data/"):
            return safe_join(ROOT_DIR, rel)
        # default admin writes go to public (shared)
        return safe_join(PUBLIC_DIR, rel)
    else:
        # regular user writes into their home
        if "/" in rel or "\\" in rel:
            raise PermissionError("subdirectories not allowed for regular users")
        return safe_join(user_home(username), rel)
 
 
# ---------------- Command handling ----------------
def handle_client(conn, addr):
    log(f"[CONNECT] {addr}")
    send_line(conn, "WELCOME - login <user> <pass> to continue")
 
    session = {"auth": False, "user": None, "role": None}
    login_attempts = 0
 
    try:
        while True:
            line = recv_line(conn)
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()
 
            # LOGIN
            if cmd == "login":
                if len(parts) != 3:
                    send_line(conn, "ERR usage: login <user> <pass>")
                    continue
                username, password = parts[1], parts[2]
                user_record = find_user_record(username)
                if not user_record or not verify_password(password, user_record.get("password", "")):
                    login_attempts += 1
                    send_line(conn, "ERR bad credentials")
                    log(f"[AUTH FAIL] {username} from {addr}")
                    if login_attempts >= MAX_LOGIN_ATTEMPTS:
                        send_line(conn, "ERR too many attempts")
                        break
                    continue
                if user_record.get("locked"):
                    send_line(conn, "ERR account locked")
                    continue
                session["auth"] = True
                session["user"] = username
                session["role"] = user_record.get("role", "user")
                send_line(conn, f"OK logged in as {username} ({session['role']})")
                log(f"[AUTH OK] {username} from {addr}")
                # ensure user's home exists
                user_home(username)
                continue
 
            # require authentication for all further commands
            if not session["auth"]:
                send_line(conn, "ERR not authenticated")
                continue
 
            username = session["user"]
            is_admin = (session["role"] == "admin")
 
            # LS -> return shared list and user list (filenames only)
            if cmd == "ls":
                try:
                    # list shared filenames
                    shared_list = sorted([f for f in os.listdir(PUBLIC_DIR) if os.path.isfile(os.path.join(PUBLIC_DIR, f))])
                    # list user filenames (for this user)
                    user_list = sorted([f for f in os.listdir(user_home(username)) if os.path.isfile(os.path.join(user_home(username), f))])
                    body = "Shared Files:\n" + ("\n".join(shared_list) if shared_list else "(none)")
                    body += "\n\nYour Files:\n" + ("\n".join(user_list) if user_list else "(none)")
                    send_line(conn, f"OK {len(body.encode())}")
                    conn.sendall(body.encode())
                    log(f"[LS] user={username} admin={is_admin}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR LS] user={username} err={e}")
                continue
            # GET (download)
            if cmd == "get":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: get <file>")
                    continue
                rel = parts[1]
                try:
                    path = resolve_path_for_read(username, rel, is_admin)
                    if not os.path.isfile(path):
                        send_line(conn, "ERR not found")
                        continue
                    size = os.path.getsize(path)
                    send_line(conn, "OK")
                    send_line(conn, str(size))
                    with open(path, "rb") as f:
                        while True:
                            chunk = f.read(BUF)
                            if not chunk:
                                break
                            conn.sendall(chunk)
                    log(f"[GET] user={username} file={rel} path={path} size={size}")
                    # If a regular user downloaded a shared file, copy it into their private folder
                    if not is_admin and is_shared_path(path):
                        dest = os.path.join(user_home(username), os.path.basename(path))
                        try:
                            if not os.path.exists(dest):
                                shutil.copy2(path, dest)
                                log(f"[COPY-TO-USER] {username} got shared file -> {dest}")
                        except Exception as e:
                            log(f"[ERR COPY-TO-USER] {e}")
                except PermissionError as pe:
                    send_line(conn, f"ERR {pe}")
                except FileNotFoundError:
                    send_line(conn, "ERR not found")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR GET] user={username} rel={rel} err={e}")
                continue
 
            # PUT (upload)
            if cmd == "put":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: put <file>")
                    continue
                rel = parts[1]
                try:
                    dest = resolve_path_for_write(username, rel, is_admin)
                    # prepare destination parent
                    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
                    send_line(conn, "OK")
                    size_line = recv_line(conn)
                    if not size_line:
                        send_line(conn, "ERR missing size")
                        continue
                    size = int(size_line.strip())
                    remaining = size
                    with open(dest, "wb") as f:
                        while remaining > 0:
                            chunk = conn.recv(min(BUF, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            remaining -= len(chunk)
                    send_line(conn, "OK")
                    log(f"[PUT] user={username} dest={dest} size={size}")
                except PermissionError as pe:
                    send_line(conn, f"ERR {pe}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR PUT] user={username} rel={rel} err={e}")
                continue
 
            # CREATE (touch empty file)
            if cmd == "create":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: create <file>")
                    continue
                rel = parts[1]
                try:
                    dest = resolve_path_for_write(username, rel, is_admin)
                    if os.path.exists(dest):
                        send_line(conn, "ERR exists")
                        continue
                    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
                    open(dest, "w").close()
                    send_line(conn, "OK")
                    log(f"[CREATE] user={username} dest={dest}")
                except PermissionError as pe:
                    send_line(conn, f"ERR {pe}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR CREATE] user={username} rel={rel} err={e}")
                continue
            # READ
            if cmd == "read":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: read <file>")
                    continue
                rel = parts[1]
                try:
                    path = resolve_path_for_read(username, rel, is_admin)
                    if not os.path.isfile(path):
                        send_line(conn, "ERR not found")
                        continue
                    # read file safely
                    with open(path, "r", errors="ignore") as f:
                        data = f.read()
                    send_line(conn, str(len(data.encode())))
                    if data:
                        conn.sendall(data.encode())
                    log(f"[READ] user={username} file={rel} path={path}")
                except PermissionError as pe:
                    send_line(conn, f"ERR {pe}")
                except FileNotFoundError:
                    send_line(conn, "ERR not found")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR READ] user={username} rel={rel} err={e}")
                continue
 
            # UPDATE (multi-line)
            if cmd == "update":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: update <file>")
                    continue
                rel = parts[1]
                try:
                    path = resolve_path_for_read(username, rel, is_admin)
                    # permission: regular users cannot update shared files directly
                    if not is_admin and is_shared_path(path):
                        send_line(conn, "ERR read-only (shared). Download and update your copy.")
                        continue
                    # regular users can only update their own files
                    if not is_admin and not is_user_owned_path(path, username):
                        send_line(conn, "ERR permission denied")
                        continue
                    # ready to receive data
                    send_line(conn, "READY")
                    size_line = recv_line(conn)
                    if not size_line:
                        send_line(conn, "ERR missing size")
                        continue
                    size = int(size_line.strip())
                    data_b = b""
                    while len(data_b) < size:
                        chunk = conn.recv(min(BUF, size - len(data_b)))
                        if not chunk:
                            break
                        data_b += chunk
                    with open(path, "w", errors="ignore") as f:
                        f.write(data_b.decode(errors="ignore"))
                    send_line(conn, "OK")
                    log(f"[UPDATE] user={username} file={rel} path={path} size={len(data_b)}")
                except PermissionError as pe:
                    send_line(conn, f"ERR {pe}")
                except FileNotFoundError:
                    send_line(conn, "ERR not found")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR UPDATE] user={username} rel={rel} err={e}")
                continue
 
            # DELETE
            if cmd == "delete":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: delete <file>")
                    continue
                rel = parts[1]
                try:
                    # Determine target path; for deletion we will be stricter:
                    target = resolve_path_for_read(username, rel, is_admin)
                    if not os.path.exists(target):
                        send_line(conn, "ERR not found")
                        continue
                    # If user is not admin, only allow deletion inside their own user directory
                    if not is_admin:
                        if not is_user_owned_path(target, username):
                            send_line(conn, "ERR permission denied (can only delete your own files)")
                            continue
                    # Admin may delete anywhere (shared or user_data)
                    if os.path.isdir(target):
                        # don't allow directory deletion via delete; use rmdir
                        send_line(conn, "ERR is directory")
                        continue
                    os.remove(target)
                    send_line(conn, "OK")
                    log(f"[DELETE] user={username} target={target}")
                except PermissionError as pe:
                    send_line(conn, f"ERR {pe}")
                except FileNotFoundError:
                    send_line(conn, "ERR not found")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR DELETE] user={username} rel={rel} err={e}")
                continue
 
            # MKDIR (admin only)
            if cmd == "mkdir":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: mkdir <dir>")
                    continue
                if not is_admin:
                    send_line(conn, "ERR admin required")
                    continue
                rel = parts[1]
                try:
                    path = resolve_path_for_write(username, rel, True)
                    os.makedirs(path, exist_ok=False)
                    send_line(conn, "OK")
                    log(f"[MKDIR] admin={username} dir={path}")
                except FileExistsError:
                    send_line(conn, "ERR exists")
                except PermissionError as pe:
                    send_line(conn, f"ERR {pe}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR MKDIR] admin={username} rel={rel} err={e}")
                continue
 
            # RMDIR (admin only)
            if cmd == "rmdir":
                if len(parts) != 2:
                    send_line(conn, "ERR usage: rmdir <dir>")
                    continue
                if not is_admin:
                    send_line(conn, "ERR admin required")
                    continue
                rel = parts[1]
                try:
                    path = safe_join(ROOT_DIR, rel) if (rel.startswith("shared/") or rel.startswith("user_data/")) else safe_join(ROOT_DIR, rel)
                    os.rmdir(path)
                    send_line(conn, "OK")
                    log(f"[RMDIR] admin={username} dir={path}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR RMDIR] admin={username} rel={rel} err={e}")
                continue
 
            # RENAME (admin only)
            if cmd == "rename":
                if len(parts) != 3:
                    send_line(conn, "ERR usage: rename <old> <new>")
                    continue
                if not is_admin:
                    send_line(conn, "ERR admin required")
                    continue
                old_rel, new_rel = parts[1], parts[2]
                try:
                    old_path = resolve_path_for_read(username, old_rel, True)
                    new_path = resolve_path_for_write(username, new_rel, True)
                    os.rename(old_path, new_path)
                    send_line(conn, "OK")
                    log(f"[RENAME] admin={username} {old_path} -> {new_path}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR RENAME] admin={username} {old_rel}->{new_rel} err={e}")
                continue
            # MOVE (admin only)
            if cmd == "move":
                if len(parts) != 3:
                    send_line(conn, "ERR usage: move <src> <dst>")
                    continue
                if not is_admin:
                    send_line(conn, "ERR admin required")
                    continue
                src_rel, dst_rel = parts[1], parts[2]
                try:
                    src = resolve_path_for_read(username, src_rel, True)
                    dst = resolve_path_for_write(username, dst_rel, True)
                    shutil.move(src, dst)
                    send_line(conn, "OK")
                    log(f"[MOVE] admin={username} {src}->{dst}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR MOVE] admin={username} err={e}")
                continue
 
            # COPY (admin only)
            if cmd == "copy":
                if len(parts) != 3:
                    send_line(conn, "ERR usage: copy <src> <dst>")
                    continue
                if not is_admin:
                    send_line(conn, "ERR admin required")
                    continue
                src_rel, dst_rel = parts[1], parts[2]
                try:
                    src = resolve_path_for_read(username, src_rel, True)
                    dst = resolve_path_for_write(username, dst_rel, True)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst)
                    else:
                        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
                        shutil.copy2(src, dst)
                    send_line(conn, "OK")
                    log(f"[COPY] admin={username} {src}->{dst}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR COPY] admin={username} err={e}")
                continue
 
            # SEARCH
            if cmd == "search":
                # search name <pattern> OR search content <pattern>
                if len(parts) < 3:
                    send_line(conn, "ERR usage: search <name|content> <pattern>")
                    continue
                mode = parts[1].lower()
                pattern = " ".join(parts[2:])
                try:
                    matches = []
                    if is_admin:
                        roots = [PUBLIC_DIR, USER_DATA_DIR]
                    else:
                        roots = [PUBLIC_DIR, user_home(username)]
                    for root in roots:
                        for r, _, files in os.walk(root):
                            for f in files:
                                full = os.path.join(r, f)
                                relpath = os.path.relpath(full, ROOT_DIR)
                                if mode == "name":
                                    if pattern in f:
                                        matches.append(relpath)
                                elif mode == "content":
                                    try:
                                        with open(full, "r", errors="ignore") as fh:
                                            if pattern in fh.read():
                                                matches.append(relpath)
                                    except Exception:
                                        pass
                    body = "\n".join(matches)
                    send_line(conn, f"OK {len(body.encode())}")
                    if body:
                        conn.sendall(body.encode())
                    log(f"[SEARCH] user={username} mode={mode} pattern={pattern}")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                    log(f"[ERR SEARCH] user={username} err={e}")
                continue
 
            # QUIT
            if cmd == "quit":
                send_line(conn, "BYE")
                log(f"[QUIT] user={username} addr={addr}")
                break
 
            # Unknown command
            send_line(conn, "ERR unknown command")
            log(f"[UNKNOWN CMD] user={username} cmd={line}")
 
    except Exception as e:
        log(f"[CLIENT ERROR] addr={addr} err={e}")
 
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log(f"[DISCONNECT] {addr}")
 
 
# ---------------- Server launcher ----------------
def start_server():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("Missing server.crt / server.key in server_file/ - generate them before starting.")
        return
 
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind((HOST, PORT))
    raw.listen(50)
 
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
 
    print(f"[TLS SERVER] listening on {HOST}:{PORT}")
    log("[SERVER STARTED]")
 
    try:
        while True:
            client_sock, addr = raw.accept()
            try:
                tls_conn = context.wrap_socket(client_sock, server_side=True)
            except ssl.SSLError as se:
                log(f"[TLS ERROR] {se}")
                client_sock.close()
                continue
            t = threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        raw.close()
 
 
if __name__ == "__main__":
    start_server()
 
 