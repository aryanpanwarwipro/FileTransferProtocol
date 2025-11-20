#!/usr/bin/env python3
import socket, os, threading, shutil
 
HOST = "0.0.0.0"
PORT = 5001
BUF = 4096
 
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SERVER_DIR)
 
USERS_FILE = os.path.join(SERVER_DIR, "users.txt")
 
def load_users():
    users = {}
    if not os.path.isfile(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            f.write("admin:admin:admin\n")
    with open(USERS_FILE, "r") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            try:
                u,p,r = line.split(":",2)
                users[u] = {"pass":p, "role": r}
            except:
                pass
    return users
 
USERS = load_users()
 
def send_line(conn, text):
    conn.sendall((text + "\n").encode())
 
def recv_line(conn):
    data = b''
    while True:
        ch = conn.recv(1)
        if not ch:
            return None
        if ch == b'\n':
            break
        data += ch
    return data.decode()
 
def check_admin(session):
    return session.get("auth") and session.get("role") == "admin"
 
def handle_client(conn, addr):
    print(f"[CLIENT CONNECTED] {addr}")
    session = {"user": None, "auth": False, "role": None}
 
    try:
        send_line(conn, "WELCOME - login <user> <pass> to continue")
 
        while True:
            cmdline = recv_line(conn)
            if cmdline is None:
                break
 
            parts = cmdline.strip().split()
            if not parts:
                continue
 
            cmd = parts[0].lower()
 
            # ---------------- AUTH ----------------
            if cmd == "login":
                if len(parts) < 3:
                    send_line(conn, "ERR usage: login <user> <pass>")
                    continue
                user, pwd = parts[1], parts[2]
                info = USERS.get(user)
                if info and info["pass"] == pwd:
                    session["user"] = user
                    session["auth"] = True
                    session["role"] = info["role"]
                    send_line(conn, f"OK logged in as {user} ({info['role']})")
                else:
                    send_line(conn, "ERR bad credentials")
                continue
 
            if not session["auth"]:
                send_line(conn, "ERR not authenticated")
                continue
 
            # ---------------- LIST ----------------
            if cmd == "ls":
                files = "\n".join(os.listdir())
                send_line(conn, f"OK {len(files.encode())}")
                if files:
                    conn.sendall(files.encode())
                continue
 
            # ---------------- GET ----------------
            if cmd == "get":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: get <file>")
                    continue
                fname = parts[1]
                if not os.path.isfile(fname):
                    send_line(conn, "ERR not found")
                    continue
                send_line(conn, "OK")
                send_line(conn, str(os.path.getsize(fname)))
                with open(fname, "rb") as f:
                    while chunk := f.read(BUF):
                        conn.sendall(chunk)
                continue
 
            # ---------------- PUT ----------------
            if cmd == "put":
                if len(parts) < 2:
                    send_line(conn, "ERR usage: put <file>")
                    continue
                fname = parts[1]
                send_line(conn, "OK")
                size = int(recv_line(conn))
                remaining = size
                with open(fname, "wb") as f:
                    while remaining > 0:
                        chunk = conn.recv(min(BUF, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                send_line(conn, "OK")
                continue
 
            # ---------------- CREATE ----------------
            if cmd == "create":
                fname = parts[1]
                if os.path.exists(fname):
                    send_line(conn, "ERR exists")
                else:
                    open(fname, "w").close()
                    send_line(conn, "OK")
                continue
 
            # ---------------- READ ----------------
            if cmd == "read":
                fname = parts[1]
                if not os.path.isfile(fname):
                    send_line(conn, "ERR not found")
                    continue
                with open(fname, "r", errors="ignore") as f:
                    data = f.read().encode()
                send_line(conn, str(len(data)))
                conn.sendall(data)
                continue
 
            # ---------------- UPDATE ----------------
            if cmd == "update":
                fname = parts[1]
                if not os.path.isfile(fname):
                    send_line(conn, "ERR not found")
                    continue
                send_line(conn, "READY")
                size = int(recv_line(conn))
                text = conn.recv(size).decode(errors="ignore")
                with open(fname, "w") as f:
                    f.write(text)
                send_line(conn, "OK")
                continue
 
            # ---------------- DELETE (admin) ----------------
            if cmd == "delete":
                if not check_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                fname = parts[1]
                if not os.path.exists(fname):
                    send_line(conn, "ERR not found")
                else:
                    os.remove(fname)
                    send_line(conn, "OK")
                continue
 
            # ---------------- MKDIR (admin) ----------------
            if cmd == "mkdir":
                if not check_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                try:
                    os.mkdir(parts[1])
                    send_line(conn, "OK")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                continue
 
            # ---------------- RMDIR (admin) ----------------
            if cmd == "rmdir":
                if not check_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                try:
                    os.rmdir(parts[1])
                    send_line(conn, "OK")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                continue
 
            # ---------------- RENAME (admin) ----------------
            if cmd == "rename":
                if not check_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                old, new = parts[1], parts[2]
                try:
                    os.rename(old, new)
                    send_line(conn, "OK")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                continue
 
            # ---------------- MOVE / COPY (admin) ----------------
            if cmd == "move":
                if not check_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                try:
                    shutil.move(parts[1], parts[2])
                    send_line(conn, "OK")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                continue
 
            if cmd == "copy":
                if not check_admin(session):
                    send_line(conn, "ERR admin required")
                    continue
                try:
                    shutil.copy2(parts[1], parts[2])
                    send_line(conn, "OK")
                except Exception as e:
                    send_line(conn, f"ERR {e}")
                continue
 
            # ---------------- SEARCH ----------------
            if cmd == "search":
                mode = parts[1]
                pattern = " ".join(parts[2:])
                matches = []
 
                for root, _, files in os.walk("."):
                    for f in files:
                        path = os.path.join(root, f)
 
                        if mode == "name" and pattern in f:
                            matches.append(path)
 
                        elif mode == "content":
                            try:
                                with open(path, "r", errors="ignore") as fh:
                                    if pattern in fh.read():
                                        matches.append(path)
                            except:
                                pass
 
                out = "\n".join(matches)
                send_line(conn, f"OK {len(out.encode())}")
                if out:
                    conn.sendall(out.encode())
                continue
 
            # ---------------- QUIT ----------------
            if cmd == "quit":
                send_line(conn, "BYE")
                break
 
            # ---------------- UNKNOWN ----------------
            send_line(conn, "ERR unknown command")
 
    except Exception as e:
        print("[SERVER ERROR]", e)
 
    print(f"[CLIENT LEFT] {addr}")
    conn.close()
 
def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    print(f"[SERVER RUNNING] port {PORT}")
 
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
 
if __name__ == "__main__":
    main()