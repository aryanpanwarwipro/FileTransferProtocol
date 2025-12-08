#!/usr/bin/env python3

import os
import socket
import ssl
import threading
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox
 
HOST = "127.0.0.1"
PORT = 5001
BUF = 4096
 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_USER_DATA = os.path.join(BASE_DIR, "user_data")
os.makedirs(LOCAL_USER_DATA, exist_ok=True)
 
 
# ---------------- Network Helpers ----------------
 
def recv_line(sock):
    data = b""
    while True:
        try:
            ch = sock.recv(1)
        except:
            return None
        if not ch:
            return None
        if ch == b"\n":
            break
        data += ch
    return data.decode()
 
 
def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(min(BUF, size - len(data)))
        if not chunk:
            break
        data += chunk
    return data
 
 
class FTPClient:
    def __init__(self):
        self.sock = None
        self.current_user = None
        self.role = None
        self.local_user_dir = None
        self.lock = threading.Lock()
 
    def connect(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE   # Self-signed cert
 
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = context.wrap_socket(raw, server_hostname="localhost")
        self.sock.connect((HOST, PORT))
 
        return recv_line(self.sock)
 
    def send_line(self, text):
        with self.lock:
            self.sock.sendall((text + "\n").encode())
 
    def login(self, username, password):
        self.send_line(f"login {username} {password}")
        response = recv_line(self.sock)
        if response and response.startswith("OK"):
            self.current_user = username
            # parse role
            if "(admin)" in response.lower():
                self.role = "admin"
            else:
                self.role = "user"
            # create local folder
            self.local_user_dir = os.path.join(LOCAL_USER_DATA, username)
            os.makedirs(self.local_user_dir, exist_ok=True)
        return response
 
    def quit(self):
        try:
            self.send_line("quit")
        except:
            pass
        try:
            self.sock.close()
        except:
            pass
        self.sock = None
 
 
ftp = FTPClient()
 
 
# ---------------- GUI ----------------
 
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure FTP GUI Client")
        self.geometry("980x600")
 
        self.create_widgets()
        self.set_ui_state(disabled=True)
 
    # ---------------- UI Construction ----------------
 
    def create_widgets(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=5)
 
        # Username & Password
        ttk.Label(top, text="Username:").pack(side="left", padx=(0, 5))
        self.entry_user = ttk.Entry(top, width=12)
        self.entry_user.pack(side="left", padx=(0, 10))
 
        ttk.Label(top, text="Password:").pack(side="left", padx=(0, 5))
        self.entry_pass = ttk.Entry(top, width=12, show="*")
        self.entry_pass.pack(side="left", padx=(0, 10))
 
        # Login / Logout
        self.btn_login = ttk.Button(top, text="Connect + Login", command=self.threaded_login)
        self.btn_login.pack(side="left", padx=5)
 
        self.btn_logout = ttk.Button(top, text="Logout", command=self.do_logout, state="disabled")
        self.btn_logout.pack(side="left", padx=5)
 
        # Status label
        self.lbl_status = ttk.Label(top, text="Not connected", foreground="blue")
        self.lbl_status.pack(side="left", padx=15)
 
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=10, pady=10)
 
        left = ttk.Frame(mid)
        left.pack(side="left", fill="both", expand=True)
 
        right = ttk.Frame(mid)
        right.pack(side="left", fill="both", expand=True, padx=10)
 
        ttk.Label(left, text="Shared Files").pack(anchor="w")
        self.lb_shared = tk.Listbox(left)
        self.lb_shared.pack(fill="both", expand=True)
 
        ttk.Label(right, text="Your Files").pack(anchor="w")
        self.lb_user = tk.Listbox(right)
        self.lb_user.pack(fill="both", expand=True)
 
        # Buttons Row
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=10, pady=10)
 
        self.btn_get = ttk.Button(bottom, text="Download (GET)", command=self.threaded_get)
        self.btn_put = ttk.Button(bottom, text="Upload (PUT)", command=self.threaded_put)
        self.btn_create = ttk.Button(bottom, text="Create File", command=self.threaded_create)
        self.btn_read = ttk.Button(bottom, text="Read File", command=self.threaded_read)
        self.btn_update = ttk.Button(bottom, text="Update File", command=self.threaded_update)
        self.btn_delete = ttk.Button(bottom, text="Delete File", command=self.threaded_delete)
 
        # Layout buttons
        self.btn_get.pack(side="left", padx=5)
        self.btn_put.pack(side="left", padx=5)
        self.btn_create.pack(side="left", padx=5)
        self.btn_read.pack(side="left", padx=5)
        self.btn_update.pack(side="left", padx=5)
        self.btn_delete.pack(side="left", padx=5)
 
        # Progress bar
        self.progress = ttk.Progressbar(bottom, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(side="right", padx=10)
 
        # Console
        self.console = tk.Text(self, height=10)
        self.console.pack(fill="x", padx=10, pady=(0, 10))
 
    # ---------------- Utility Methods ----------------
 
    def log(self, msg):
        self.console.insert("end", msg + "\n")
        self.console.see("end")
 
    def set_ui_state(self, disabled=True):
        state = "disabled" if disabled else "normal"
        for w in [
            self.btn_get, self.btn_put, self.btn_create,
            self.btn_read, self.btn_update, self.btn_delete
        ]:
            w.config(state=state)
 
    # ---------------- Threaded Wrappers ----------------
 
    def threaded_login(self):
        threading.Thread(target=self.do_login, daemon=True).start()
 
    def threaded_refresh(self):
        threading.Thread(target=self.refresh_lists, daemon=True).start()
 
    def threaded_get(self):
        threading.Thread(target=self.do_get, daemon=True).start()
 
    def threaded_put(self):
        threading.Thread(target=self.do_put, daemon=True).start()
 
    def threaded_create(self):
        threading.Thread(target=self.do_create, daemon=True).start()
 
    def threaded_read(self):
        threading.Thread(target=self.do_read, daemon=True).start()
 
    def threaded_update(self):
        threading.Thread(target=self.do_update, daemon=True).start()
 
    def threaded_delete(self):
        threading.Thread(target=self.do_delete, daemon=True).start()
 
    # ---------------- Login / Logout ----------------
 
    def do_login(self):
        user = self.entry_user.get().strip()
        pw = self.entry_pass.get().strip()
 
        if not user or not pw:
            messagebox.showwarning("Input Error", "Enter username and password.")
            return
 
        try:
            welcome = ftp.connect()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Cannot connect: {e}")
            return
 
        self.log(f"Server: {welcome}")
 
        response = ftp.login(user, pw)
        self.log(response)
 
        if response.startswith("OK"):
            role_text = "ADMIN" if ftp.role == "admin" else "USER"
            self.lbl_status.config(text=f"Logged in as {ftp.current_user} ({role_text})", foreground="green")
 
            self.set_ui_state(disabled=False)
            self.btn_logout.config(state="normal")
            self.threaded_refresh()
        else:
            messagebox.showerror("Login Failed", response)
            ftp.quit()
 
    def do_logout(self):
        ftp.quit()
        self.lbl_status.config(text="Logged out", foreground="blue")
        self.set_ui_state(disabled=True)
        self.btn_logout.config(state="disabled")
 
        # Clear fields and lists
        self.lb_shared.delete(0, "end")
        self.lb_user.delete(0, "end")
        self.entry_user.delete(0, "end")
        self.entry_pass.delete(0, "end")
 
    # ---------------- File Listing ----------------
 
    def refresh_lists(self):
        ftp.send_line("ls")
        header = recv_line(ftp.sock)
        if not header or not header.startswith("OK"):
            return
        size = int(header.split()[1])
        body = recv_exact(ftp.sock, size).decode()
 
        shared, user_files = body.split("\n\nYour Files:\n")
        shared = shared.replace("Shared Files:\n", "").strip()
        user_files = user_files.strip()
 
        self.lb_shared.delete(0, "end")
        self.lb_user.delete(0, "end")
 
        if shared != "(none)":
            for f in shared.splitlines():
                self.lb_shared.insert("end", f)
 
        if user_files != "(none)":
            for f in user_files.splitlines():
                self.lb_user.insert("end", f)
 
    # ---------------- GET ----------------
 
    def do_get(self):
        sel = self.lb_user.curselection() or self.lb_shared.curselection()
        if not sel:
            messagebox.showinfo("Select File", "Select a file to download.")
            return
 
        lb = self.lb_user if self.lb_user.curselection() else self.lb_shared
        filename = os.path.basename(lb.get(sel[0]))
 
        local = os.path.join(ftp.local_user_dir, filename)
        self.progress["value"] = 0
 
        def progress_cb(done, total):
            if total > 0:
                self.progress["value"] = int(done / total * 100)
 
        ftp.send_line(f"get {filename}")
        header = recv_line(ftp.sock)
 
        if header != "OK":
            self.log(header)
            return
 
        size = int(recv_line(ftp.sock))
 
        received = 0
        with open(local, "wb") as f:
            while received < size:
                chunk = ftp.sock.recv(min(BUF, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
                progress_cb(received, size)
 
        self.log(f"Downloaded → {local}")
        self.progress["value"] = 0
        self.threaded_refresh()
        # ---------------- PUT ----------------
 
    def do_put(self):
        path = filedialog.askopenfilename(initialdir=ftp.local_user_dir)
        if not path:
            return
 
        filename = os.path.basename(path)
        size = os.path.getsize(path)
 
        ftp.send_line(f"put {filename}")
        header = recv_line(ftp.sock)
 
        if header != "OK":
            self.log(header)
            return
 
        ftp.send_line(str(size))
        sent = 0
 
        def progress_cb(done, total):
            self.progress["value"] = int(done / total * 100)
 
        with open(path, "rb") as f:
            while True:
                chunk = f.read(BUF)
                if not chunk:
                    break
                ftp.sock.sendall(chunk)
                sent += len(chunk)
                progress_cb(sent, size)
 
        reply = recv_line(ftp.sock)
        self.log(f"UPLOAD: {reply}")
        self.progress["value"] = 0
        self.threaded_refresh()
 
    # ---------------- CREATE ----------------
 
    def do_create(self):
        name = simpledialog.askstring("Create File", "Enter filename:")
        if not name:
            return
 
        ftp.send_line(f"create {name}")
        self.log(recv_line(ftp.sock))
        self.threaded_refresh()
 
    # ---------------- READ ----------------
 
    def do_read(self):
        sel = self.lb_user.curselection() or self.lb_shared.curselection()
        if not sel:
            messagebox.showinfo("Select File", "Select a file to read.")
            return
 
        lb = self.lb_user if self.lb_user.curselection() else self.lb_shared
        filename = os.path.basename(lb.get(sel[0]))
 
        ftp.send_line(f"read {filename}")
        header = recv_line(ftp.sock)
 
        if header.startswith("ERR"):
            self.log(header)
            return
 
        size = int(header.strip())
        body = recv_exact(ftp.sock, size).decode()
 
        # Show popup
        top = tk.Toplevel(self)
        top.title(f"Read: {filename}")
        text = tk.Text(top, wrap="word", height=20, width=80)
        text.pack(fill="both", expand=True)
        text.insert("1.0", body)
 
    # ---------------- UPDATE ----------------
 
    def do_update(self):
        sel = self.lb_user.curselection() or self.lb_shared.curselection()
        if not sel:
            messagebox.showinfo("Select File", "Select a file to update.")
            return
 
        lb = self.lb_user if self.lb_user.curselection() else self.lb_shared
        filename = os.path.basename(lb.get(sel[0]))
 
        ftp.send_line(f"update {filename}")
        header = recv_line(ftp.sock)
        if header != "READY":
            self.log(header)
            return
 
        # Edit popup
        top = tk.Toplevel(self)
        top.title(f"Update: {filename}")
        text = tk.Text(top, wrap="word", height=20, width=80)
        text.pack(fill="both", expand=True)
 
        def send_update():
            data = text.get("1.0", "end").rstrip("\n")
            ftp.send_line(str(len(data)))
            if data:
                ftp.sock.sendall(data.encode())
            self.log(recv_line(ftp.sock))
            top.destroy()
            self.threaded_refresh()
 
        btn = ttk.Button(top, text="Save Update", command=send_update)
        btn.pack(pady=10)
 
    # ---------------- DELETE ----------------
 
    def do_delete(self):
        sel = self.lb_user.curselection() or self.lb_shared.curselection()
        if not sel:
            messagebox.showinfo("Select File", "Select a file to delete.")
            return
 
        lb = self.lb_user if self.lb_user.curselection() else self.lb_shared
        filename = os.path.basename(lb.get(sel[0]))
 
        if not messagebox.askyesno("Confirm Delete", f"Delete {filename}?"):
            return
 
        ftp.send_line(f"delete {filename}")
        reply = recv_line(ftp.sock)
 
        self.log(f"DELETE: {reply}")
        self.threaded_refresh()
 
    # ---------------- Search ----------------
 
    # (Left out since unchanged — can add back if needed)
 
    # ---------------- CLOSE ----------------
 
    def on_close(self):
        ftp.quit()
        self.destroy()
 
 
if __name__ == "__main__":
    app = App()
    app.mainloop()