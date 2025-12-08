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
 
# ---------------- networking helpers ----------------
def recv_line(sock):
    data = b""
    while True:
        ch = sock.recv(1)
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
        self.user_dir = None
        self.lock = threading.Lock()  # protect socket usage
 
    def connect(self):
        """Create TLS-wrapped socket and connect."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # local testing with self-signed
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = context.wrap_socket(raw, server_hostname="localhost")
        self.sock.connect((HOST, PORT))
        # read welcome
        return recv_line(self.sock)
 
    def close(self):
        if self.sock:
            try:
                with self.lock:
                    self.sock.close()
            except:
                pass
            self.sock = None
 
    def send_line(self, text):
        with self.lock:
            self.sock.sendall((text + "\n").encode())
 
    def login(self, username, password):
        self.send_line(f"login {username} {password}")
        res = recv_line(self.sock)
        if res and res.startswith("OK"):
            self.current_user = username
            self.user_dir = os.path.join(LOCAL_USER_DATA, username)
            os.makedirs(self.user_dir, exist_ok=True)
        return res
 
    def simple_command_response(self, cmd):
        """Send a command and return the first-line response"""
        self.send_line(cmd)
        return recv_line(self.sock)
 
    def ls(self):
        self.send_line("ls")
        header = recv_line(self.sock)
        if not header:
            return "ERR Connection lost", ""
        if header.startswith("OK "):
            size = int(header.split()[1])
            body = recv_exact(self.sock, size).decode()
            return "OK", body
        return header, ""
 
    def read_file(self, filename):
        self.send_line(f"read {filename}")
        header = recv_line(self.sock)
        if not header:
            return "ERR Connection lost"
        if header.startswith("ERR"):
            return header
        try:
            size = int(header.strip())
            if size == 0:
                return "(empty)"
            data = recv_exact(self.sock, size).decode(errors="ignore")
            return data
        except:
            return "ERR invalid response"
 
    def create_file(self, filename):
        self.send_line(f"create {filename}")
        return recv_line(self.sock)
 
    def delete_file(self, filename):
        self.send_line(f"delete {filename}")
        return recv_line(self.sock)
 
    def search(self, mode, pattern):
        self.send_line(f"search {mode} {pattern}")
        header = recv_line(self.sock)
        if not header:
            return "ERR connection lost"
        if header.startswith("OK "):
            size = int(header.split()[1])
            body = recv_exact(self.sock, size).decode()
            return body
        return header
 
    def update_file(self, filename, text):
        self.send_line(f"update {filename}")
        header = recv_line(self.sock)
        if header != "READY":
            return header
        self.send_line(str(len(text)))
        if text:
            with self.lock:
                self.sock.sendall(text.encode())
        return recv_line(self.sock)
 
    def put_file_from_local(self, filename, local_path, progress_callback=None):
        # precondition: local_path exists
        # server should reply 'OK' before sending size
        self.send_line(f"put {filename}")
        header = recv_line(self.sock)
        if header != "OK":
            return header
        size = os.path.getsize(local_path)
        # send size
        self.send_line(str(size))
        sent = 0
        with open(local_path, "rb") as f:
            while True:
                chunk = f.read(BUF)
                if not chunk:
                    break
                with self.lock:
                    self.sock.sendall(chunk)
                sent += len(chunk)
                if progress_callback:
                    progress_callback(sent, size)
        return recv_line(self.sock)
 
    def get_file_to_local(self, filename, local_path, progress_callback=None):
        self.send_line(f"get {filename}")
        header = recv_line(self.sock)
        if header != "OK":
            return header
        size_line = recv_line(self.sock)
        try:
            size = int(size_line.strip())
        except:
            return "ERR invalid size"
        received = 0
        with open(local_path, "wb") as f:
            while received < size:
                chunk = self.sock.recv(min(BUF, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
                if progress_callback:
                    progress_callback(received, size)
        return "OK"
 
    def quit(self):
        try:
            self.send_line("quit")
        except:
            pass
        self.close()
 
ftp = FTPClient()
 
# ---------------- GUI ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure FTP GUI Client")
        self.geometry("900x560")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
 
        # frames
        top = ttk.Frame(self)
        top.pack(side="top", fill="x", padx=8, pady=6)
 
        mid = ttk.Frame(self)
        mid.pack(side="top", fill="both", expand=True, padx=8, pady=6)
 
        bottom = ttk.Frame(self)
        bottom.pack(side="bottom", fill="x", padx=8, pady=6)
 
        # top: connection / login
        ttk.Label(top, text="Server:").pack(side="left")
        ttk.Label(top, text=f"{HOST}:{PORT}").pack(side="left", padx=(0,10))
 
        ttk.Label(top, text="Username:").pack(side="left")
        self.ent_user = ttk.Entry(top, width=12)
        self.ent_user.pack(side="left")
 
        ttk.Label(top, text="Password:").pack(side="left", padx=(6,0))
        self.ent_pass = ttk.Entry(top, width=12, show="*")
        self.ent_pass.pack(side="left")
 
        self.btn_connect = ttk.Button(top, text="Connect+Login", command=self.threaded_login)
        self.btn_connect.pack(side="left", padx=8)
 
        self.lbl_status = ttk.Label(top, text="Not connected", foreground="blue")
        self.lbl_status.pack(side="left", padx=10)
 
        # mid: lists and file operations
        left = ttk.Frame(mid)
        left.pack(side="left", fill="both", expand=True)
 
        right = ttk.Frame(mid)
        right.pack(side="left", fill="both", expand=True, padx=(8,0))
 
        # Shared files list
        ttk.Label(left, text="Shared files").pack(anchor="w")
        self.lb_shared = tk.Listbox(left)
        self.lb_shared.pack(fill="both", expand=True)
 
        # user files list
        ttk.Label(right, text="Your files").pack(anchor="w")
        self.lb_user = tk.Listbox(right)
        self.lb_user.pack(fill="both", expand=True)
 
        # operations panel
        ops = ttk.Frame(self)
        ops.pack(side="left", padx=8, pady=6)
 
        op_frame = ttk.Frame(bottom)
        op_frame.pack(side="left")
 
        # action buttons
        self.btn_get = ttk.Button(op_frame, text="Get → Download", command=self.threaded_get)
        self.btn_get.grid(row=0, column=0, padx=4, pady=3)
 
        self.btn_put = ttk.Button(op_frame, text="Put ← Upload", command=self.threaded_put)
        self.btn_put.grid(row=0, column=1, padx=4, pady=3)
 
        self.btn_create = ttk.Button(op_frame, text="Create", command=self.threaded_create)
        self.btn_create.grid(row=0, column=2, padx=4, pady=3)
 
        self.btn_read = ttk.Button(op_frame, text="Read", command=self.threaded_read)
        self.btn_read.grid(row=0, column=3, padx=4, pady=3)
 
        self.btn_update = ttk.Button(op_frame, text="Update", command=self.threaded_update)
        self.btn_update.grid(row=0, column=4, padx=4, pady=3)
 
        self.btn_delete = ttk.Button(op_frame, text="Delete (admin)", command=self.threaded_delete)
        self.btn_delete.grid(row=0, column=5, padx=4, pady=3)
 
        ttk.Label(bottom, text="Search:").pack(side="left", padx=(12,4))
        self.ent_search = ttk.Entry(bottom, width=24)
        self.ent_search.pack(side="left")
        self.cmb_mode = ttk.Combobox(bottom, values=["name","content"], width=8)
        self.cmb_mode.current(0)
        self.cmb_mode.pack(side="left", padx=4)
        self.btn_search = ttk.Button(bottom, text="Search", command=self.threaded_search)
        self.btn_search.pack(side="left", padx=6)
 
        self.progress = ttk.Progressbar(bottom, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(side="right")
 
        # console output
        self.txt_console = tk.Text(self, height=8)
        self.txt_console.pack(side="bottom", fill="x", padx=8, pady=(0,8))
 
        # initial state
        self.set_ui_state(connected=False)
 
    # ---------------- UI helpers ----------------
    def log(self, text):
        self.txt_console.insert("end", text + "\n")
        self.txt_console.see("end")
 
    def set_ui_state(self, connected):
        state = "normal" if connected else "disabled"
        for w in [self.btn_get, self.btn_put, self.btn_create, self.btn_read,
                  self.btn_update, self.btn_delete, self.btn_search]:
            w.config(state=state)
        if connected:
            self.lbl_status.config(text=f"Logged in: {ftp.current_user}", foreground="green")
            self.btn_connect.config(text="Reconnect/Login")
        else:
            self.lbl_status.config(text="Not connected", foreground="blue")
            self.btn_connect.config(text="Connect+Login")
            self.lb_shared.delete(0, "end")
            self.lb_user.delete(0, "end")
            # ---------------- threads wrappers ----------------
    def threaded_login(self):
        threading.Thread(target=self.do_login, daemon=True).start()
 
    def threaded_refresh_lists(self):
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
 
    def threaded_search(self):
        threading.Thread(target=self.do_search, daemon=True).start()
 
    # ---------------- actions ----------------
    def do_login(self):
        user = self.ent_user.get().strip()
        pw = self.ent_pass.get().strip()
        if not user or not pw:
            messagebox.showwarning("Input", "Enter username and password")
            return
        try:
            welcome = ftp.connect()
        except Exception as e:
            messagebox.showerror("Connection", f"Cannot connect: {e}")
            return
        self.log(f"Server: {welcome}")
        res = ftp.login(user, pw)
        self.log(res)
        if res and res.startswith("OK"):
            self.set_ui_state(True)
            self.threaded_refresh_lists()
        else:
            self.set_ui_state(False)
 
    def refresh_lists(self):
        ok, body = ftp.ls()
        if ok != "OK":
            self.log(f"LS ERROR: {ok}")
            return
        # split into two parts ("Shared Files:" / "Your Files:")
        parts = body.split("\n\nYour Files:\n")
        shared_block = parts[0].replace("Shared Files:\n","").strip()
        your_block = parts[1].strip() if len(parts) > 1 else ""
        self.lb_shared.delete(0, "end")
        self.lb_user.delete(0, "end")
        for s in shared_block.splitlines():
            if s.strip():
                self.lb_shared.insert("end", s.strip())
        for s in your_block.splitlines():
            if s.strip():
                self.lb_user.insert("end", s.strip())
 
    def do_get(self):
        # prefer selected in user list, else shared
        sel = self.lb_user.curselection()
        if sel:
            filename = os.path.basename(self.lb_user.get(sel[0]))
        else:
            sel = self.lb_shared.curselection()
            if sel:
                filename = os.path.basename(self.lb_shared.get(sel[0]))
            else:
                messagebox.showinfo("Select", "Select a file from Your files or Shared files list first")
                return
 
        # local path in user's own folder
        local = os.path.join(LOCAL_USER_DATA, ftp.current_user, filename)
        os.makedirs(os.path.dirname(local), exist_ok=True)
        self.progress["value"] = 0
 
        def progress_cb(done, total):
            if total:
                val = int(done / total * 100)
                self.progress["value"] = val
 
        self.log(f"Downloading {filename} ...")
        res = ftp.get_file_to_local(filename, local, progress_callback=progress_cb)
        if res == "OK":
            self.log(f"Downloaded to {local}")
            # after get, refresh listing because server may copy shared->user_data
            self.threaded_refresh_lists()
        else:
            self.log(f"GET ERROR: {res}")
        self.progress["value"] = 0
 
    def do_put(self):
        # select a file to upload; must be inside local user dir
        cur_user = ftp.current_user
        if not cur_user:
            messagebox.showwarning("Login", "Please login first")
            return
        initialdir = os.path.join(LOCAL_USER_DATA, cur_user)
        os.makedirs(initialdir, exist_ok=True)
        path = filedialog.askopenfilename(initialdir=initialdir, title="Select file to upload")
        if not path:
            return
        # ensure selected file is inside user's local dir (enforce local isolation)
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(os.path.abspath(initialdir)+os.sep) and os.path.basename(path) != os.path.basename(initialdir):
            messagebox.showerror("Upload", "You must choose a file from your local user folder")
            return
        filename = os.path.basename(path)
        self.progress["value"] = 0
        def progress_cb(done, total):
            if total:
                self.progress["value"] = int(done/total*100)
        self.log(f"Uploading {filename} ...")
        res = ftp.put_file_from_local(filename, path, progress_callback=progress_cb)
        self.log(f"PUT result: {res}")
        self.progress["value"] = 0
        self.threaded_refresh_lists()
 
    def do_create(self):
        name = simpledialog.askstring("Create file", "Enter filename to create:")
        if not name:
            return
        res = ftp.create_file(name)
        self.log(f"CREATE: {res}")
        self.threaded_refresh_lists()
 
    def do_read(self):
        sel = self.lb_user.curselection()
        if sel:
            filename = os.path.basename(self.lb_user.get(sel[0]))
        else:
            sel = self.lb_shared.curselection()
            if sel:
                filename = os.path.basename(self.lb_shared.get(sel[0]))
            else:
                messagebox.showinfo("Select", "Select a file to read")
                return
        content = ftp.read_file(filename)
        if content.startswith("ERR"):
            self.log(f"READ ERROR: {content}")
        else:
            # show in popup
            top = tk.Toplevel(self)
            top.title(f"Read: {filename}")
            txt = tk.Text(top, wrap="word", height=20, width=80)
            txt.pack(fill="both", expand=True)
            txt.insert("1.0", content)
 
    def do_update(self):
        sel = self.lb_user.curselection()
        if sel:
            filename = os.path.basename(self.lb_user.get(sel[0]))
        else:
            sel = self.lb_shared.curselection()
            if sel:
                filename = os.path.basename(self.lb_shared.get(sel[0]))
            else:
                messagebox.showinfo("Select", "Select a file to update")
                return
        # show editor dialog
        top = tk.Toplevel(self)
        top.title(f"Update: {filename}")
        txt = tk.Text(top, wrap="word", height=20, width=80)
        txt.pack(fill="both", expand=True)
        def do_send():
            data = txt.get("1.0", "end-1c")
            res = ftp.update_file(filename, data)
            self.log(f"UPDATE: {res}")
            top.destroy()
            self.threaded_refresh_lists()
        btn = ttk.Button(top, text="Save", command=do_send)
        btn.pack(pady=6)
 
    def do_delete(self):
        sel = self.lb_user.curselection()
        if sel:
            filename = os.path.basename(self.lb_user.get(sel[0]))
        else:
            sel = self.lb_shared.curselection()
            if sel:
                filename = os.path.basename(self.lb_shared.get(sel[0]))
            else:
                messagebox.showinfo("Select", "Select a file to delete")
                return
        if not messagebox.askyesno("Delete", f"Confirm delete of '{filename}'? (admin only)"):
            return
        res = ftp.delete_file(filename)
        self.log(f"DELETE: {res}")
        self.threaded_refresh_lists()
 
    def do_search(self):
        pat = self.ent_search.get().strip()
        mode = self.cmb_mode.get().strip()
        if not pat:
            messagebox.showwarning("Search", "Enter a search pattern")
            return
        res = ftp.search(mode, pat)
        self.log(f"SEARCH results:\n{res}")
 
    def on_close(self):
        try:
            ftp.quit()
        except:
            pass
        self.destroy()
 
if __name__ == "__main__":
    app = App()
    app.mainloop()
 