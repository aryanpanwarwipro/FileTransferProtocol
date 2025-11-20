#!/usr/bin/env python3
"""
client.py - companion client supporting:
- login <user> <pass>
- ls, get, put
- create, read, update, delete
- mkdir, rmdir, rename, move, copy (admin ops)
- search name|content <pattern>
- optional TLS via --tls flag
"""
import socket, sys, os, argparse
from tqdm import tqdm
import ssl
 
BUF = 4096
 
parser = argparse.ArgumentParser()
parser.add_argument("host")
parser.add_argument("port", type=int)
parser.add_argument("--tls", action="store_true", help="use TLS")
args = parser.parse_args()
 
HOST = args.host
PORT = args.port
USE_TLS = args.tls
 
CLIENT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(CLIENT_DIR)
 
def recv_line(sock):
    data = b''
    while True:
        ch = sock.recv(1)
        if not ch:
            return None
        if ch == b'\n':
            break
        data += ch
    return data.decode()
 
def recv_exact(sock, n):
    got = b''
    while len(got) < n:
        chunk = sock.recv(min(BUF, n - len(got)))
        if not chunk:
            raise ConnectionError("connection closed")
        got += chunk
    return got
 
def connect():
    s = socket.socket()
    s.connect((HOST, PORT))
    if USE_TLS:
        context = ssl.create_default_context()
        # for self-signed certs (development) uncomment next line:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        s = context.wrap_socket(s, server_hostname=HOST)
    return s
 
sock = connect()
welcome = recv_line(sock)
print("Server:", welcome)
 
while True:
    cmd = input("ftp> ").strip()
    if not cmd:
        continue
    sock.sendall((cmd + "\n").encode())
    parts = cmd.split()
    base = parts[0].lower()
 
    # LIST
    if base == "ls":
        header = recv_line(sock)
        if not header:
            print("Disconnected")
            break
        if header.startswith("OK "):
            size = int(header.split()[1])
            if size > 0:
                data = recv_exact(sock, size)
                print(data.decode())
            else:
                print("(empty)")
        else:
            print(header)
        continue
 
    # GET
    if base == "get":
        header = recv_line(sock)
        if not header:
            print("Disconnected")
            break
        if header.startswith("ERR"):
            print(header)
            continue
        if header != "OK":
            print("Unexpected:", header)
            continue
        size_line = recv_line(sock)
        size = int(size_line.strip())
        fname = parts[1] if len(parts) > 1 else "downloaded"
        progress = tqdm(total=size, unit='B', unit_scale=True, desc=f"Downloading {fname}")
        with open(fname, "wb") as f:
            remaining = size
            while remaining > 0:
                chunk = sock.recv(min(BUF, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
                progress.update(len(chunk))
        progress.close()
        print("Downloaded", fname)
        continue
 
    # PUT
    if base == "put":
        if len(parts) < 2:
            print("usage: put <filename>")
            continue
        fname = parts[1]
        if not os.path.isfile(fname):
            print("local file missing")
            continue
        header = recv_line(sock)
        if header is None:
            print("Disconnected")
            break
        if header.startswith("ERR"):
            print(header); continue
        if header != "OK":
            print("Unexpected:", header); continue
        size = os.path.getsize(fname)
        sock.sendall((str(size) + "\n").encode())
        progress = tqdm(total=size, unit='B', unit_scale=True, desc=f"Uploading {fname}")
        with open(fname, "rb") as f:
            while True:
                data = f.read(BUF)
                if not data:
                    break
                sock.sendall(data)
                progress.update(len(data))
        progress.close()
        resp = recv_line(sock)
        print(resp)
        continue
 
    # CREATE
    if base == "create":
        print(recv_line(sock))
        continue
 
    # READ
    if base == "read":
        head = recv_line(sock)
        if not head:
            print("Disconnected"); break
        if head.startswith("ERR"):
            print(head); continue
        size = int(head.strip())
        if size == 0:
            print("(empty)")
            continue
        data = recv_exact(sock, size)
        print("----- FILE CONTENT -----")
        print(data.decode(errors="ignore"))
        print("------------------------")
        continue
 
    # UPDATE
    if base == "update":
        head = recv_line(sock)
        if not head:
            print("Disconnected"); break
        if head != "READY":
            print(head); continue
        print("Enter new content. End with a blank line.")
        lines=[]
        while True:
            ln = input()
            if ln == "": break
            lines.append(ln)
        text = "\n".join(lines)
        sock.sendall((str(len(text)) + "\n").encode())
        if len(text) > 0:
            sock.sendall(text.encode())
        print(recv_line(sock))
        continue
 
    # DELETE / MKDIR / RMDIR / RENAME / MOVE / COPY
    if base in ("delete","mkdir","rmdir","rename","move","copy"):
        print(recv_line(sock))
        continue
 
    # SEARCH
    if base == "search":
        head = recv_line(sock)
        if not head:
            print("Disconnected"); break
        if head.startswith("ERR"):
            print(head); continue
        if head.startswith("OK "):
            size = int(head.split()[1])
            if size == 0:
                print("(no results)")
                continue
            data = recv_exact(sock, size)
            print(data.decode())
            continue
        print(head)
        continue
 
    # LOGIN
    if base == "login":
        print(recv_line(sock))
        continue
 
    # QUIT
    if base == "quit":
        print(recv_line(sock))
        break
 
    # FALLBACK (any other unexpected)
    resp = recv_line(sock)
    if resp:
        print(resp)
    else:
        print("No response / disconnected")
        break
 
sock.close()