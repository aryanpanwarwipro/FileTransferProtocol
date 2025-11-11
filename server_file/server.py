import socket, os
 
HOST = "0.0.0.0"
PORT = 5001
BUF = 4096
 
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SERVER_DIR)

s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)
print("Server running on", PORT)
 
while True:
    conn, addr = s.accept()
    print("Client connected:", addr)
 
    while True:
        cmd = conn.recv(1024).decode().strip()
        if not cmd: break
 
        if cmd == "ls":
            files = "\n".join(os.listdir())
            conn.send(files.encode() or b"-empty-")
 
        elif cmd.startswith("get "):
            fname = cmd[4:]
            if not os.path.isfile(fname):
                conn.send(b"ERR")
                continue
            conn.send(b"OK")
            conn.sendall(open(fname, "rb").read())
 
        elif cmd.startswith("put "):
            fname = cmd[4:]
            conn.send(b"OK")
            data = conn.recv(10_000_000)      
            open(fname, "wb").write(data)
 
        elif cmd == "quit":
            break
 
    conn.close()