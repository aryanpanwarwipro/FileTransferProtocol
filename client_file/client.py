import socket, sys, os
 
HOST = sys.argv[1]
PORT = int(sys.argv[2])
BUF = 4096

CLIENT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(CLIENT_DIR)
 
sock = socket.socket()
sock.connect((HOST, PORT))
print("Connected to server")
 
while True:
    cmd = input("ftp> ").strip()
    if not cmd: continue
 
    sock.send(cmd.encode())
 
    if cmd == "ls":
        print(sock.recv(5000).decode())
 
    elif cmd.startswith("get "):
        reply = sock.recv(2)
        if reply != b"OK":
            print("File not found")
            continue
        fname = cmd[4:]
        data = sock.recv(10_000_000)
        open(fname, "wb").write(data)
        print("Downloaded:", fname)
 
    elif cmd.startswith("put "):
        fname = cmd[4:]
        if not os.path.isfile(fname):
            print("Local file missing!")
            continue
        sock.recv(2)         
        sock.send(open(fname, "rb").read())
        print("Uploaded:", fname)
 
    elif cmd == "quit":
        break