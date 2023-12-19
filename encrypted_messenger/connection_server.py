# echo-server.py

import socket

HOST = socket.gethostname()  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Server started. Waiting for connection...")
    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Message from {addr[0]}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)
                print(data.decode())
                if data.decode() == "CLOSE":
                    print("Closing connection as per client's request.")
                    break
