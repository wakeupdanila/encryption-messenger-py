# echo-server.py

import socket, rsa

HOST = socket.gethostname()  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

## RSA key
pubKey, privKey = rsa.newkeys(512)
pubKey_export = pubKey.save_pkcs1(format="DER")

## Decryption process
def decryptMessage(encryptMessage):
    decryptedMessage = rsa.decrypt(encryptMessage,privKey).decode()
    return decryptedMessage

def encryptMessage(text):
    encryptedMessage = rsa.encrypt(message.encode(),pubKey)
    return encryptedMessage

def exchangePubRSA():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST,PORT))
            s.listen()
            print("Waiting for RSA exchange")
            conn, addr = s.accept()
            with conn:
                conn.sendall(pubKey_export)
                rsa_pubKey_import = conn.recv(1024)
                print("SUCCESS", rsa_pubKey_import)
    except Exception as ex:
        print(f"Error on exchange: {ex}")
    finally:
        s.close()

exchangePubRSA()
PORT = 65431

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Server started. Waiting for connection...")

    # Get the pub key from client
    conn, addr = s.accept()
    client_rsa_pubKey = conn.recv(1024)


    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    while True:
        with conn:
            print(f"Message from {addr[0]}")
            print(client_rsa_pubKey)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)
                print(data)
