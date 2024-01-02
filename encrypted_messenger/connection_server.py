# echo-server.py

import socket, rsa, logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = socket.gethostname()  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

## RSA key
RSApubKey, RSAprivKey = rsa.newkeys(512)
pubKey_export = RSApubKey.save_pkcs1(format="DER")


## Decryption process
def decryptMessage(encryptMessage):
    decryptedMessage = rsa.decrypt(encryptMessage, RSAprivKey).decode()
    return decryptedMessage


def encryptMessage(text):
    encryptedMessage = rsa.encrypt(text.encode(), RSApubKey)
    return encryptedMessage


def exchangePubRSA():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Configuration allowing multi usage
            s.bind((HOST, PORT))
            s.listen()
            logging.info(f"Waiting for RSA exchange {pubKey_export}")
            conn, addr = s.accept()
            with conn:
                conn.sendall(pubKey_export)
                rsa_pubkey_import = conn.recv(1024)
                logging.info(f"Key exchanged! {rsa_pubkey_import}")
    except Exception as ex:
        logging.info(f"Error on exchange: {ex}")
    finally:
        s.close()


exchangePubRSA()

try:  # After exchanging RSA, socket starts
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        # Server is listening for message from client
        logging.info("Server started. Waiting for message...")
        conn, addr = s.accept()
        with conn:  # Once the connection is accepted
            logging.info(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)  # Data received from client
                if not data:
                    break
                logging.info(f"Received data: {data}")
                print(type(data))
                try:
                    receivedEncrypted = decryptMessage(data)  # Attempt to decrypt the message
                    print(receivedEncrypted)
                except Exception as decryptError:
                    logging.error(f"Error decrypting data: {decryptError}")
                    break
except Exception as exi:
    logging.exception(f"Error: {exi}")
    s.close()
