import socket
import logging
import threading
import rsa
from messenger_common import send_encrypted_message

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%m-%Y %H:%M:%S')


def listen_for_messages(socket, priv_key):
    try:
        while True:
            data = socket.recv(4096)
            if data:
                decrypted_message = rsa.decrypt(data, priv_key)
                print(f"Received message: {decrypted_message.decode()}")
    except Exception as e:
        print(f"Error receiving message: {e}")


def start_client():
    pub_key, priv_key = rsa.newkeys(2048)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('127.0.0.1', 65432))
            logging.info(f"Connected to 127.0.0.1 on port: 65432")

            listen_thread = threading.Thread(target=listen_for_messages, args=(s, priv_key))
            listen_thread.start()

            try:
                while True:
                    message = input("Message: ")
                    if message.lower() == 'exit':
                        break
                    encrypted_message = rsa.encrypt(message.encode(), pub_key)
                    send_encrypted_message(s, encrypted_message)

            except KeyboardInterrupt:
                logging.info("Client terminated. Closing connection.")
                s.close()
                listen_thread.join(1)

    except Exception as e:
        logging.error(f"Connection error: {e}")


def main():
    start_client()


if __name__ == "__main__":
    main()
