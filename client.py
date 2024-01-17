import socket
import logging
import threading
import rsa
from messenger_common import HOST, PORT, exchange_pub_rsa, listen_for_messages_in_background, encrypt_message, \
    send_encrypted_message

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%m-%Y %H:%M:%S')


def start_client():
    pub_key, priv_key = rsa.newkeys(2048)
    pub_key_export = pub_key.save_pkcs1(format="PEM")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            logging.info(f"Connected to {HOST} on port: {PORT}")

            server_pub_key = exchange_pub_rsa(s, pub_key_export)

            if server_pub_key:
                listen_thread = threading.Thread(target=listen_for_messages_in_background,
                                                 args=(s, "Server", s))
                listen_thread.start()

                try:
                    while True:
                        message = input("Message: ")
                        if message.lower() == 'exit':
                            break
                        encrypted_message = encrypt_message(message, server_pub_key)
                        send_encrypted_message(s, encrypted_message)

                except KeyboardInterrupt:
                    logging.info("Client terminated. Closing connection.")
                    s.close()
                    listen_thread.join(1)

            else:
                logging.error("Public key exchange failed, terminating.")

    except Exception as e:
        logging.error(f"Connection error: {e}")


def main():
    start_client()


if __name__ == "__main__":
    main()
