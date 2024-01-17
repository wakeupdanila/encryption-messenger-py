import socket
import logging
import threading
import rsa
from messenger_common import HOST, PORT, exchange_pub_rsa, listen_for_messages_in_background

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%m-%Y %H:%M:%S')


def start_server():
    pub_key, priv_key = rsa.newkeys(2048)
    pub_key_export = pub_key.save_pkcs1(format="PEM")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            logging.info(f"Server started. Waiting for connections...")

            client1_socket, addr1 = s.accept()
            exchange_pub_rsa(client1_socket, pub_key_export)

            client2_socket, addr2 = s.accept()
            exchange_pub_rsa(client2_socket, pub_key_export)

            listen_thread1 = threading.Thread(target=listen_for_messages_in_background, args=(
                client1_socket, "Client 1", client2_socket))
            listen_thread2 = threading.Thread(target=listen_for_messages_in_background, args=(
                client2_socket, "Client 2", client1_socket))

            listen_thread1.start()
            listen_thread2.start()

            listen_thread1.join()
            listen_thread2.join()

    except Exception as e:
        logging.error(f"Server terminated. Closing connections. {e}")


def main():
    start_server()


if __name__ == "__main__":
    main()
