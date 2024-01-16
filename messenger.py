import datetime
import rsa
import socket
import logging
import json
import threading
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '127.0.0.1'
PORT = 65432


def get_current_time():
    return datetime.datetime.now()


def create_json_dumped_message(text):
    now = get_current_time()
    message_detail = {
        "Time": now.strftime("%H:%M:%S"),
        "Date": now.strftime("%Y-%m-%d"),
        "Message": text,
    }
    return json.dumps(message_detail)


def encrypt_message(text, public_key):
    encrypted_message = rsa.encrypt(text.encode(), public_key)
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
    return decrypted_message


def exchange_pub_rsa(socket, public_key_export):
    try:
        socket.sendall(public_key_export)
        logging.info("Public key sent, waiting for the other party's public key")
        other_party_pub_key_data = socket.recv(4096)
        other_party_pub_key = rsa.PublicKey.load_pkcs1(other_party_pub_key_data, format='PEM')
        logging.info("Other party's public key received")
        return other_party_pub_key
    except Exception as ex:
        logging.error(f"Error during key exchange: {ex}")
        return None


def send_encrypted_message(socket, encrypted_message):
    try:
        socket.sendall(encrypted_message)
    except Exception as send_error:
        logging.error(f"Send error: {send_error}")


def listen_for_messages_in_background(socket, private_key, client_name, other_client_socket, other_client_pub_key):
    try:
        while True:
            message = listen_for_message(socket, private_key)
            if message:
                logging.info(f"Received from {client_name} (Decrypted): {message}")
                encrypted_message = encrypt_message(message, other_client_pub_key)
                send_encrypted_message(other_client_socket, encrypted_message)
    except Exception as e:
        logging.error(f"Error receiving/sending message: {e}")


def listen_for_message(socket, private_key):
    try:
        data = socket.recv(4096)
        if data:
            decrypted_message = decrypt_message(data, private_key)
            if decrypted_message:
                return decrypted_message
        else:
            return None
    except Exception as receive_error:
        logging.error(f"Receive error: {receive_error}")
        return None


def start_server():
    pubKey, privKey = rsa.newkeys(2048)
    pubKey_export = pubKey.save_pkcs1(format="PEM")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            logging.info(f"Server started. Waiting for connections...")

            client1_socket, addr1 = s.accept()
            client1_pub_key = exchange_pub_rsa(client1_socket, pubKey_export)

            client2_socket, addr2 = s.accept()
            client2_pub_key = exchange_pub_rsa(client2_socket, pubKey_export)

            client_sockets = [client1_socket, client2_socket]

            listen_thread1 = threading.Thread(target=listen_for_messages_in_background, args=(
                client1_socket, privKey, "Client 1", client2_socket, client2_pub_key))
            listen_thread2 = threading.Thread(target=listen_for_messages_in_background, args=(
                client2_socket, privKey, "Client 2", client1_socket, client1_pub_key))

            listen_thread1.start()
            listen_thread2.start()

            listen_thread1.join()
            listen_thread2.join()

    except Exception as e:
        logging.error(f"Server terminated. Closing connections. {e}")


def start_client():
    pubKey, privKey = rsa.newkeys(2048)
    pubKey_export = pubKey.save_pkcs1(format="PEM")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            logging.info(f"Connected to {HOST} on port: {PORT}")

            server_pub_key = exchange_pub_rsa(s, pubKey_export)

            if server_pub_key:
                listen_thread = threading.Thread(target=listen_for_messages_in_background,
                                                 args=(s, privKey, "Server", None, None))
                listen_thread.start()

                try:
                    while True:
                        message = input("Message: ")
                        if message.lower() == 'exit':
                            break
                        send_encrypted_message(s, encrypt_message(message, server_pub_key))

                except KeyboardInterrupt:
                    logging.info("Client terminated. Closing connection.")
                finally:
                    s.close()
                    listen_thread.join()
            else:
                logging.error("Public key exchange failed, terminating.")

    except Exception as e:
        logging.error(f"Connection error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['server', 'client']:
        print("Usage: python messenger.py [server|client]")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'server':
        start_server()
    elif mode == 'client':
        start_client()
