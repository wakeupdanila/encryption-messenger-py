import datetime
import rsa
import socket
import logging
import json
import threading

# Configure logging for better debugging and visibility
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Network configuration
HOST = '127.0.0.1'  # Use the loopback address for local testing
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)


def get_current_time():
    return datetime.datetime.now()


def create_json_dumped_message(text):
    now = get_current_time()
    message_detail = {
        "Client": HOST,
        "Message": text,
        "Date": now.strftime("%Y-%m-%d"),
        "Timestamp": now.strftime("%H:%M:%S")
    }
    return json.dumps(message_detail)


def encrypt_message(text, public_key):
    encrypted_message = rsa.encrypt(text.encode(), public_key)
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
    return decrypted_message


def exchange_pub_rsa(socket):
    try:
        client_pub_key_data = socket.recv(4096)
        client_pub_key = rsa.PublicKey.load_pkcs1(client_pub_key_data, format='PEM')
        logging.info("Client's public key received")
        socket.sendall(pubKey_export)
        return client_pub_key
    except Exception as ex:
        logging.error(f"Error during key exchange: {ex}")
        return None


def send_new_message(socket, text, public_key):
    try:
        message = create_json_dumped_message(text)
        message_encrypted = encrypt_message(message, public_key)
        socket.sendall(message_encrypted)
    except Exception as message_error:
        logging.error(f"Message error: {message_error}")


def listen_for_messages_in_background(socket, private_key):
    while True:
        try:
            message = listen_for_message(socket, private_key)
            if message:
                logging.info(f"Received from client (Decrypted): {message}")
                # Forward the received message to the other client
                other_client_socket = get_other_client_socket(socket)
                if other_client_socket:
                    send_new_message(other_client_socket, message, client2_pub_key)
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            break


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


def get_other_client_socket(current_client_socket):
    for client_socket in client_sockets:
        if client_socket != current_client_socket:
            return client_socket
    return None


if __name__ == "__main__":
    # Generate RSA keys
    pubKey, privKey = rsa.newkeys(2048)
    pubKey_export = pubKey.save_pkcs1(format="PEM")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()

            logging.info(f"Server started. Waiting for connections...")

            client1_socket, addr1 = s.accept()
            client1_pub_key = exchange_pub_rsa(client1_socket)

            client2_socket, addr2 = s.accept()
            client2_pub_key = exchange_pub_rsa(client2_socket)

            client_sockets = [client1_socket, client2_socket]

            listen_thread1 = threading.Thread(target=listen_for_messages_in_background, args=(client1_socket, privKey))
            listen_thread2 = threading.Thread(target=listen_for_messages_in_background, args=(client2_socket, privKey))

            listen_thread1.start()
            listen_thread2.start()

            listen_thread1.join()
            listen_thread2.join()

    except Exception as e:
        logging.error(f"Server terminated. Closing connections. {e}")
