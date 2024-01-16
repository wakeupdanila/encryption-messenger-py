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
    # Encrypt the message using the RSA public key
    encrypted_message = rsa.encrypt(text.encode(), public_key)
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    # Decrypt the message using the RSA private key
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
    return decrypted_message


def exchange_pub_rsa(socket, other_client=False):
    try:
        if not other_client:
            # For the server and first client: send public key and receive other client's public key
            socket.sendall(pubKey_export)
            logging.info("Public key sent, waiting for the other client's public key")
            other_client_pub_key_data = socket.recv(4096)
            other_client_pub_key = rsa.PublicKey.load_pkcs1(other_client_pub_key_data, format='PEM')
            logging.info("Other client's public key received")
            return other_client_pub_key
        else:
            # For the second client: receive server's public key and send own public key
            client_pub_key_data = socket.recv(4096)
            client_pub_key = rsa.PublicKey.load_pkcs1(client_pub_key_data, format='PEM')
            logging.info("Client's public key received")
            socket.sendall(pubKey_export)
            return client_pub_key
    except Exception as ex:
        logging.error(f"Error during key exchange: {ex}")
        return None


def send_new_message(socket, text, public_key, print_encrypted=True):
    try:
        # Create a JSON-formatted message and encrypt it with the recipient's public key
        message = create_json_dumped_message(text)
        message_encrypted = encrypt_message(message, public_key)
        if print_encrypted:
            logging.info(f"Message encrypted: {message_encrypted}")
        socket.sendall(message_encrypted)
    except Exception as message_error:
        logging.error(f"Message error: {message_error}")


def listen_for_message(socket, private_key, other_client=False):
    try:
        # Receive the encrypted message and decrypt it using the private key
        data = socket.recv(4096)
        if data:
            decrypted_message = decrypt_message(data, private_key)
            if decrypted_message and not other_client:
                logging.info(f"Received from client (Decrypted): {decrypted_message}")
            elif decrypted_message:
                logging.info(f"Received from other client (Decrypted): {decrypted_message}")
        else:
            return False
    except Exception as receive_error:
        logging.error(f"Receive error: {receive_error}")
        return False
    return True


def listen_for_messages_in_background(socket, private_key, other_client=False):
    while True:
        try:
            # Continuously listen for messages in the background
            message = listen_for_message(socket, private_key, other_client)
            if message:
                if other_client:
                    logging.info(f"Received from other client (Decrypted): {message}")
                else:
                    logging.info(f"Received from client (Decrypted): {message}")
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            break


# Generate RSA keys (using a larger key size for better security)
pubKey, privKey = rsa.newkeys(2048)
pubKey_export = pubKey.save_pkcs1(format="PEM")


def chat_server():
    try:
        # Set up the server socket and accept connections from two clients
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logging.info("Server started. Waiting for connections...")

        conn1, addr1 = server_socket.accept()
        client1_pub_key = exchange_pub_rsa(conn1)

        conn2, addr2 = server_socket.accept()
        client2_pub_key = exchange_pub_rsa(conn2, other_client=True)

        # Handle public key exchange errors
        if not client1_pub_key or not client2_pub_key:
            logging.error("Public key exchange failed. Closing connections.")
            conn1.close()
            conn2.close()
            return

        # Start separate threads to listen for messages from each client
        listen_thread1 = threading.Thread(target=listen_for_messages_in_background, args=(conn1, privKey))
        listen_thread2 = threading.Thread(target=listen_for_messages_in_background, args=(conn2, privKey, True))

        listen_thread1.start()
        listen_thread2.start()

        try:
            while True:
                # Server can send messages to both clients simultaneously
                message = input("Server Message: ")
                if message.lower() == 'exit':
                    break
                send_new_message(conn1, message, client1_pub_key, print_encrypted=False)
                send_new_message(conn2, message, client2_pub_key, print_encrypted=False)
        except KeyboardInterrupt:
            logging.info("Server terminated. Closing connections.")
            conn1.close()
            conn2.close()

        # Wait for the listen threads to finish
        listen_thread1.join()
        listen_thread2.join()

    except Exception as e:
        logging.error(f"Error during message handling: {e}")


def chat_client():
    try:
        # Set up a client socket and connect to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            logging.info(f"Connected to {HOST} on port: {PORT}")

            # Exchange public keys with the server
            server_pub_key = exchange_pub_rsa(s)

            # Handle public key exchange errors
            if server_pub_key:
                # Start a thread to listen for messages from the server
                listen_thread = threading.Thread(target=listen_for_messages_in_background, args=(s, privKey))
                listen_thread.start()

                while True:
                    # Send messages to the server
                    message = input("Message: ")
                    if message.lower() == 'exit':
                        break
                    send_new_message(s, message, server_pub_key)

                # Wait for the listen thread to finish
                listen_thread.join()
            else:
                logging.error("Public key exchange failed, terminating.")

    except Exception as e:
        logging.error(f"Connection error: {e}")


if __name__ == "__main__":
    import sys

    # Check if the program is started as a server or client
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'server':
        chat_server()
    else:
        chat_client()
