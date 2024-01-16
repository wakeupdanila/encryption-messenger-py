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


def exchange_pub_rsa(socket, other_client=False):
    try:
        if not other_client:
            socket.sendall(pubKey_export)
            logging.info("Public key sent, waiting for the other client's public key")
            other_client_pub_key_data = socket.recv(4096)
            other_client_pub_key = rsa.PublicKey.load_pkcs1(other_client_pub_key_data, format='PEM')
            logging.info("Other client's public key received")
            return other_client_pub_key
        else:
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
        message_encrypted = encrypt_message(create_json_dumped_message(text), public_key)
        socket.sendall(message_encrypted)
    except Exception as message_error:
        logging.error(f"Message error: {message_error}")


def listen_for_message(socket, private_key, other_client=False):
    try:
        data = socket.recv(4096)
        if data:
            return decrypt_message(data, private_key)
        else:
            return None
    except Exception as receive_error:
        logging.error(f"Receive error: {receive_error}")
        return None


def listen_for_messages_in_background(socket, private_key, other_client=False):
    while True:
        try:
            message = listen_for_message(socket, private_key, other_client)
            if message:
                if other_client:
                    logging.info(f"Received from other client: {message}")
                else:
                    logging.info(f"Received from client: {message}")
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            break  # Break the loop to end the thread on error


# Generate RSA keys (using a larger key size for better security)
pubKey, privKey = rsa.newkeys(2048)

# Export the public key in PEM format
pubKey_export = pubKey.save_pkcs1(format="PEM")


def chat_server():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logging.info("Server started. Waiting for connections...")

        # Wait for the first client to connect
        conn1, addr1 = server_socket.accept()
        client1_pub_key = exchange_pub_rsa(conn1)

        # Wait for the second client to connect
        conn2, addr2 = server_socket.accept()
        client2_pub_key = exchange_pub_rsa(conn2, other_client=True)

        if not client1_pub_key or not client2_pub_key:
            logging.error("Public key exchange failed. Closing connections.")
            conn1.close()
            conn2.close()
            return

        # Start listening for messages from each client in separate threads
        listen_thread1 = threading.Thread(target=listen_for_messages_in_background, args=(conn1, privKey))
        listen_thread2 = threading.Thread(target=listen_for_messages_in_background, args=(conn2, privKey, True))

        listen_thread1.start()
        listen_thread2.start()

        # Wait for the listen threads to finish
        listen_thread1.join()
        listen_thread2.join()

        logging.info("Closing connections.")
        conn1.close()
        conn2.close()

    except Exception as e:
        logging.error(f"Error during message handling: {e}")


def chat_client():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        logging.info(f"Connected to {HOST} on port: {PORT}")

        # Exchange keys with the server
        server_pub_key = exchange_pub_rsa(s)

        if not server_pub_key:
            logging.error("Public key exchange failed, terminating.")
            s.close()
            return

        # Start listening for messages from the server in a separate thread
        listen_thread = threading.Thread(target=listen_for_messages_in_background, args=(s, privKey))
        listen_thread.start()

        while True:
            message = input("Message: ")
            if message.lower() == 'exit':
                break
            send_new_message(s, message, server_pub_key)

        # Clean up
        listen_thread.join()
        s.close()

    except Exception as e:
        logging.error(f"Connection error: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 1:
        print("Usage:")
        print("To run as a server: python3 messenger.py server")
        print("To run as a client: python3 messenger.py client")
    elif sys.argv[1].lower() == 'server':
        chat_server()
    elif sys.argv[1].lower() == 'client':
        chat_client()
    else:
        print("Invalid argument. Use 'server' or 'client'.")
