import socket
import rsa
import logging
import threading
import datetime
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Network configuration
HOST = socket.gethostname()  # Hostname of the local machine
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

# Generate RSA keys (using a larger key size for better security)
RSApubKey, RSAprivKey = rsa.newkeys(2048)

# Export the public key in PEM format for easier handling
pubKey_export = RSApubKey.save_pkcs1(format="PEM")


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


# Function to encrypt a message using the public key
def encrypt_message(text, public_key):
    encrypted_message = rsa.encrypt(text.encode(), public_key)
    return encrypted_message


# Function to decrypt a message using the private key
def decrypt_message(encrypted_message):
    try:
        decrypted_message = rsa.decrypt(encrypted_message, RSAprivKey).decode()
        return decrypted_message
    except Exception as e:
        logging.error(f"Error decrypting message: {e}")
        return None


# Function to exchange the public RSA key with a client
def exchange_pub_rsa():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of the socket
            s.bind((HOST, PORT))
            s.listen()
            logging.info("Server is listening for key exchange...")
            conn, addr = s.accept()
            with conn:
                conn.sendall(pubKey_export)
                client_pub_key_data = conn.recv(4096)
                client_pub_key = rsa.PublicKey.load_pkcs1(client_pub_key_data, format='PEM')
                logging.info("Public key exchange successful")
                return client_pub_key
    except Exception as ex:
        logging.error(f"Error during key exchange: {ex}")
        return None


def listen_for_message(conn):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                logging.info("No more data received. Ending listening thread.")
                break
            logging.info("Received encrypted data")
            decrypted_message = decrypt_message(data)
            if decrypted_message:
                print(f"{decrypted_message}")
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            break  # Break the loop to end the thread on error


def send_new_message(conn, text, server_pub_key):
    try:
        message_encrypted = encrypt_message(create_json_dumped_message(text), server_pub_key)
        conn.sendall(message_encrypted)
    except Exception as message_error:
        logging.error(f"Message error: {message_error}")


def handle_client(conn, addr, client_pub_key):
    logging.info(f"Connected by {addr}")
    listen_thread = threading.Thread(target=listen_for_message, args=(conn,))
    listen_thread.start()

    # Example of sending a welcome message to the client
    send_new_message(conn, "Welcome to the server!", client_pub_key)
    listen_thread.join()


client_pub_key = exchange_pub_rsa()

if client_pub_key:
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logging.info("Server started. Waiting for messages...")

        while True:  # Loop to accept multiple clients
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, client_pub_key))
            client_thread.start()

    except Exception as e:
        logging.error(f"Error during message handling: {e}")
else:
    logging.error("Public key exchange failed, server shutting down.")
