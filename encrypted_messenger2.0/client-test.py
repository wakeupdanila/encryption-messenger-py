import datetime
import rsa
import socket
import logging
import json
import threading

# Configure logging for better debugging and visibility
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Network configuration
HOST = socket.gethostname()  # Hostname of the local machine
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

# Generate RSA keys (using a larger key size for better security)
pubKey, privKey = rsa.newkeys(2048)

# Export the public key in PEM format
pubKey_export = pubKey.save_pkcs1(format="PEM")


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
def decrypt_message(encrypted_message, private_key):
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
    return decrypted_message


# Function to exchange the public RSA key with the server
def exchange_pub_rsa():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(pubKey_export)
            logging.info("Public key sent, waiting for server's public key")
            server_pub_key_data = s.recv(4096)
            server_pub_key = rsa.PublicKey.load_pkcs1(server_pub_key_data, format='PEM')
            logging.info("Server's public key received")
            return server_pub_key
    except Exception as ex:
        logging.error(f"Error during key exchange: {ex}")
        return None


# Exchange keys with server
server_pub_key = exchange_pub_rsa()


# Function to send a new message
def send_new_message(s, text, server_pub_key):
    try:
        message_encrypted = encrypt_message(create_json_dumped_message(text), server_pub_key)
        s.sendall(message_encrypted)
    except Exception as message_error:
        logging.error(f"Message error: {message_error}")


# Function to listen for a message
def listen_for_message(s):
    try:
        data = s.recv(4096)
        if data:
            logging.info(f"Received: {decrypt_message(data, privKey)}")
        else:
            return False
    except Exception as receive_error:
        logging.error(f"Receive error: {receive_error}")
        return False
    return True


def listen_for_messages_in_background(s):
    while True:
        if not listen_for_message(s):
            logging.info("Stopping the listening thread.")
            break


if server_pub_key:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((HOST, PORT))
        logging.info(f"Connected to {HOST} on port: {PORT}")

        # Start listening for messages in a separate thread
        listen_thread = threading.Thread(target=listen_for_messages_in_background, args=(s,))
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
else:
    logging.error("Public key exchange failed, terminating.")
