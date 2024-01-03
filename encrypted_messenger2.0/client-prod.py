import datetime
import rsa
import socket
import logging
import json

# Configure logging for better debugging and visibility
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Network configuration
HOST = socket.gethostname()  # Hostname of the local machine
PORT = 65432                # Port to listen on (non-privileged ports are > 1023)

# Generate RSA keys (using a larger key size for better security)
pubKey, privKey = rsa.newkeys(2048)

# Export the public key in PEM format
pubKey_export = pubKey.save_pkcs1(format="PEM")

# Function to encrypt a message using the public key
def encrypt_message(text, public_key):
    encrypted_message = rsa.encrypt(text.encode(), public_key)
    return encrypted_message

# Function to decrypt a message using the private key
def decrypt_message(encrypted_message, private_key):
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
    return decrypted_message

# Create a JSON-formatted message
def create_json_dumped_message(sender, message, timestamp):
    message_detail = {
        "Sender": sender,
        "Message": message,
        "Timestamp": timestamp
    }
    json_dumped_message = json.dumps(message_detail)
    return json_dumped_message



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

if server_pub_key:
    # Encrypt a test message with server's public key
    message_encrypted = encrypt_message("Test Message", server_pub_key)

    # After key exchange, establish a new connection for messaging
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((HOST, PORT))

            while True:
                try:
                    s.sendall(message_encrypted)
                    data = s.recv(4096)
                    logging.info(f"Received: {decrypt_message(data, privKey)}")
                except Exception as message_error:
                    logging.error(f"Message error: {message_error}")
                    break
    except Exception as e:
        logging.error(f"Connection error: {e}")
else:
    logging.error("Public key exchange failed, terminating.")
