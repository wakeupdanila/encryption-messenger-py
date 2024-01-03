import socket
import rsa
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Network configuration
HOST = socket.gethostname()  # Hostname of the local machine
PORT = 65432                # Port to listen on (non-privileged ports are > 1023)

# Generate RSA keys (using a larger key size for better security)
RSApubKey, RSAprivKey = rsa.newkeys(2048)

# Export the public key in PEM format for easier handling
pubKey_export = RSApubKey.save_pkcs1(format="PEM")

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

# Exchange keys with client
client_pub_key = exchange_pub_rsa()

# Main server loop for message handling
if client_pub_key:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            logging.info("Server started. Waiting for messages...")
            conn, addr = s.accept()
            client_ip = addr[0]  # IP address of the client
            client_port = addr[1]  # Port number of the client

            try:
                # Attempt to resolve the IP to a hostname
                client_hostname = socket.gethostbyaddr(client_ip)[0]
            except socket.herror:
                # If the host cannot be found, fall back to the IP address
                client_hostname = client_ip

            with conn:
                logging.info(f"Connected by {addr}")
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    logging.info(f"Received encrypted data")
                    decrypted_message = decrypt_message(data)
                    if decrypted_message:
                        print(f"Message ({client_hostname}): {decrypted_message}")
    except Exception as e:
        logging.error(f"Error during message handling: {e}")
else:
    logging.error("Public key exchange failed, server shutting down.")
