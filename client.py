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
PORT = 65432  # Port to connect to (server's port)


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
        socket.sendall(pubKey_export)
        logging.info("Public key sent, waiting for the server's public key")
        server_pub_key_data = socket.recv(4096)
        server_pub_key = rsa.PublicKey.load_pkcs1(server_pub_key_data, format='PEM')
        logging.info("Server's public key received")
        return server_pub_key
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
                logging.info(f"Received from server (Decrypted): {message}")
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


if __name__ == "__main__":
    # Generate RSA keys
    pubKey, privKey = rsa.newkeys(2048)
    pubKey_export = pubKey.save_pkcs1(format="PEM")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            logging.info(f"Connected to {HOST} on port: {PORT}")

            server_pub_key = exchange_pub_rsa(s)

            if server_pub_key:
                listen_thread = threading.Thread(target=listen_for_messages_in_background, args=(s, privKey))
                listen_thread.start()

                try:
                    while True:
                        message = input("Message: ")
                        if message.lower() == 'exit':
                            break
                        send_new_message(s, message, server_pub_key)

                except KeyboardInterrupt:
                    logging.info("Client terminated. Closing connection.")
                finally:
                    s.close()
                    listen_thread.join()
            else:
                logging.error("Public key exchange failed, terminating.")

    except Exception as e:
        logging.error(f"Connection error: {e}")
